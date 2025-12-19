package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

func main() {
	var (
		socksAddr   = flag.String("socks-addr", "127.0.0.1:5040", "SOCKS5 listen address")
		stateDir    = flag.String("state-dir", "./tsnet-state", "Directory to store tsnet state")
		hostname    = flag.String("hostname", "tailsocks", "Tailscale node name (hostname)")
		authKey     = flag.String("authkey", "", "Optional Tailscale auth key (or set TS_AUTHKEY env var; if omitted, loads from disk or prompts)")
		exitNode    = flag.String("exit-node", "", "Exit node selector: IP or MagicDNS base name (e.g. 'home-exit'). Required.")
		allowLAN    = flag.Bool("exit-node-allow-lan-access", false, "Allow access to local LAN while using exit node")
		loginServer = flag.String("login-server", "", "Optional control server URL (e.g. https://controlplane.tld for Headscale)")
	)
	flag.Parse()

	if *exitNode == "" {
		log.Fatalf("missing --exit-node (IP like 100.x or MagicDNS base name)")
	}

	key := strings.TrimSpace(*authKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("TS_AUTHKEY"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &tsnet.Server{
		AuthKey:  key,
		Dir:      *stateDir,
		Hostname: *hostname,
		Logf: func(format string, args ...any) {
			log.Printf("[tsnet] "+format, args...)
		},
		ControlURL: *loginServer,
	}

	// Start tsnet by calling Up
	_, err := s.Up(ctx)
	if err != nil {
		log.Fatalf("failed to start tsnet: %v", err)
	}

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatalf("LocalClient: %v", err)
	}

	// Ensure we're logged in and have status (needed for SetExitNodeIP helper).
	st, err := waitForRunningStatus(ctx, lc, time.Minute)
	if err != nil {
		log.Fatalf("tailscale not running/authorized: %v", err)
	}
	log.Printf("Tailscale is up as %q (%s)", st.Self.DNSName, st.Self.TailscaleIPs)

	// Configure exit node prefs.
	err = setExitNodePrefs(ctx, lc, *exitNode, *allowLAN)
	if err != nil {
		log.Fatalf("set exit node prefs: %v", err)
	}
	log.Printf("Configured exit node %q (allow LAN access=%v)", *exitNode, *allowLAN)

	// SOCKS5 server that dials via tsnet's embedded netstack.
	dialViaTS := func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		// go-socks5 provides addr as host:port (host may be a DNS name).
		return s.Dial(dialCtx, network, addr)
	}

	conf := &socks5.Config{
		Dial: dialViaTS,
		// You can add auth rules here if you want. Leaving it open on localhost.
	}
	socksServer, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("create socks5 server: %v", err)
	}

	l, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("listen SOCKS on %s: %v", *socksAddr, err)
	}
	log.Printf("SOCKS5 proxy listening on socks5://%s", *socksAddr)

	// Shutdown handling.
	go func() {
		err = socksServer.Serve(l)
		if err != nil {
			log.Printf("SOCKS server stopped: %v", err)
			cancel()
		}
	}()

	waitForSignals()
	log.Printf("Shutting down...")
	_ = l.Close()
	_ = s.Close()
}

func waitForSignals() {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
}

func waitForRunningStatus(ctx context.Context, lc *local.Client, timeout time.Duration) (*ipnstateStatusLite, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("timed out waiting for tailscale to be running; check auth key and tailnet policies")
		case <-tick.C:
			st, err := lc.Status(ctx)
			if err != nil {
				continue
			}
			// Status is a concrete type from tailscale.com/ipnstate, but we only need a few fields.
			if st.BackendState == "Running" && st.Self != nil {
				return &ipnstateStatusLite{
					Self: ipnstateSelfLite{
						DNSName:      st.Self.DNSName,
						TailscaleIPs: st.Self.TailscaleIPs,
						StableNodeID: st.Self.ID,
					},
				}, nil
			}
		}
	}
}

// Minimal "view" of ipnstate.Status we need, so this file stays small.
type ipnstateStatusLite struct {
	Self ipnstateSelfLite
}
type ipnstateSelfLite struct {
	DNSName      string
	TailscaleIPs []netip.Addr
	StableNodeID any // only for logging/debug; not used
}

func setExitNodePrefs(ctx context.Context, lc *local.Client, exitNodeSel string, allowLAN bool) error {
	// Get current prefs and clone.
	p, err := lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("error getting preferences: %w", err)
	}
	np := p.Clone()
	np.WantRunning = true
	np.ExitNodeAllowLANAccess = allowLAN

	// Clear any existing exit node first to avoid conflicts.
	np.ClearExitNode()

	// Prefer SetExitNodeIP, since it accepts either IP or MagicDNS base name.
	// It requires a full ipnstate.Status, but LocalAPI's SetExitNodeIP helper
	// also accepts MagicDNS base names and resolves/validates internally
	//
	// We don't have the full ipnstate.Status type in this minimal example, so:
	// - If it's an IP literal, set ExitNodeIP directly.
	// - Otherwise, try using it as MagicDNS base name via Prefs.SetExitNodeIP by
	//   fetching full status from LocalAPI.
	ip, err := netip.ParseAddr(exitNodeSel)
	if err == nil {
		np.ExitNodeIP = ip
	} else {
		fullStatus, err := lc.Status(ctx)
		if err != nil {
			return fmt.Errorf("Status (for MagicDNS exit node resolution): %w", err)
		}
		err = np.SetExitNodeIP(exitNodeSel, fullStatus)
		if err != nil {
			return fmt.Errorf("SetExitNodeIP(%q): %w", exitNodeSel, err)
		}
	}

	mp := &ipn.MaskedPrefs{
		Prefs:                     *np,
		WantRunningSet:            true,
		ExitNodeIPSet:             true,
		ExitNodeIDSet:             true, // we cleared it; mark as intentionally set (zero)
		ExitNodeAllowLANAccessSet: true,
	}

	_, err = lc.EditPrefs(ctx, mp)
	if err != nil {
		return fmt.Errorf("EditPrefs: %w", err)
	}

	// Some clients separate "set which exit node" from "enable using it".
	// This endpoint exists in LocalAPI
	err = lc.SetUseExitNode(ctx, true)
	if err != nil {
		// If it fails, prefs alone may still work depending on version, but surface it.
		return fmt.Errorf("SetUseExitNode(true): %w", err)
	}

	return nil
}
