package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/italypaleale/go-kit/signals"
	kitslog "github.com/italypaleale/go-kit/slog"
	"github.com/italypaleale/tailsocks/buildinfo"
	"github.com/lmittmann/tint"
	isatty "github.com/mattn/go-isatty"
	"github.com/spf13/pflag"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

func main() {
	var (
		socksAddr   = pflag.StringP("socks-addr", "a", "127.0.0.1:5040", "SOCKS5 listen address")
		stateDir    = pflag.StringP("state-dir", "s", "./tsnet-state", "Directory to store tsnet state")
		hostname    = pflag.StringP("hostname", "n", "tailsocks", "Tailscale node name (hostname)")
		authKey     = pflag.StringP("authkey", "k", "", "Optional Tailscale auth key (or set TS_AUTHKEY env var; if omitted, loads from disk or prompts)")
		exitNode    = pflag.StringP("exit-node", "x", "", "Exit node selector: IP or MagicDNS base name (e.g. 'home-exit'). Required.")
		allowLAN    = pflag.BoolP("exit-node-allow-lan-access", "l", false, "Allow access to local LAN while using exit node")
		loginServer = pflag.StringP("login-server", "c", "", "Optional control server URL (e.g. https://controlplane.tld for Headscale)")
		showHelp    = pflag.BoolP("help", "h", false, "Show this help message")
		showVersion = pflag.BoolP("version", "v", false, "Show version")
	)
	pflag.Parse()

	switch {
	case *showHelp:
		pflag.Usage()
		os.Exit(0)
	case *showVersion:
		fmt.Printf("%s %s - build: %s\n", buildinfo.AppName, buildinfo.AppVersion, buildinfo.BuildDescription)
		os.Exit(0)
	}

	setLogger()

	if *exitNode == "" {
		kitslog.FatalError(slog.Default(), "missing --exit-node (IP like 100.x or MagicDNS base name)", errors.New("exit-node flag is required"))
	}

	key := strings.TrimSpace(*authKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("TS_AUTHKEY"))
	}

	ctx := signals.SignalContext(context.Background())

	s := &tsnet.Server{
		AuthKey:  key,
		Dir:      *stateDir,
		Hostname: *hostname,
		Logf: func(format string, args ...any) {
			slog.Info(fmt.Sprintf(format, args...), slog.String("scope", "tsnet"))
		},
		ControlURL: *loginServer,
	}

	// Start tsnet by calling Up
	_, err := s.Up(ctx)
	if err != nil {
		kitslog.FatalError(slog.Default(), "failed to start tsnet", err)
	}

	lc, err := s.LocalClient()
	if err != nil {
		kitslog.FatalError(slog.Default(), "LocalClient failed", err)
	}

	// Ensure we're logged in and have status
	st, err := lc.Status(ctx)
	if err != nil {
		kitslog.FatalError(slog.Default(), "tailscale not running/authorized", err)
	}
	slog.Info("Tailscale is up", "dnsName", st.Self.DNSName, "tailscaleIps", st.Self.TailscaleIPs)

	// Configure exit node prefs.
	err = setExitNodePrefs(ctx, lc, *exitNode, *allowLAN)
	if err != nil {
		kitslog.FatalError(slog.Default(), "set exit node prefs failed", err)
	}
	slog.Info("Configured exit node", "exitNode", *exitNode, "allowLanAccess", *allowLAN)

	socksServer, err := socks5.New(&socks5.Config{
		// SOCKS5 server that dials via tsnet's embedded netstack.
		Dial: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			// go-socks5 provides addr as host:port (host may be a DNS name).
			return s.Dial(dialCtx, network, addr)
		},
		Logger: slog.NewLogLogger(
			slog.Default().With(slog.String("scope", "socks")).Handler(),
			slog.LevelInfo,
		),
	})
	if err != nil {
		kitslog.FatalError(slog.Default(), "error creating socks5 server", err)
	}

	nlc := net.ListenConfig{}
	l, err := nlc.Listen(ctx, "tcp", *socksAddr)
	if err != nil {
		kitslog.FatalError(slog.Default(), "listen SOCKS failed", err)
	}
	slog.Info("SOCKS5 proxy listening", "addr", "socks5://"+*socksAddr)

	// Shutdown handling.
	go func() {
		err = socksServer.Serve(l)
		if err != nil {
			slog.Warn("SOCKS server stopped", "error", err)
		}
	}()

	<-ctx.Done()

	slog.Info("Shutting down...")
	_ = l.Close()
	_ = s.Close()
}

func setLogger() {
	// Setup logger with tint handler if connected to a tty
	var handler slog.Handler
	if isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd()) {
		handler = tint.NewHandler(os.Stderr, nil)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func setExitNodePrefs(ctx context.Context, lc *local.Client, exitNodeSel string, allowLAN bool) error {
	// Get current prefs and clone.
	p, err := lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("GetPrefs: %w", err)
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
			return fmt.Errorf("Status (for MagicDNS exit node resolution): %w", err) //nolint:staticcheck
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
