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
	"github.com/lmittmann/tint"
	isatty "github.com/mattn/go-isatty"
	"github.com/spf13/pflag"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/italypaleale/tailsocks/buildinfo"
)

func main() {
	opts, err := ParseFlags()
	if err != nil {
		kitslog.FatalError(slog.Default(), "failed to parse flags", err)
	}

	switch {
	case opts.ShowHelp:
		pflag.Usage()
		os.Exit(0)
	case opts.ShowVersion:
		fmt.Printf("%s %s - build: %s\n", buildinfo.AppName, buildinfo.AppVersion, buildinfo.BuildDescription) //nolint:forbidigo
		os.Exit(0)
	}

	setLogger()

	if opts.ExitNode == "" {
		kitslog.FatalError(slog.Default(), "missing --exit-node (IP like 100.x or MagicDNS base name)", errors.New("exit-node flag is required"))
	}

	ctx := signals.SignalContext(context.Background())

	// Setup authentication
	var (
		authKey   string
		ephemeral bool
	)

	// If --oauth2 flag is set, use OAuth2 credentials
	if opts.OAuth2 {
		credPath, err := getCredentialsPath()
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to determine OAuth2 credentials path", err)
		}

		creds, err := loadOAuth2Credentials(credPath)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to load OAuth2 credentials", err)
		}

		authKey, err = creds.GetAuthToken(ctx)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to get Tailscale auth key using OAuth2", err)
		}

		// Default is ephemeral
		ephemeral = determineEphemeralFlag(opts, true)

		slog.Info("Using OAuth2 credentials", "path", opts.OAuth2, "ephemeral", ephemeral)
	} else {
		// Otherwise, use the standard auth key flow
		// The auth key from CLI and env can be empty, in which case tsnet will either use the existing credentials (if the node is already registered) or prompt for interactive authentication
		authKey = strings.TrimSpace(opts.AuthKey)
		if authKey == "" {
			authKey = getAuthKeyFromEnv()
		}

		// Default is persistent
		ephemeral = determineEphemeralFlag(opts, true)
	}

	s := &tsnet.Server{
		AuthKey:   authKey,
		Dir:       opts.StateDir,
		Hostname:  opts.Hostname,
		Ephemeral: ephemeral,
		Logf: func(format string, args ...any) {
			slog.Info(fmt.Sprintf(format, args...), slog.String("scope", "tsnet"))
		},
		ControlURL: opts.LoginServer,
	}

	// Start tsnet by calling Up
	_, err = s.Up(ctx)
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

	// Configure exit node prefs
	err = setExitNodePrefs(ctx, lc, opts.ExitNode, opts.AllowLAN)
	if err != nil {
		kitslog.FatalError(slog.Default(), "set exit node prefs failed", err)
	}
	slog.Info("Configured exit node", "exitNode", opts.ExitNode, "allowLanAccess", opts.AllowLAN)

	// Configure the SOCKS5 server
	socksConfig := &socks5.Config{
		// SOCKS5 server that dials via tsnet's embedded netstack
		Dial: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			// go-socks5 provides addr as host:port (host may be a DNS name).
			return s.Dial(dialCtx, network, addr)
		},
		Logger: slog.NewLogLogger(
			slog.Default().With(slog.String("scope", "socks")).Handler(),
			slog.LevelInfo,
		),
	}

	// Use Tailscale DNS resolver by default, unless --local-dns is set
	if !opts.LocalDNS && st.CurrentTailnet.MagicDNSEnabled {
		socksConfig.Resolver = NewTailscaleResolver(lc, st.CurrentTailnet.MagicDNSSuffix)
		slog.Info("Using Tailscale DNS resolver")
	} else {
		slog.Info("Using local DNS resolver")
	}

	socksServer, err := socks5.New(socksConfig)
	if err != nil {
		kitslog.FatalError(slog.Default(), "error creating socks5 server", err)
	}

	nlc := net.ListenConfig{}
	l, err := nlc.Listen(ctx, "tcp", opts.SocksAddr)
	if err != nil {
		kitslog.FatalError(slog.Default(), "listen SOCKS failed", err)
	}
	slog.Info("SOCKS5 proxy listening", "addr", "socks5://"+opts.SocksAddr)

	// Shutdown handling
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

	// Clear any existing exit node first to avoid conflicts
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

	// Some clients separate "set which exit node" from "enable using it"
	// This endpoint exists in LocalAPI
	err = lc.SetUseExitNode(ctx, true)
	if err != nil {
		// If it fails, prefs alone may still work depending on version, but surface it
		return fmt.Errorf("SetUseExitNode(true): %w", err)
	}

	return nil
}
