package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

	// Parse TCP port-forwarding rules early so invalid input fails before we bring up the tunnel
	forwards, err := ParsePortForwards(opts.TCPForwards)
	if err != nil {
		kitslog.FatalError(slog.Default(), "invalid --tcp port forward", err)
	}

	// Likewise, resolve the shared proxy credentials early so a bad --auth-password (e.g. an unreadable file) fails fast
	proxyUser, proxyPassword, err := resolveProxyAuth(opts)
	if err != nil {
		kitslog.FatalError(slog.Default(), "invalid --auth-password", err)
	}

	ctx := signals.SignalContext(context.Background())

	// Bring up the backend that carries every outbound connection
	var b *backend
	if opts.TailcatMode() {
		b, err = setupTailcat(ctx, opts)
	} else {
		b, err = setupTailnet(ctx, opts)
	}
	if err != nil {
		kitslog.FatalError(slog.Default(), "failed to start the tunnel", err)
	}

	tunnel := b.dial
	resolver := b.resolver

	// Start the SOCKS5 proxy, unless it's disabled
	// ParseFlags guarantees at least one of the two proxies is enabled
	var (
		socksListener net.Listener
		socksDone     <-chan struct{}
	)
	if opts.SocksAddr != "" {
		warnIfNonLoopbackAddr("SOCKS5 proxy", opts.SocksAddr, proxyPassword != "")

		socksListener, socksDone, err = startSocksProxy(ctx, tunnel, resolver, opts.SocksAddr, proxyUser, proxyPassword)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to start SOCKS5 proxy", err)
		}
		slog.Info("SOCKS5 proxy listening", "addr", "socks5://"+socksListener.Addr().String(), "authenticated", proxyPassword != "")
	}

	// Start the HTTP proxy, if enabled
	var httpServer *http.Server
	if opts.HTTPAddr != "" {
		warnIfNonLoopbackAddr("HTTP proxy", opts.HTTPAddr, proxyPassword != "")

		var httpAddr net.Addr
		httpServer, httpAddr, err = startHTTPProxy(ctx, tunnel, opts.HTTPAddr, proxyUser, proxyPassword)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to start HTTP proxy", err)
		}
		slog.Info("HTTP proxy listening", "addr", "http://"+httpAddr.String(), "authenticated", proxyPassword != "")
	}

	// Start TCP port forwarders, if any
	// Each dials its target through the active tunnel so traffic is routed via the exit node
	forwardListeners := make([]net.Listener, len(forwards))
	for i, pf := range forwards {
		fl, ferr := startPortForward(ctx, tunnel, pf)
		if ferr != nil {
			kitslog.FatalError(slog.Default(), "failed to start TCP port forward", ferr)
		}

		forwardListeners[i] = fl
		slog.Info("TCP port forward listening", "listen", pf.Listen, "target", pf.Target)
	}

	// Wait until either the context is canceled, or the SOCKS5 server has stopped serving
	// When the SOCKS5 proxy is disabled socksDone is nil, and receiving from a nil channel blocks forever, so the context becomes the only way out
	select {
	case <-ctx.Done():
	case <-socksDone:
	}

	slog.Info("Shutting down...")
	if socksListener != nil {
		_ = socksListener.Close()
	}
	if httpServer != nil {
		stopHTTPProxy(httpServer)
	}
	for _, fl := range forwardListeners {
		_ = fl.Close()
	}
	b.close()
}

// backend is what a mode provides to the rest of the process: a dialer that reaches the outside world, the resolver that feeds it names, and a way to shut it down
type backend struct {
	dial     dialer
	resolver socks5.NameResolver
	close    func()
}

// setupTailnet brings up the tsnet backend, which joins a tailnet and routes through one of its exit nodes
func setupTailnet(ctx context.Context, opts *Options) (*backend, error) {
	// Setup authentication
	var (
		authKey   string
		ephemeral bool
	)

	// If --oauth2 flag is set, use OAuth2 credentials
	if opts.OAuth2 {
		// Default is ephemeral
		ephemeral = determineEphemeralFlag(opts, true)

		authKey = getOAuth2AuthKey(ctx, ephemeral)
	} else {
		// Otherwise, use the standard auth key flow
		// The auth key from CLI and env can be empty, in which case tsnet will either use the existing credentials (if the node is already registered) or prompt for interactive authentication
		authKey = strings.TrimSpace(opts.AuthKey)
		if authKey == "" {
			authKey = getAuthKeyFromEnv()
		}

		// Default is persistent
		ephemeral = determineEphemeralFlag(opts, false)
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
	_, err := s.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start tsnet: %w", err)
	}

	lc, err := s.LocalClient()
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("LocalClient failed: %w", err)
	}

	// Ensure we're logged in and have status
	st, err := lc.Status(ctx)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("tailscale not running/authorized: %w", err)
	}
	slog.Info("Tailscale is up", "dnsName", st.Self.DNSName, "tailscaleIps", st.Self.TailscaleIPs)

	// Configure exit node prefs
	err = setExitNodePrefs(ctx, lc, opts.ExitNode, opts.AllowLAN)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("set exit node prefs failed: %w", err)
	}
	slog.Info("Configured exit node", "exitNode", opts.ExitNode, "allowLanAccess", opts.AllowLAN)

	// Select the resolver used for every outbound connection
	// Resolving in a single place keeps DNS behavior identical for the SOCKS5 proxy, the HTTP proxy, and the TCP port forwards
	var resolver socks5.NameResolver
	if opts.LocalDNS {
		resolver = socks5.DNSResolver{}
		slog.Info("Using local DNS resolver")
	} else {
		// CurrentTailnet is unset when the node isn't fully configured yet, in which case there's no MagicDNS suffix to expand short names with
		var (
			magicDNSSuffix  string
			magicDNSEnabled bool
		)
		if st.CurrentTailnet != nil {
			magicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
			magicDNSEnabled = st.CurrentTailnet.MagicDNSEnabled
		}

		resolver = NewTailscaleResolver(lc, magicDNSSuffix)
		slog.Info("Using Tailscale DNS resolver", "magicDNSEnabled", magicDNSEnabled)
	}

	return &backend{
		dial:     newTunnelDialer(s, resolver),
		resolver: resolver,
		close:    func() { _ = s.Close() },
	}, nil
}

// getOAuth2AuthKey retrieves the OAuth2 auth key
// It panics in case of error
func getOAuth2AuthKey(ctx context.Context, ephemeral bool) (authKey string) {
	var err error

	// In CI/federated workflows, an access token can be provided directly.
	oauthAccessToken := strings.TrimSpace(os.Getenv("TS_OAUTH_ACCESS_TOKEN"))
	if oauthAccessToken != "" {
		oauthTag := strings.TrimSpace(os.Getenv("TS_OAUTH_TAG"))
		if oauthTag == "" {
			kitslog.FatalError(slog.Default(), "missing TS_OAUTH_TAG for OAuth2 access token authentication", errors.New("TS_OAUTH_TAG is required when TS_OAUTH_ACCESS_TOKEN is set"))
		}

		creds := &OAuth2Credentials{
			Tag: oauthTag,
		}

		authKey, err = creds.createAuthKey(ctx, oauthAccessToken, ephemeral)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to create Tailscale auth key from OAuth2 access token", err)
		}

		slog.Info("Using OAuth2 access token from environment", "ephemeral", ephemeral)
	} else {
		// Load credentials from file
		credPath, err := getCredentialsPath()
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to determine OAuth2 credentials path", err)
		}

		creds, err := loadOAuth2Credentials(credPath)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to load OAuth2 credentials", err)
		}

		authKey, err = creds.GetAuthToken(ctx, ephemeral)
		if err != nil {
			kitslog.FatalError(slog.Default(), "failed to get Tailscale auth key using OAuth2", err)
		}

		slog.Info("Using OAuth2 credentials", "path", credPath, "ephemeral", ephemeral)
	}

	return authKey
}

func setLogger() {
	// Setup logger with tint handler if connected to a tty
	var handler slog.Handler
	if isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd()) {
		handler = tint.NewTextHandler(os.Stderr, nil)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// warnIfNonLoopbackAddr logs a warning when a listener binds outside of loopback and authenticated is false, since anyone who can reach that address can then use the proxy
func warnIfNonLoopbackAddr(kind string, addr string, authenticated bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		slog.Warn(kind+" could not determine bind address security", "addr", addr, "error", err)
		return
	}

	if authenticated {
		return
	}

	if host == "" {
		slog.Warn(kind+" listening on all interfaces without authentication", "addr", addr)
		return
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			// Show a warning
			slog.Warn(kind+" listening on a non-loopback address without authentication", "addr", addr)
		}
		return
	}

	if host != "localhost" {
		// Show a warning
		slog.Warn(kind+" listening on a non-loopback hostname without authentication", "addr", addr, "host", host)
	}
}

func setExitNodePrefs(ctx context.Context, lc *local.Client, exitNodeSel string, allowLAN bool) error {
	// Get current prefs and clone
	p, err := lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("GetPrefs: %w", err)
	}

	np := p.Clone()
	np.WantRunning = true
	np.ExitNodeAllowLANAccess = allowLAN

	// Clear any existing exit node first to avoid conflicts
	np.ClearExitNode()

	// SetExitNodeIP accepts either IP or MagicDNS base name
	status, err := lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("Status (for MagicDNS exit node resolution): %w", err) //nolint:staticcheck
	}

	err = np.SetExitNodeIP(exitNodeSel, status)
	if err != nil {
		return fmt.Errorf("SetExitNodeIP(%q): %w", exitNodeSel, err)
	}

	mp := &ipn.MaskedPrefs{
		Prefs:                     *np,
		WantRunningSet:            true,
		ExitNodeIPSet:             true,
		ExitNodeIDSet:             true,
		ExitNodeAllowLANAccessSet: true,
	}

	_, err = lc.EditPrefs(ctx, mp)
	if err != nil {
		return fmt.Errorf("EditPrefs: %w", err)
	}

	return nil
}
