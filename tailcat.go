package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armon/go-socks5"
	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

const (
	// Name of the file inside the state directory that holds the tailcat client identity
	tailcatKeyFileName = "tailcat-key.json"
	// Environment variable read when --experimental-tailcat is set to "-"
	tailcatTokenEnvVar = "TAILSOCKS_TAILCAT_TOKEN" //nolint:gosec
	// Prefix of the TXT record tailcat uses to publish a token under a DNS name
	tailcatTXTPrefix = "tailcat="
	// Every token starts with this, which is how a token is told apart from a path or a DNS name
	tailcatTokenPrefix = "tc"
	// How long to wait for the initial handshake with the tailcat server
	tailcatHandshakeTimeout = 30 * time.Second
	// How long a single handshake attempt is given before another one is sent
	tailcatHandshakeAttemptTimeout = 2 * time.Second
	// How long to wait between handshake attempts
	tailcatHandshakeRetryInterval = 250 * time.Millisecond
	// How long to wait for the TXT lookup that turns a DNS name into a token
	tailcatTXTLookupTimeout = 10 * time.Second
	// Permissions for the private key file and the directory holding it
	tailcatKeyFileMode = 0o600
	tailcatKeyDirMode  = 0o700
)

// tailcatTunnel dials through a tailcat server that is running as an exit node
// It satisfies the same dialer interface as *tsnet.Server, so everything layered on top (the SOCKS5 proxy, the HTTP proxy, the TCP port forwards) is shared with tailnet mode
type tailcatTunnel struct {
	cl *tailcat.Client
}

// Dial opens a connection to an already-resolved address through the tailcat server
// tailcat maps IPv4 destinations into the NAT64 prefix itself, since the tunnel is IPv6-only
func (t *tailcatTunnel) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	// A tailcat tunnel carries TCP only: its UDP dial path is deliberately unimplemented
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("unsupported network '%s': a tailcat tunnel carries TCP only", network)
	}

	// tunnelDialer resolves names before reaching this point, so addr always carries an IP
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address '%s': %w", addr, err)
	}

	conn, err := t.cl.DialTCP(ctx, ap)
	if err != nil {
		return nil, fmt.Errorf("failed to dial '%s' through the tailcat server: %w", addr, err)
	}

	return conn, nil
}

// Close shuts down the tailcat client and its DERP connections
func (t *tailcatTunnel) Close() error {
	err := t.cl.Close()
	if err != nil {
		return fmt.Errorf("failed to close the tailcat client: %w", err)
	}
	return nil
}

// setupTailcat brings up the tailcat backend: it loads the token and the client identity, connects to the server, and returns the dialer and resolver the proxies run on
func setupTailcat(ctx context.Context, opts *Options) (*backend, error) {
	slog.Warn("tailcat mode is experimental: tailcat makes no stability promises for its API or its wire format, so this mode can change or break in a future release")

	blob, err := loadTailcatToken(ctx, opts.Tailcat)
	if err != nil {
		return nil, err
	}

	priv, keyPath, err := loadOrCreateTailcatKey(opts.StateDir, opts.TailcatKey)
	if err != nil {
		return nil, err
	}

	cl := &tailcat.Client{
		Server:     blob,
		Key:        priv,
		DERPMapURL: opts.TailcatDERPMapURL,
		// tailcat logs the whole WireGuard and DERP lifecycle, which is too noisy for the default level
		Logf: func(format string, args ...any) {
			slog.Debug(fmt.Sprintf(format, args...), slog.String("scope", "tailcat"))
		},
	}

	// Log the public key before connecting rather than after
	// A server started with --allow simply ignores clients that aren't on its list, so a failed handshake looks like a timeout and the key is what the operator needs to fix it
	pubKey := priv.Public().String()
	slog.Info("Connecting to tailcat server", "clientPublicKey", pubKey, "keyFile", keyPath)

	res, err := tailcatHandshake(ctx, cl)
	if err != nil {
		_ = cl.Close()
		return nil, fmt.Errorf("handshake with the tailcat server failed; if the server runs with --allow, check that '%s' is on its list: %w", pubKey, err)
	}
	slog.Info("Connected to tailcat server", "latency", res.Latency)

	tunnel := &tailcatTunnel{cl: cl}

	resolver := newTailcatResolver(opts, tunnel)

	return &backend{
		dial:     newTunnelDialer(tunnel, resolver),
		resolver: resolver,
		close:    func() { _ = tunnel.Close() },
	}, nil
}

// tailcatHandshake registers this client with the tailcat server, retrying until the overall deadline
//
// The handshake is a single unacknowledged datagram over DERP, so it is simply lost when either side's relay connection is not up yet, which is the normal state of affairs for the first moments after startup
// Retrying is also what keeps a server that comes back later reachable, rather than failing the process on a transient relay hiccup
func tailcatHandshake(ctx context.Context, cl *tailcat.Client) (tailcat.PingResult, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, tailcatHandshakeTimeout)
	defer cancel()

	var lastErr error
	for {
		attemptCtx, cancelAttempt := context.WithTimeout(handshakeCtx, tailcatHandshakeAttemptTimeout)
		res, err := cl.Ping(attemptCtx)
		cancelAttempt()

		if err == nil {
			return res, nil
		}
		lastErr = err

		select {
		case <-handshakeCtx.Done():
			return tailcat.PingResult{}, lastErr
		case <-time.After(tailcatHandshakeRetryInterval):
		}
	}
}

// newTailcatResolver picks the resolver used in tailcat mode
// There is no MagicDNS here, so the choice is between resolving locally and resolving on the far side of the tunnel
func newTailcatResolver(opts *Options, tunnel *tailcatTunnel) socks5.NameResolver {
	if opts.LocalDNS {
		slog.Info("Using local DNS resolver")
		return socks5.DNSResolver{}
	}

	// Queries go through the raw tunnel rather than through tunnelDialer: resolving the DNS server's own address would be circular, which is also why --experimental-tailcat-dns is required to be an IP
	slog.Info("Resolving DNS through the tailcat tunnel", "server", opts.TailcatDNS)

	return NewRemoteDNSResolver(tunnel.Dial, opts.TailcatDNS)
}

// loadTailcatToken turns the value of --experimental-tailcat into a token
// It accepts the token itself, "@path" to read it from a file, "-" to read it from the environment, or a DNS name whose "tailcat=" TXT record holds one
func loadTailcatToken(ctx context.Context, arg string) (tailcat.ConnBlob, error) {
	arg = strings.TrimSpace(arg)

	var (
		raw string
		err error
	)
	switch {
	case arg == "-":
		raw = strings.TrimSpace(os.Getenv(tailcatTokenEnvVar))
		if raw == "" {
			return "", fmt.Errorf("--experimental-tailcat is '-' but the %s environment variable is empty", tailcatTokenEnvVar)
		}

	case strings.HasPrefix(arg, "@"):
		raw, err = readTailcatTokenFile(strings.TrimPrefix(arg, "@"))
		if err != nil {
			return "", err
		}

	case strings.Contains(arg, "."):
		// A token is base64 and can never contain a dot, so anything holding one is a DNS name
		raw, err = lookupTailcatTXT(ctx, arg)
		if err != nil {
			return "", err
		}

	default:
		raw = arg
	}

	if !strings.HasPrefix(raw, tailcatTokenPrefix) {
		return "", fmt.Errorf("value for --experimental-tailcat is not a tailcat token: expected it to start with '%s'", tailcatTokenPrefix)
	}

	blob := tailcat.ConnBlob(raw)
	_, err = tailcat.ParseConnBlob(blob)
	if err != nil {
		return "", fmt.Errorf("failed to parse the tailcat token: %w", err)
	}

	return blob, nil
}

// readTailcatTokenFile reads a token from a file, so it never has to appear in the process arguments
func readTailcatTokenFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("--experimental-tailcat is '@' with no file path after it")
	}

	read, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("failed to read the tailcat token from '%s': %w", path, err)
	}

	return strings.TrimSpace(string(read)), nil
}

// lookupTailcatTXT resolves a DNS name to the token published in its "tailcat=" TXT record
// The lookup uses the local resolver on purpose: it happens before the tunnel exists
func lookupTailcatTXT(ctx context.Context, name string) (string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, tailcatTXTLookupTimeout)
	defer cancel()

	var r net.Resolver
	records, err := r.LookupTXT(lookupCtx, name)
	if err != nil {
		return "", fmt.Errorf("failed to look up the TXT record for '%s': %w", name, err)
	}

	for _, txt := range records {
		suffix, ok := strings.CutPrefix(txt, tailcatTXTPrefix)
		if ok {
			return strings.TrimSpace(suffix), nil
		}
	}

	return "", fmt.Errorf("no '%s' TXT record found for '%s'", tailcatTXTPrefix, name)
}

// loadOrCreateTailcatKey returns the client identity the tailcat server sees, along with the path it was loaded from
// A stable identity is what makes the server's --allow list usable across restarts, so a key is persisted unless the caller asks for a throwaway one
// The file format matches tailcat's own key files, so a path like ~/.config/tailcat/keys/client-default.private.json can be used directly
func loadOrCreateTailcatKey(stateDir string, spec string) (priv key.NodePrivate, path string, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "new" {
		return key.NewNode(), "(ephemeral)", nil
	}

	path = spec
	if path == "" {
		path = filepath.Join(stateDir, tailcatKeyFileName)
	}

	read, err := os.ReadFile(path) //nolint:gosec
	switch {
	case err == nil:
		var stored tailcat.PrivateKey
		err = json.Unmarshal(read, &stored)
		if err != nil {
			return priv, path, fmt.Errorf("failed to parse the tailcat client key in '%s': %w", path, err)
		}
		if stored.Private.IsZero() {
			return priv, path, fmt.Errorf("the tailcat client key in '%s' is empty", path)
		}

		return stored.Private, path, nil

	case errors.Is(err, os.ErrNotExist):
		// Fall through to create one below

	default:
		return priv, path, fmt.Errorf("failed to read the tailcat client key from '%s': %w", path, err)
	}

	created := tailcat.NewPrivateKey()

	encoded, err := json.MarshalIndent(created, "", "\t")
	if err != nil {
		return priv, path, fmt.Errorf("failed to encode a new tailcat client key: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(path), tailcatKeyDirMode)
	if err != nil {
		return priv, path, fmt.Errorf("failed to create the directory for the tailcat client key: %w", err)
	}

	err = os.WriteFile(path, encoded, tailcatKeyFileMode)
	if err != nil {
		return priv, path, fmt.Errorf("failed to write the tailcat client key to '%s': %w", path, err)
	}
	slog.Info("Created a new tailcat client key", "path", path)

	return created.Private, path, nil
}
