package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
)

// PortForward describes a single TCP port-forwarding rule: traffic accepted on Listen is forwarded to Target through the Tailscale tunnel
type PortForward struct {
	// Listen is the local address to listen on (e.g. "127.0.0.1:3900")
	Listen string
	// Target is the remote address to forward to (e.g. "test.com:3900")
	Target string
}

// String returns a human-readable representation of the rule
func (pf PortForward) String() string {
	return pf.Listen + "=>" + pf.Target
}

// dialer abstracts the part of *tsnet.Server used to dial the target host
// It is meant for testing without a real Tailscale tunnel
type dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// ParsePortForward parses a single "--tcp" spec in the form "LISTEN=TARGET"
// E.g. "127.0.0.1:3900=test.com:3900"
func ParsePortForward(spec string) (PortForward, error) {
	if spec == "" {
		return PortForward{}, errors.New("port forward spec is empty")
	}

	listen, target, ok := strings.Cut(spec, "=")
	if !ok {
		return PortForward{}, fmt.Errorf("invalid port forward spec %q: expected format 'LISTEN=TARGET' (e.g. '127.0.0.1:3900=test.com:3900')", spec)
	}

	listen = strings.TrimSpace(listen)
	target = strings.TrimSpace(target)

	err := validateHostPort(listen, true)
	if err != nil {
		return PortForward{}, fmt.Errorf("invalid listen address %q in port forward spec %q: %w", listen, spec, err)
	}

	err = validateHostPort(target, false)
	if err != nil {
		return PortForward{}, fmt.Errorf("invalid target address %q in port forward spec %q: %w", target, spec, err)
	}

	return PortForward{Listen: listen, Target: target}, nil
}

// ParsePortForwards parses all "--tcp" specs and ensures no two rules listen on the same address
func ParsePortForwards(specs []string) ([]PortForward, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	forwards := make([]PortForward, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for i, spec := range specs {
		pf, err := ParsePortForward(spec)
		if err != nil {
			return nil, err
		}

		// Look for duplicate listen addresses
		_, dup := seen[pf.Listen]
		if dup {
			return nil, fmt.Errorf("duplicate listen address %q: each --tcp rule must listen on a distinct address", pf.Listen)
		}
		seen[pf.Listen] = struct{}{}

		forwards[i] = pf
	}

	return forwards, nil
}

// validateHostPort checks that addr is a valid "host:port" pair
// When the host is allowed to be empty (allowEmptyHost), an address like ":3900" is accepted
func validateHostPort(addr string, allowEmptyHost bool) error {
	if addr == "" {
		return errors.New("address is empty")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("expected format 'host:port': %w", err)
	}

	if port == "" {
		return errors.New("port is missing")
	}
	if !allowEmptyHost && host == "" {
		return errors.New("host is missing")
	}

	return nil
}

// startPortForward begins listening for the given rule and forwards every accepted connection to the target through the provided dialer
// The returned listener should be closed to stop the forwarder
func startPortForward(ctx context.Context, d dialer, pf PortForward) (net.Listener, error) {
	nlc := net.ListenConfig{}
	l, err := nlc.Listen(ctx, "tcp", pf.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %q: %w", pf.Listen, err)
	}

	// Logs a warning when a forward listens on a non-loopback address
	warnIfNonLoopbackListenAddr(pf)

	// Accept the connections and forward traffic
	go acceptForwardConns(ctx, d, l, pf)

	return l, nil
}

// acceptForwardConns accepts connections on l until it is closed, handling each in its own goroutine
func acceptForwardConns(ctx context.Context, d dialer, l net.Listener, pf PortForward) {
	for {
		conn, err := l.Accept()
		if err != nil {
			// A closed listener (e.g. during shutdown) is expected
			// Anything else is logged but does not stop the loop unless the listener is gone
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}

			slog.Warn("Error accepting connection for port forward", "forward", pf.String(), "error", err)
			continue
		}

		go handleForwardConn(ctx, d, conn, pf)
	}
}

// handleForwardConn dials the target and pipes data between the accepted local connection and the remote connection
func handleForwardConn(ctx context.Context, d dialer, local net.Conn, pf PortForward) {
	defer local.Close()

	remote, err := d.Dial(ctx, "tcp", pf.Target)
	if err != nil {
		slog.Warn("Failed to dial target for port forward", "forward", pf.String(), "error", err)
		return
	}
	defer remote.Close()

	slog.Debug("Forwarding connection", "forward", pf.String(), "client", local.RemoteAddr().String())

	// Copy in both directions and return when either side is done
	var wg sync.WaitGroup
	wg.Add(2)

	copyAndClose := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)

		// Signal EOF to the other side so the paired copy can unblock
		cw, ok := dst.(interface{ CloseWrite() error })
		if ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copyAndClose(remote, local)
	go copyAndClose(local, remote)

	wg.Wait()
}

// warnIfNonLoopbackListenAddr logs a warning when a forward listens on a non-loopback address, since the forwarded port is unauthenticated
func warnIfNonLoopbackListenAddr(pf PortForward) {
	host, _, err := net.SplitHostPort(pf.Listen)
	if err != nil {
		slog.Warn("Could not determine port forward bind address security", "forward", pf.String(), "error", err)
		return
	}

	if host == "" {
		slog.Warn("Port forward is listening on all interfaces without authentication", "forward", pf.String())
		return
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			slog.Warn("Port forward is listening on a non-loopback address without authentication", "forward", pf.String())
		}
		return
	}

	if host != "localhost" {
		slog.Warn("Port forward is listening on a non-loopback hostname without authentication", "forward", pf.String(), "host", host)
	}
}
