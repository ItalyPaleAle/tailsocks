package main

import (
	"context"
	"fmt"
	"net"

	"github.com/armon/go-socks5"
)

// tunnelDialer resolves a name and then dials the result through whichever tunnel the process was started with
// - In tailnet mode the tunnel is tsnet's embedded netstack, which routes via the configured exit node
// - In tailcat mode it is a tailcat client, whose server does the forwarding
// Resolving here rather than inside the tunnel keeps DNS behavior identical for every consumer: the SOCKS5 server, the HTTP proxy, and the TCP port forwards all honor the selected resolver the same way
type tunnelDialer struct {
	// A *tsnet.Server in tailnet mode, a *tailcatTunnel in tailcat mode
	ts       dialer
	resolver socks5.NameResolver
}

// newTunnelDialer creates a dialer that resolves names with resolver and dials through ts
func newTunnelDialer(ts dialer, resolver socks5.NameResolver) *tunnelDialer {
	return &tunnelDialer{
		ts:       ts,
		resolver: resolver,
	}
}

// Dial resolves the host part of addr when it isn't already an IP, then dials it through the tunnel
func (d *tunnelDialer) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	// addr must be in "host:port" form
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address '%s': %w", addr, err)
	}

	// The SOCKS5 server resolves names itself before invoking the dialer, so addresses usually arrive as IPs and skip the lookup
	ip := net.ParseIP(host)
	if ip == nil {
		ctx, ip, err = d.resolver.Resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve '%s': %w", host, err)
		}

		// A resolver may report success while returning no address, which would otherwise produce a confusing dial error
		if ip == nil {
			return nil, fmt.Errorf("no addresses found for '%s'", host)
		}
	}

	dialAddr := net.JoinHostPort(ip.String(), port)
	conn, err := d.ts.Dial(ctx, network, dialAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial '%s': %w", dialAddr, err)
	}

	return conn, nil
}
