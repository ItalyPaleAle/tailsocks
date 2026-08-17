package main

import (
	"context"
	"fmt"
	"net"

	"github.com/armon/go-socks5"
)

// tailnetDialer dials connections through tsnet's embedded netstack, so traffic is routed via the configured exit node
// Names are resolved with the resolver selected at startup, before the address is handed to tsnet
// Resolving here rather than inside tsnet keeps DNS behavior identical for every consumer: the SOCKS5 server, the HTTP proxy, and the TCP port forwards all honor MagicDNS and --local-dns the same way
type tailnetDialer struct {
	// In production this is always a *tsnet.Server, whose Dial method matches the dialer interface
	ts       dialer
	resolver socks5.NameResolver
}

// newTailnetDialer creates a dialer that resolves names with resolver and dials through ts
func newTailnetDialer(ts dialer, resolver socks5.NameResolver) *tailnetDialer {
	return &tailnetDialer{
		ts:       ts,
		resolver: resolver,
	}
}

// Dial resolves the host part of addr when it isn't already an IP, then dials it through the tailnet
func (d *tailnetDialer) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
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
