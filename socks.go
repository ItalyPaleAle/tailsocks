package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/armon/go-socks5"
)

// startSocksProxy begins listening for SOCKS5 connections on addr, routing all traffic through the dialer
// The returned listener should be closed to stop the server, and the returned channel is closed once the server stops serving
func startSocksProxy(ctx context.Context, d dialer, resolver socks5.NameResolver, addr string) (net.Listener, <-chan struct{}, error) {
	socksConfig := &socks5.Config{
		// The dialer resolves the name and routes the connection through the active tunnel, so traffic goes via the exit node
		Dial: d.Dial,
		// go-socks5 resolves destination names itself and passes the resulting IP to Dial
		Resolver: resolver,
		Logger: slog.NewLogLogger(
			slog.Default().With(slog.String("scope", "socks")).Handler(),
			slog.LevelInfo,
		),
	}

	socksServer, err := socks5.New(socksConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating socks5 server: %w", err)
	}

	nlc := net.ListenConfig{}
	l, err := nlc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on '%s': %w", addr, err)
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)

		serveErr := socksServer.Serve(l)
		if serveErr != nil {
			slog.Warn("SOCKS server stopped", "error", serveErr)
		}
	}()

	return l, doneCh, nil
}
