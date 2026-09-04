package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/armon/go-socks5"
)

// singleCredentialStore is a socks5.CredentialStore that accepts exactly one username/password pair
type singleCredentialStore struct {
	username string
	password string
}

func (c singleCredentialStore) Valid(user, password string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(c.username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(c.password)) == 1
	return userMatch && passMatch
}

// startSocksProxy begins listening for SOCKS5 connections on addr, routing all traffic through the dialer
// When username is non-empty, clients must authenticate with matching SOCKS5 username/password credentials
// The returned listener should be closed to stop the server, and the returned channel is closed once the server stops serving
func startSocksProxy(ctx context.Context, d dialer, resolver socks5.NameResolver, addr string, username string, password string) (net.Listener, <-chan struct{}, error) {
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

	// Leaving Credentials nil makes go-socks5 accept connections without any authentication
	if username != "" {
		socksConfig.Credentials = singleCredentialStore{username: username, password: password}
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
		if !errors.Is(serveErr, net.ErrClosed) {
			slog.Warn("SOCKS server stopped", "error", serveErr)
		} else {
			slog.Info("SOCKS server stopped")
		}
	}()

	return l, doneCh, nil
}
