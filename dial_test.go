package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubResolver returns a canned result and records the names it was asked to resolve
type stubResolver struct {
	mu    sync.Mutex
	ip    net.IP
	err   error
	names []string
}

func (r *stubResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.names = append(r.names, name)
	return ctx, r.ip, r.err
}

func (r *stubResolver) resolved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.names...)
}

// TestTunnelDialerResolvesNames verifies that a hostname is resolved before being handed to the tunnel, so the tunnel only ever sees IP addresses
func TestTunnelDialerResolvesNames(t *testing.T) {
	resolver := &stubResolver{
		ip: net.ParseIP("100.64.0.7"),
	}
	tunnel := &recordingDialer{}

	d := newTunnelDialer(tunnel, resolver)
	_, err := d.Dial(t.Context(), "tcp", "service.tailnet.ts.net:8080")

	// The dial itself fails because recordingDialer always fails, but the address it received is what matters here
	require.Error(t, err)
	assert.Equal(t, []string{"service.tailnet.ts.net"}, resolver.resolved())
	assert.Equal(t, []string{"100.64.0.7:8080"}, tunnel.dialed())
}

// TestTunnelDialerSkipsResolutionForIPs verifies that an address that is already an IP is dialed without a lookup
// This is the common path for the SOCKS5 proxy, which resolves names itself before invoking the dialer
func TestTunnelDialerSkipsResolutionForIPs(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "IPv4",
			addr: "100.64.0.7:443",
			want: "100.64.0.7:443",
		},
		{
			name: "IPv6",
			addr: "[fd7a:115c:a1e0::1]:443",
			want: "[fd7a:115c:a1e0::1]:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &stubResolver{
				err: errors.New("resolver must not be called"),
			}
			tunnel := &recordingDialer{}

			d := newTunnelDialer(tunnel, resolver)
			_, err := d.Dial(t.Context(), "tcp", tt.addr)

			require.Error(t, err)
			assert.Empty(t, resolver.resolved())
			assert.Equal(t, []string{tt.want}, tunnel.dialed())
		})
	}
}

// TestTunnelDialerResolverFailure verifies that a failed lookup is reported instead of being dialed
func TestTunnelDialerResolverFailure(t *testing.T) {
	tests := []struct {
		name     string
		resolver *stubResolver
	}{
		{
			name: "resolver returns an error",
			resolver: &stubResolver{
				err: errors.New("lookup failed"),
			},
		},
		{
			name: "resolver returns no address",
			resolver: &stubResolver{
				ip: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnel := &recordingDialer{}

			d := newTunnelDialer(tunnel, tt.resolver)
			_, err := d.Dial(t.Context(), "tcp", "service.example.com:443")

			require.Error(t, err)
			assert.Empty(t, tunnel.dialed())
		})
	}
}

// TestTunnelDialerInvalidAddress verifies that an address without a port is rejected rather than resolved
func TestTunnelDialerInvalidAddress(t *testing.T) {
	resolver := &stubResolver{
		ip: net.ParseIP("100.64.0.7"),
	}
	tunnel := &recordingDialer{}

	d := newTunnelDialer(tunnel, resolver)
	_, err := d.Dial(t.Context(), "tcp", "service.example.com")

	require.Error(t, err)
	assert.Empty(t, resolver.resolved())
	assert.Empty(t, tunnel.dialed())
}
