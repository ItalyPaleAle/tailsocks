package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortForward(t *testing.T) {
	tests := []struct {
		name       string
		spec       string
		wantListen string
		wantTarget string
		wantErr    bool
	}{
		{
			name:       "valid IP listen and DNS target",
			spec:       "127.0.0.1:3900=test.com:3900",
			wantListen: "127.0.0.1:3900",
			wantTarget: "test.com:3900",
		},
		{
			name:       "valid with surrounding whitespace",
			spec:       "  127.0.0.1:3900 = test.com:3900  ",
			wantListen: "127.0.0.1:3900",
			wantTarget: "test.com:3900",
		},
		{
			name:       "listen on all interfaces",
			spec:       ":8080=10.0.0.1:80",
			wantListen: ":8080",
			wantTarget: "10.0.0.1:80",
		},
		{
			name:       "localhost hostname",
			spec:       "localhost:5000=db.internal:5432",
			wantListen: "localhost:5000",
			wantTarget: "db.internal:5432",
		},
		{
			name:    "empty spec",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "missing separator",
			spec:    "127.0.0.1:3900",
			wantErr: true,
		},
		{
			name:    "missing listen port",
			spec:    "127.0.0.1=test.com:3900",
			wantErr: true,
		},
		{
			name:    "missing target port",
			spec:    "127.0.0.1:3900=test.com",
			wantErr: true,
		},
		{
			name:    "target host missing",
			spec:    "127.0.0.1:3900=:3900",
			wantErr: true,
		},
		{
			name:    "empty listen",
			spec:    "=test.com:3900",
			wantErr: true,
		},
		{
			name:    "empty target",
			spec:    "127.0.0.1:3900=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortForward(tt.spec)
			if tt.wantErr {
				require.Error(t, err, "expected error for spec %q", tt.spec)
				return
			}
			require.NoError(t, err, "unexpected error for spec %q", tt.spec)
			assert.Equal(t, tt.wantListen, got.Listen)
			assert.Equal(t, tt.wantTarget, got.Target)
		})
	}
}

func TestParsePortForwards(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got, err := ParsePortForwards(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("multiple valid", func(t *testing.T) {
		got, err := ParsePortForwards([]string{
			"127.0.0.1:3900=test.com:3900",
			"127.0.0.1:5432=db.internal:5432",
		})
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("duplicate listen address", func(t *testing.T) {
		_, err := ParsePortForwards([]string{
			"127.0.0.1:3900=test.com:3900",
			"127.0.0.1:3900=other.com:80",
		})
		require.Error(t, err)
	})

	t.Run("one invalid fails all", func(t *testing.T) {
		_, err := ParsePortForwards([]string{
			"127.0.0.1:3900=test.com:3900",
			"bogus",
		})
		require.Error(t, err)
	})
}

func TestPortForwardString(t *testing.T) {
	pf := PortForward{Listen: "127.0.0.1:3900", Target: "test.com:3900"}
	got, want := pf.String(), "127.0.0.1:3900=>test.com:3900"
	assert.Equal(t, want, got)
}

// directDialer implements the dialer interface by dialing the address directly, standing in for tsnet's tunnel dialer in tests
type directDialer struct{}

func (directDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr) //nolint:wrapcheck
}

// TestPortForwardEndToEnd starts a real TCP echo server as the "target", a forwarder pointing at it, and verifies that data sent to the local listen address is round-tripped through the target
func TestPortForwardEndToEnd(t *testing.T) {
	// Target echo server.
	target, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)
	defer target.Close() //nolint:errcheck

	go func() {
		for {
			c, aerr := target.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	pf := PortForward{
		Listen: "127.0.0.1:0",
		Target: target.Addr().String(),
	}
	l, err := startPortForward(ctx, directDialer{}, pf)
	require.NoError(t, err)
	defer l.Close() //nolint:errcheck

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second) //nolint:noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	want := []byte("hello tailsocks")
	_, err = conn.Write(want)
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestPortForwardDialError ensures a failed target dial simply closes the client connection without crashing the forwarder
func TestPortForwardDialError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Target points at a port that is closed; reserve one then close it
	tmp, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)
	deadTarget := tmp.Addr().String()
	_ = tmp.Close()

	pf := PortForward{Listen: "127.0.0.1:0", Target: deadTarget}
	l, err := startPortForward(ctx, directDialer{}, pf)
	require.NoError(t, err)
	defer l.Close() //nolint:errcheck

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second) //nolint:noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// The forwarder should close our connection because the target dial fails
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	require.Error(t, err)
}
