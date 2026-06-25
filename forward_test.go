package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
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
				if err == nil {
					t.Fatalf("expected error for spec %q, got none", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for spec %q: %v", tt.spec, err)
			}
			if got.Listen != tt.wantListen || got.Target != tt.wantTarget {
				t.Fatalf("got %+v, want listen=%q target=%q", got, tt.wantListen, tt.wantTarget)
			}
		})
	}
}

func TestParsePortForwards(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got, err := ParsePortForwards(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("multiple valid", func(t *testing.T) {
		got, err := ParsePortForwards([]string{
			"127.0.0.1:3900=test.com:3900",
			"127.0.0.1:5432=db.internal:5432",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 forwards, got %d", len(got))
		}
	})

	t.Run("duplicate listen address", func(t *testing.T) {
		_, err := ParsePortForwards([]string{
			"127.0.0.1:3900=test.com:3900",
			"127.0.0.1:3900=other.com:80",
		})
		if err == nil {
			t.Fatal("expected error for duplicate listen address, got none")
		}
	})

	t.Run("one invalid fails all", func(t *testing.T) {
		_, err := ParsePortForwards([]string{
			"127.0.0.1:3900=test.com:3900",
			"bogus",
		})
		if err == nil {
			t.Fatal("expected error for invalid spec, got none")
		}
	})
}

func TestPortForwardString(t *testing.T) {
	pf := PortForward{Listen: "127.0.0.1:3900", Target: "test.com:3900"}
	if got, want := pf.String(), "127.0.0.1:3900=>test.com:3900"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// directDialer implements the dialer interface by dialing the address directly,
// standing in for tsnet's tunnel dialer in tests.
type directDialer struct{}

func (directDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// TestPortForwardEndToEnd starts a real TCP echo server as the "target", a
// forwarder pointing at it, and verifies that data sent to the local listen
// address is round-tripped through the target.
func TestPortForwardEndToEnd(t *testing.T) {
	// Target echo server.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}
	defer target.Close()

	go func() {
		for {
			c, aerr := target.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pf := PortForward{Listen: "127.0.0.1:0", Target: target.Addr().String()}
	l, err := startPortForward(ctx, directDialer{}, pf)
	if err != nil {
		t.Fatalf("failed to start port forward: %v", err)
	}
	defer l.Close()

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to dial forwarder: %v", err)
	}
	defer conn.Close()

	want := []byte("hello tailsocks")
	if _, err = conn.Write(want); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestPortForwardDialError ensures a failed target dial simply closes the
// client connection without crashing the forwarder.
func TestPortForwardDialError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Target points at a port that is closed; reserve one then close it.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	deadTarget := tmp.Addr().String()
	_ = tmp.Close()

	pf := PortForward{Listen: "127.0.0.1:0", Target: deadTarget}
	l, err := startPortForward(ctx, directDialer{}, pf)
	if err != nil {
		t.Fatalf("failed to start port forward: %v", err)
	}
	defer l.Close()

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to dial forwarder: %v", err)
	}
	defer conn.Close()

	// The forwarder should close our connection because the target dial fails.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after failed target dial")
	}
}
