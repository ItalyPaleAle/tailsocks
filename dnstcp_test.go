package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsStub is a DNS-over-TCP server that answers from a fixed table, standing in for whatever resolver sits on the far side of the tunnel
type dnsStub struct {
	// Answers keyed by lowercase FQDN, then by record type
	answers map[string]map[dnsmessage.Type][]netip.Addr
	ttl     uint32
	// When set, every response carries this ID instead of the one from the query
	forceID *uint16

	ln      net.Listener
	queries chan string
}

func newDNSStub(t *testing.T) *dnsStub {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &dnsStub{
		answers: map[string]map[dnsmessage.Type][]netip.Addr{},
		ttl:     60,
		ln:      ln,
		queries: make(chan string, 32),
	}

	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()

	return s
}

// addr returns the "ip:port" pair the resolver should be pointed at
func (s *dnsStub) addr() string {
	return s.ln.Addr().String()
}

// set registers the answer for a name, which must be given without a trailing dot
func (s *dnsStub) set(name string, qt dnsmessage.Type, addrs ...netip.Addr) {
	byType, ok := s.answers[name+"."]
	if !ok {
		byType = map[dnsmessage.Type][]netip.Addr{}
		s.answers[name+"."] = byType
	}
	byType[qt] = addrs
}

func (s *dnsStub) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *dnsStub) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	for {
		query, err := readDNSMessage(conn)
		if err != nil {
			return
		}

		resp, name, err := s.respond(query)
		if err != nil {
			return
		}

		select {
		case s.queries <- name:
		default:
		}

		err = writeDNSMessage(conn, resp)
		if err != nil {
			return
		}
	}
}

func (s *dnsStub) respond(query []byte) (resp []byte, name string, err error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	q, err := p.Question()
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	id := h.ID
	if s.forceID != nil {
		id = *s.forceID
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true})
	b.EnableCompression()

	err = b.StartQuestions()
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}
	err = b.Question(q)
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	err = b.StartAnswers()
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: s.ttl}
	for _, addr := range s.answers[q.Name.String()][q.Type] {
		rh.Type = q.Type

		switch q.Type { //nolint:exhaustive
		case dnsmessage.TypeA:
			err = b.AResource(rh, dnsmessage.AResource{A: addr.As4()})
		case dnsmessage.TypeAAAA:
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: addr.As16()})
		}
		if err != nil {
			return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
		}
	}

	resp, err = b.Finish()
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	return resp, q.Name.String(), nil
}

// directDial reaches the stub without a tunnel, so the resolver can be tested on its own
func directDial(ctx context.Context, network string, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr) //nolint:wrapcheck
}

// TestRemoteDNSResolverA verifies the common case: an A record is returned and the query really went to the configured server
func TestRemoteDNSResolverA(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.10"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.10", ip.String())

	assert.Equal(t, "example.com.", <-stub.queries)
}

// TestRemoteDNSResolverPrefersA verifies that an IPv4 answer wins over an IPv6 one, since IPv4 destinations ride tailcat's NAT64 mapping
func TestRemoteDNSResolverPrefersA(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("dual.example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.20"))
	stub.set("dual.example.com", dnsmessage.TypeAAAA, netip.MustParseAddr("2001:db8::20"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "dual.example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.20", ip.String())
}

// TestRemoteDNSResolverFallsBackToAAAA verifies that an IPv6-only name still resolves
func TestRemoteDNSResolverFallsBackToAAAA(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("v6.example.com", dnsmessage.TypeAAAA, netip.MustParseAddr("2001:db8::30"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "v6.example.com")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::30", ip.String())
}

// TestRemoteDNSResolverNormalizesNames verifies that casing and whitespace do not produce a second lookup
func TestRemoteDNSResolverNormalizesNames(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("mixed.example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.40"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "  MiXeD.Example.COM ")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.40", ip.String())
}

// TestRemoteDNSResolverCaches verifies that a repeated lookup is served from the cache instead of hitting the server again
func TestRemoteDNSResolverCaches(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("cached.example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.50"))

	// The A and AAAA lookups run in parallel, so the counter has to be safe for concurrent use
	var dials atomic.Int64
	countingDial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		dials.Add(1)
		return directDial(ctx, network, addr)
	}

	r := NewRemoteDNSResolver(countingDial, stub.addr())

	for range 3 {
		_, ip, err := r.Resolve(t.Context(), "cached.example.com")
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.50", ip.String())
	}

	// One connection each for the A and the AAAA question, from the first lookup only
	assert.Equal(t, int64(2), dials.Load())
}

// TestRemoteDNSResolverNoAnswer verifies that a name the server knows nothing about is reported rather than returning a nil address
func TestRemoteDNSResolverNoAnswer(t *testing.T) {
	stub := newDNSStub(t)

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "missing.example.com")
	require.Error(t, err)
	assert.Nil(t, ip)
	assert.Contains(t, err.Error(), "no addresses found")
}

// TestRemoteDNSResolverRejectsMismatchedID verifies that a response answering a different question is not accepted
func TestRemoteDNSResolverRejectsMismatchedID(t *testing.T) {
	stub := newDNSStub(t)
	wrongID := uint16(0)
	stub.forceID = &wrongID
	stub.set("spoofed.example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.60"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, _, err := r.Resolve(t.Context(), "spoofed.example.com")
	require.Error(t, err)
}

// TestRemoteDNSResolverUnreachableServer verifies that a resolver pointed at nothing fails instead of hanging
func TestRemoteDNSResolverUnreachableServer(t *testing.T) {
	// Take a port and immediately release it, so connecting to it is refused
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	r := NewRemoteDNSResolver(directDial, addr)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, _, err = r.Resolve(ctx, "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "through the tunnel")
}

// TestReadDNSMessageRejectsOversized verifies that a server claiming an absurd response length is refused before the read
func TestReadDNSMessageRejectsOversized(t *testing.T) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], 0xFFFF)

	_, err := readDNSMessage(io.MultiReader(bytesReader(buf[:]), zeroReader{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b []byte
	i int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
