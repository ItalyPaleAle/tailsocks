package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsStubMode says how the stub treats one of the two transports
type dnsStubMode int

const (
	// Answers queries normally
	dnsStubAnswers dnsStubMode = iota
	// Takes the query and never replies, which is how a tailcat server that does not forward a protocol looks from the client side: the packet filter drops it rather than refusing it
	dnsStubDrops
)

// dnsStub is a DNS server that answers from a fixed table, standing in for whatever resolver sits on the far side of the tunnel
// It binds the same port over both transports, so a resolver pointed at it can be watched choosing between them
type dnsStub struct {
	// Guards everything a test changes while the stub is already serving
	mu sync.Mutex
	// Answers keyed by lowercase FQDN, then by record type
	answers map[string]map[dnsmessage.Type][]netip.Addr
	ttl     uint32
	// When set, every response carries this ID instead of the one from the query
	forceID *uint16
	// When set, a response sent over UDP carries the truncation bit and no answers, the way a server replies when its answer does not fit one datagram
	truncateUDP bool
	// When set, a query for this record type is never answered, which fails one question of a lookup while the other is served normally
	dropType dnsmessage.Type

	tcpMode dnsStubMode
	udpMode dnsStubMode

	ln      net.Listener
	pc      net.PacketConn
	queries chan string
	// Counted per transport, so a test can tell which one actually carried a query, including one that was dropped rather than answered
	tcpQueries atomic.Int32
	udpQueries atomic.Int32
}

// newDNSStub creates a stub that answers over both transports
func newDNSStub(t *testing.T) *dnsStub {
	t.Helper()

	return newDNSStubModes(t, dnsStubAnswers, dnsStubAnswers)
}

// newDNSStubModes creates a stub that treats each transport as asked, so a server that carries only one of them can be modeled
func newDNSStubModes(t *testing.T, tcpMode dnsStubMode, udpMode dnsStubMode) *dnsStub {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// The same port over UDP, so one "ip:port" reaches the stub either way
	pc, err := lc.ListenPacket(t.Context(), "udp", ln.Addr().String())
	require.NoError(t, err)

	s := &dnsStub{
		answers: map[string]map[dnsmessage.Type][]netip.Addr{},
		ttl:     60,
		tcpMode: tcpMode,
		udpMode: udpMode,
		ln:      ln,
		pc:      pc,
		queries: make(chan string, 32),
	}

	t.Cleanup(func() {
		_ = ln.Close()
		_ = pc.Close()
	})
	go s.serve()
	go s.servePackets()

	return s
}

// addr returns the "ip:port" pair the resolver should be pointed at
func (s *dnsStub) addr() string {
	return s.ln.Addr().String()
}

// set registers the answer for a name, which must be given without a trailing dot
func (s *dnsStub) set(name string, qt dnsmessage.Type, addrs ...netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	byType, ok := s.answers[name+"."]
	if !ok {
		byType = map[dnsmessage.Type][]netip.Addr{}
		s.answers[name+"."] = byType
	}
	byType[qt] = addrs
}

// setForceID makes every response carry the given ID instead of the one from the query
func (s *dnsStub) setForceID(id uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.forceID = &id
}

// setTruncateUDP makes every response sent over UDP carry the truncation bit and no answers
func (s *dnsStub) setTruncateUDP() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.truncateUDP = true
}

// setDropType leaves queries for one record type unanswered, whatever transport they arrive on
func (s *dnsStub) setDropType(qt dnsmessage.Type) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dropType = qt
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

		s.tcpQueries.Add(1)
		if s.tcpMode == dnsStubDrops {
			continue
		}

		resp, name, err := s.respond(query, false)
		if err != nil {
			return
		}

		select {
		case s.queries <- name:
		default:
		}

		// Left unanswered on purpose, with the connection held open so the client waits rather than seeing it close
		if resp == nil {
			continue
		}

		err = writeDNSMessage(conn, resp)
		if err != nil {
			return
		}
	}
}

// servePackets answers over UDP, where each datagram carries one whole message
func (s *dnsStub) servePackets() {
	buf := make([]byte, maxDNSDatagramSize)

	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}

		s.udpQueries.Add(1)
		if s.udpMode == dnsStubDrops {
			continue
		}

		resp, name, err := s.respond(buf[:n], true)
		if err != nil {
			continue
		}

		select {
		case s.queries <- name:
		default:
		}

		// Left unanswered on purpose
		if resp == nil {
			continue
		}

		_, err = s.pc.WriteTo(resp, from)
		if err != nil {
			return
		}
	}
}

// respond builds the answer to a query, where overUDP says which transport it arrived on, since that is what decides whether the answer is truncated
func (s *dnsStub) respond(query []byte, overUDP bool) (resp []byte, name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	truncate := overUDP && s.truncateUDP

	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	q, err := p.Question()
	if err != nil {
		return nil, "", fmt.Errorf("dns stub failed to build a response: %w", err)
	}

	// A nil response tells the caller to say nothing at all, the way a server that ignores a question leaves the client waiting
	if s.dropType != 0 && q.Type == s.dropType {
		return nil, q.Name.String(), nil
	}

	id := h.ID
	if s.forceID != nil {
		id = *s.forceID
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true, Truncated: truncate})
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

	// A truncated response carries the question and the bit that says to ask again over TCP, but none of the record set that did not fit
	answers := s.answers[q.Name.String()][q.Type]
	if truncate {
		answers = nil
	}

	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: s.ttl}
	for _, addr := range answers {
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

// pinTransport settles the transport up front, so a test that counts connections measures its own lookups rather than the one-time probe that would otherwise dial both
func pinTransport(r *RemoteDNSResolver, transport dnsTransport) {
	r.transport.Store(int32(transport))
}

// TestRemoteDNSResolverUsesUDP verifies that a server reachable only over UDP is resolved through, which is the case a TCP-only resolver could never serve
func TestRemoteDNSResolverUsesUDP(t *testing.T) {
	stub := newDNSStubModes(t, dnsStubDrops, dnsStubAnswers)
	stub.set("example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.10"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.10", ip.String())

	// The answer can only have come over UDP, since nothing was ever sent back over TCP
	assert.Equal(t, dnsTransportUDP, dnsTransport(r.transport.Load()))
	assert.Positive(t, stub.udpQueries.Load())
}

// TestRemoteDNSResolverFallsBackToTCP verifies that a server swallowing UDP is still resolved through, which is what a tailcat exit node predating v0.7.0 (or a custom server that never sets OnUDPForward) does: it forwards TCP only and drops UDP without refusing it
func TestRemoteDNSResolverFallsBackToTCP(t *testing.T) {
	stub := newDNSStubModes(t, dnsStubAnswers, dnsStubDrops)
	stub.set("example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.11"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.11", ip.String())

	assert.Equal(t, dnsTransportTCP, dnsTransport(r.transport.Load()))
}

// TestRemoteDNSResolverRemembersTransport verifies that the transport is discovered once rather than raced on every lookup, so a server that drops UDP is not probed over and over
func TestRemoteDNSResolverRemembersTransport(t *testing.T) {
	stub := newDNSStubModes(t, dnsStubAnswers, dnsStubDrops)
	stub.set("first.example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.12"))
	stub.set("second.example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.13"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, _, err := r.Resolve(t.Context(), "first.example.com")
	require.NoError(t, err)

	// Whatever the first lookup spent finding out, the second one asks over TCP alone
	probed := stub.udpQueries.Load()
	require.Positive(t, probed)

	_, ip, err := r.Resolve(t.Context(), "second.example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.13", ip.String())

	assert.Equal(t, probed, stub.udpQueries.Load(), "expected no further UDP probes once the transport was known")
}

// TestRemoteDNSResolverRetriesTruncatedOverTCP verifies that an answer too large for a datagram is asked for again over TCP, rather than being returned half-empty
func TestRemoteDNSResolverRetriesTruncatedOverTCP(t *testing.T) {
	stub := newDNSStub(t)
	stub.setTruncateUDP()
	stub.set("example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.14"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	// Pinned to UDP: with both transports answering, a race would be settled by whichever is quicker, and the retry is only reached by going over UDP first
	pinTransport(r, dnsTransportUDP)

	_, ip, err := r.Resolve(t.Context(), "example.com")
	require.NoError(t, err)

	// The address is only in the full answer, which arrived over TCP after the truncated datagram
	assert.Equal(t, "203.0.113.14", ip.String())
	assert.Positive(t, stub.tcpQueries.Load())

	// Having to truncate says nothing about whether UDP works, so it stays the transport of choice
	assert.Equal(t, dnsTransportUDP, dnsTransport(r.transport.Load()))
}

// TestRemoteDNSResolverKeepsTransportOnPartialFailure verifies that one unanswered question does not throw away a transport that is plainly working
// A resolver that answers A and ignores AAAA is a real shape to meet, and forgetting on that would re-probe both transports on every single lookup
func TestRemoteDNSResolverKeepsTransportOnPartialFailure(t *testing.T) {
	stub := newDNSStubModes(t, dnsStubAnswers, dnsStubDrops)
	stub.set("example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.16"))

	// The AAAA question is never answered, so that half of the lookup can only end in the deadline below
	stub.setDropType(dnsmessage.TypeAAAA)

	r := NewRemoteDNSResolver(directDial, stub.addr())
	pinTransport(r, dnsTransportTCP)

	// Short, since the lookup is only done once the ignored question has run out of time
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	_, ip, err := r.Resolve(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.16", ip.String())

	// The A question came back over TCP, so TCP is still known to work
	assert.Equal(t, dnsTransportTCP, dnsTransport(r.transport.Load()))
}

// TestRemoteDNSResolverReportsBothTransports verifies that a server answering on neither is reported as both failures, rather than whichever happened to finish last
func TestRemoteDNSResolverReportsBothTransports(t *testing.T) {
	stub := newDNSStubModes(t, dnsStubDrops, dnsStubDrops)
	stub.set("example.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.15"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	// Both transports have to run out their own clock here, so the deadline is the test's rather than the resolver's
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, _, err := r.Resolve(ctx, "example.com")
	require.Error(t, err)
	require.ErrorContains(t, err, "over udp")
	require.ErrorContains(t, err, "over tcp")

	// A failure leaves nothing remembered, so the next lookup starts over instead of being pinned to a transport that never worked
	assert.Equal(t, dnsTransportUnknown, dnsTransport(r.transport.Load()))
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
	pinTransport(r, dnsTransportTCP)

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
	stub.setForceID(0)
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

// TestRemoteDNSResolverIDN verifies that an internationalized name is asked for in its punycode form, since raw UTF-8 in the
func TestRemoteDNSResolverIDN(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("xn--caf-dma.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.70"))

	r := NewRemoteDNSResolver(directDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "café.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.70", ip.String())

	assert.Equal(t, "xn--caf-dma.com.", <-stub.queries)
}

// TestRemoteDNSResolverIDNSharesCacheEntry verifies that the Unicode and punycode spellings of one name are a single cache
func TestRemoteDNSResolverIDNSharesCacheEntry(t *testing.T) {
	stub := newDNSStub(t)
	stub.set("xn--caf-dma.com", dnsmessage.TypeA, netip.MustParseAddr("203.0.113.80"))

	var dials atomic.Int64
	countingDial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		dials.Add(1)
		return directDial(ctx, network, addr)
	}

	r := NewRemoteDNSResolver(countingDial, stub.addr())
	pinTransport(r, dnsTransportTCP)

	for _, name := range []string{"café.com", "CAFÉ.com", " Café.com ", "xn--caf-dma.com"} {
		_, ip, err := r.Resolve(t.Context(), name)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.80", ip.String())
	}

	// One connection each for the A and the AAAA question, from the first lookup only
	assert.Equal(t, int64(2), dials.Load())
}

// TestRemoteDNSResolverRejectsInvalidIDN verifies that a name that cannot be encoded fails before anything is put on the wire
func TestRemoteDNSResolverRejectsInvalidIDN(t *testing.T) {
	stub := newDNSStub(t)

	var dials atomic.Int64
	countingDial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		dials.Add(1)
		return directDial(ctx, network, addr)
	}

	r := NewRemoteDNSResolver(countingDial, stub.addr())

	_, ip, err := r.Resolve(t.Context(), "café x.com")
	require.Error(t, err)
	assert.Nil(t, ip)
	assert.Zero(t, dials.Load())
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
