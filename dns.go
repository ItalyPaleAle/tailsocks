package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/italypaleale/go-kit/ttlcache"
	"golang.org/x/net/dns/dnsmessage"
)

// How long a single DNS query is given
// go-socks5 resolves with a background context that carries no deadline, so without a timeout here a resolver that accepts the connection could hang forever
const dnsQueryTimeout = 5 * time.Second

// Largest DNS response accepted off the wire
// Responses arrive over TCP, where the 2-byte length prefix allows up to 64KB
// We limit to 8KB as we don't need anything close to that
const maxDNSResponseSize = 8 << 10

// Largest DNS message exchanged in a single datagram
// Queries carry no EDNS0 option, so a server keeps its answers within the classic 512-byte limit and sets the truncation bit rather than going over
// The buffer is sized to what the tunnel carries in one datagram anyway (tailcat's IPv6 MTU leaves 1232 bytes), so a server that ignores that limit is still read whole rather than cut short here
const maxDNSDatagramSize = 1232

// dnsTransport is how a query travels to the DNS server on the far side of the tunnel
type dnsTransport int32

const (
	// Nothing is known yet about what the server forwards, so the next query has to find out
	dnsTransportUnknown dnsTransport = iota
	dnsTransportUDP
	dnsTransportTCP
)

// String returns the name of the transport, which for a decided one doubles as the network to dial
func (t dnsTransport) String() string {
	switch t {
	case dnsTransportUDP:
		return "udp"
	case dnsTransportTCP:
		return "tcp"
	case dnsTransportUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// RemoteDNSResolver resolves names by querying a DNS server on the far side of the tunnel
//
// tailcat has no control plane and therefore no MagicDNS, so this is what keeps resolution off the local machine: the query and its answer travel inside the tunnel, and the DNS server sees a lookup coming from the exit node rather than from here
// This offers both privacy and making sure that records returned by the DNS resolvers are optimized for the exit node, not the local node
//
// Queries go over UDP where the tunnel carries it and over TCP where it does not, which is decided by asking rather than by configuration: see queryRace
type RemoteDNSResolver struct {
	// Dials the DNS server through the tunnel
	// This is the raw tunnel rather than tunnelDialer, since resolving the DNS server's own address would be circular
	dial   func(ctx context.Context, network string, addr string) (net.Conn, error)
	server string
	cache  *ttlcache.Cache[string, net.IP]

	// The transport the server was last seen to answer on, held as a dnsTransport
	// It starts out unknown, and the first query to get an answer records what worked so the ones after it go straight there
	transport atomic.Int32
}

// NewRemoteDNSResolver creates a resolver that queries server, given as an "ip:port" pair, through dial
func NewRemoteDNSResolver(dial func(ctx context.Context, network string, addr string) (net.Conn, error), server string) *RemoteDNSResolver {
	return &RemoteDNSResolver{
		dial:   dial,
		server: server,
		cache: ttlcache.NewCache[string, net.IP](&ttlcache.CacheOptions{
			MaxTTL: maxCacheTTL,
		}),
	}
}

// Resolve implements socks5.NameResolver
// It resolves the given hostname through the tunnel, caching results for up to 5 minutes or the record's TTL, whichever is shorter
func (r *RemoteDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Normalize the name so the cache key and the DNS query agree regardless of casing, stray whitespace, or which form an internationalized name arrived in
	name, err := normalizeDNSName(name)
	if err != nil {
		return ctx, nil, err
	}

	cached, ok := r.cache.Get(name)
	if ok {
		return ctx, cached, nil
	}

	// Look up A and AAAA in parallel, each on its own connection
	type resMsg struct {
		records []netip.Addr
		ttl     time.Duration
		err     error
	}
	var res struct {
		A    resMsg
		AAAA resMsg
	}

	// Noted before the questions go out, so a failure below is judged against the transport that actually carried them
	used := dnsTransport(r.transport.Load())

	var wg sync.WaitGroup
	wg.Go(func() {
		records, ttl, err := r.query(ctx, name, dnsmessage.TypeA)
		res.A = resMsg{records: records, ttl: ttl, err: err}
	})
	wg.Go(func() {
		records, ttl, err := r.query(ctx, name, dnsmessage.TypeAAAA)
		res.AAAA = resMsg{records: records, ttl: ttl, err: err}
	})
	wg.Wait()

	// Neither question got through, which is what a transport that has stopped working looks like: a server restarted with different forwarding, say
	// Forgetting it sends the next lookup back to trying both, rather than staying pinned to one that has become a black hole
	// It takes both to decide, since a resolver can be unlucky on AAAA alone while the transport carrying it is perfectly fine
	if res.A.err != nil && res.AAAA.err != nil {
		r.transport.CompareAndSwap(int32(used), int32(dnsTransportUnknown))
	}

	// Prefer A over AAAA: IPv4 destinations ride tailcat's NAT64 mapping, and the exit node may have no IPv6 connectivity of its own
	// When several records come back, pick one at random to spread load across endpoints
	if res.A.err == nil && len(res.A.records) > 0 {
		ip := res.A.records[rand.IntN(len(res.A.records))].AsSlice() // #nosec G404 -- Random number is only used to pick an item from the slice
		r.cache.Set(name, ip, getCacheTTL(res.A.ttl))
		return ctx, ip, nil
	}
	if res.AAAA.err == nil && len(res.AAAA.records) > 0 {
		ip := res.AAAA.records[rand.IntN(len(res.AAAA.records))].AsSlice() // #nosec G404 -- Random number is only used to pick an item from the slice
		r.cache.Set(name, ip, getCacheTTL(res.AAAA.ttl))
		return ctx, ip, nil
	}

	// Report the A error if there was one, matching TailscaleResolver, which ignores AAAA failures
	if res.A.err != nil {
		return ctx, nil, res.A.err
	}

	return ctx, nil, fmt.Errorf("no addresses found for '%s'", name)
}

// query sends a single question to the DNS server through the tunnel and returns the addresses it answered with
// It uses the transport already known to work, or discovers one when nothing is known yet
func (r *RemoteDNSResolver) query(ctx context.Context, name string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	known := dnsTransport(r.transport.Load())
	if known == dnsTransportUnknown {
		return r.queryRace(ctx, name, qt)
	}

	return r.queryOver(ctx, known, name, qt)
}

// queryRace asks over UDP and TCP at the same time and takes whichever answers first, remembering it for the queries that follow
//
// Whether the tunnel carries UDP is up to the server: forwarding it is opt-in (tailcat.Server.OnUDPForward), which tailcat's own "serve exit-node" has wired up by default since v0.7.0, but a server on an older tailcat, or a custom one built on the library, may still drop UDP at its packet filter rather than refusing it
// Nothing in the protocol asks a server which it does, and a wrong guess costs a full timeout on every query, so the first one simply tries both and lets the server settle it
func (r *RemoteDNSResolver) queryRace(ctx context.Context, name string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	type raceResult struct {
		idx       int
		transport dnsTransport
		addrs     []netip.Addr
		ttl       time.Duration
		err       error
	}

	transports := []dnsTransport{dnsTransportUDP, dnsTransportTCP}

	// Canceled as soon as one of the two answers, which tears the loser down instead of leaving it to run out its own timeout
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Buffered, so the loser can always report and exit even though nobody reads it
	results := make(chan raceResult, len(transports))
	for idx, transport := range transports {
		go func() {
			addrs, ttl, err := r.queryOver(raceCtx, transport, name, qt)
			results <- raceResult{idx: idx, transport: transport, addrs: addrs, ttl: ttl, err: err}
		}()
	}

	// Held by transport rather than by arrival, so a report of a total failure reads the same way every time
	errs := make([]error, len(transports))
	for range transports {
		res := <-results
		if res.err != nil {
			errs[res.idx] = res.err
			continue
		}

		// Worth a line: which transport survives the tunnel is the first thing to know when DNS misbehaves, and it is only ever logged when the answer changes
		if r.transport.Swap(int32(res.transport)) != int32(res.transport) {
			slog.Info("Selected the DNS transport through the tunnel", "transport", res.transport.String(), "server", r.server)
		}

		return res.addrs, res.ttl, nil
	}

	// Neither worked, so report both rather than whichever happened to finish last
	return nil, 0, errors.Join(errs...)
}

// queryOver sends a single question over one transport, on a fresh connection through the tunnel
func (r *RemoteDNSResolver) queryOver(ctx context.Context, transport dnsTransport, name string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	// #nosec G404,G115 -- Not security-related use, and number is limited to uint16
	id := uint16(rand.UintN(1 << 16))

	msg, err := buildDNSQuery(id, ensureTrailingDot(name), qt)
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancel()

	conn, err := r.dial(ctx, transport.String(), r.server)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to reach the DNS server '%s' over %s through the tunnel: %w", r.server, transport, err)
	}
	defer conn.Close() //nolint:errcheck

	// The dial honors the context, but the exchange that follows would not, so push the same deadline onto the connection
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	// The two transports frame messages differently: TCP prefixes each one with its length, while UDP puts exactly one in each datagram
	if transport == dnsTransportUDP {
		err = writeDNSDatagram(conn, msg)
	} else {
		err = writeDNSMessage(conn, msg)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to send the DNS query for '%s' over %s: %w", name, transport, err)
	}

	var resp []byte
	if transport == dnsTransportUDP {
		resp, err = readDNSDatagram(conn)
	} else {
		resp, err = readDNSMessage(conn)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read the DNS response for '%s' over %s: %w", name, transport, err)
	}

	truncated, err := checkDNSResponse(resp, id)
	if err != nil {
		return nil, 0, err
	}

	// A truncated answer carries only part of the record set, and the same question over TCP has no datagram to overflow
	// That the server had to truncate says nothing about whether UDP works, so the remembered transport is left alone
	if truncated && transport == dnsTransportUDP {
		return r.queryOver(ctx, dnsTransportTCP, name, qt)
	}

	addrs, ttl, err := parseAandAAAA(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse the DNS response for '%s': %w", name, err)
	}

	return addrs, ttl, nil
}

// buildDNSQuery encodes a single recursive question
func buildDNSQuery(id uint16, qname string, qt dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(qname)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS name '%s': %w", qname, err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	b.EnableCompression()

	err = b.StartQuestions()
	if err != nil {
		return nil, fmt.Errorf("error from DNS message builder StartQuestions: %w", err)
	}

	err = b.Question(dnsmessage.Question{
		Name:  name,
		Type:  qt,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, fmt.Errorf("error from DNS message builder Question: %w", err)
	}

	msg, err := b.Finish()
	if err != nil {
		return nil, fmt.Errorf("error from DNS message builder Finish: %w", err)
	}

	return msg, nil
}

// writeDNSMessage sends a message using the DNS-over-TCP framing, which prefixes every message with its length
func writeDNSMessage(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF {
		return fmt.Errorf("DNS query is too large to send: %d bytes", len(msg))
	}

	framed := make([]byte, 2+len(msg))
	// #nosec G115 -- the length is bounded by the check right above
	binary.BigEndian.PutUint16(framed[:2], uint16(len(msg)))
	copy(framed[2:], msg)

	_, err := w.Write(framed)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	return nil
}

// readDNSMessage reads one length-prefixed message
func readDNSMessage(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	_, err := io.ReadFull(r, lenBuf[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read the length prefix: %w", err)
	}

	size := binary.BigEndian.Uint16(lenBuf[:])
	if size == 0 {
		return nil, errors.New("DNS response is empty")
	}
	if int(size) > maxDNSResponseSize {
		return nil, fmt.Errorf("DNS response is too large: %d bytes", size)
	}

	msg := make([]byte, size)
	_, err = io.ReadFull(r, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body: %w", err)
	}

	return msg, nil
}

// writeDNSDatagram sends a message as a single datagram, which is how DNS over UDP frames it: no length prefix, one message per packet
func writeDNSDatagram(w io.Writer, msg []byte) error {
	if len(msg) > maxDNSDatagramSize {
		return fmt.Errorf("DNS query is too large to send in one datagram: %d bytes", len(msg))
	}

	_, err := w.Write(msg)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	return nil
}

// readDNSDatagram reads one datagram, which carries exactly one message
// Anything the server sends past the buffer is dropped by the read, the same way it would be by a socket, and a response that large has its truncation bit set anyway
func readDNSDatagram(r io.Reader) ([]byte, error) {
	buf := make([]byte, maxDNSDatagramSize)

	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response: %w", err)
	}
	if n == 0 {
		return nil, errors.New("DNS response is empty")
	}

	return buf[:n], nil
}

// checkDNSResponse rejects a response that does not answer the question that was asked, and reports whether the server had to truncate it
func checkDNSResponse(resp []byte, want uint16) (truncated bool, err error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return false, fmt.Errorf("error from DNS message parser Start: %w", err)
	}

	if h.ID != want {
		return false, fmt.Errorf("DNS response carries ID %d but the query used %d", h.ID, want)
	}

	return h.Truncated, nil
}
