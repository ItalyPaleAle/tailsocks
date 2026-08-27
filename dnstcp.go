package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/italypaleale/go-kit/ttlcache"
	"golang.org/x/net/dns/dnsmessage"
)

// How long a single DNS query is given
// go-socks5 resolves with a background context that carries no deadline, so without a bound here a resolver that accepts the connection and then goes quiet would hang the request forever
const dnsQueryTimeout = 5 * time.Second

// Largest DNS response accepted off the wire
// Responses arrive over TCP, where the 2-byte length prefix allows up to 64 KB, but nothing legitimate this resolver asks for comes close
const maxDNSResponseSize = 8 << 10

// RemoteDNSResolver resolves names by querying a DNS server on the far side of the tunnel
//
// tailcat has no control plane and therefore no MagicDNS, so this is what keeps resolution off the local machine: the query and its answer travel inside the tunnel, and the DNS server sees a lookup coming from the exit node rather than from here
// That matters for more than privacy: CDNs answer based on where the query came from, and names that only exist on the server's network do not resolve any other way
//
// The transport is DNS over TCP because a tailcat tunnel carries no UDP
type RemoteDNSResolver struct {
	// Dials the DNS server through the tunnel
	// This is the raw tunnel rather than tunnelDialer, since resolving the DNS server's own address would be circular
	dial   func(ctx context.Context, network string, addr string) (net.Conn, error)
	server string
	cache  *ttlcache.Cache[string, net.IP]
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
	// Normalize the name so the cache key and the DNS query agree regardless of casing or stray whitespace
	name = strings.ToLower(strings.TrimSpace(name))

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

	// Prefer A over AAAA: IPv4 destinations ride tailcat's NAT64 mapping, and the exit node may have no IPv6 connectivity of its own
	// When several records come back, pick one at random to spread load across endpoints
	if res.A.err == nil && len(res.A.records) > 0 {
		ip := res.A.records[rand.IntN(len(res.A.records))].AsSlice() // #nosec G404 -- Random number is only used to pick an item from the slice
		r.cache.Set(name, ip, clampCacheTTL(res.A.ttl))
		return ctx, ip, nil
	}
	if res.AAAA.err == nil && len(res.AAAA.records) > 0 {
		ip := res.AAAA.records[rand.IntN(len(res.AAAA.records))].AsSlice() // #nosec G404 -- Random number is only used to pick an item from the slice
		r.cache.Set(name, ip, clampCacheTTL(res.AAAA.ttl))
		return ctx, ip, nil
	}

	// Report the A error if there was one, matching TailscaleResolver, which ignores AAAA failures
	if res.A.err != nil {
		return ctx, nil, res.A.err
	}

	return ctx, nil, fmt.Errorf("no addresses found for '%s'", name)
}

// query sends a single question to the DNS server over a fresh connection through the tunnel and returns the addresses it answered with
func (r *RemoteDNSResolver) query(ctx context.Context, name string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	//nolint:gosec // The query ID does not need to be unpredictable: one question per connection means there is nothing to match it against
	id := uint16(rand.UintN(1 << 16))

	msg, err := buildDNSQuery(id, ensureTrailingDot(name), qt)
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancel()

	conn, err := r.dial(ctx, "tcp", r.server)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to reach the DNS server '%s' through the tunnel: %w", r.server, err)
	}
	defer conn.Close() //nolint:errcheck

	// The dial honors the context, but the exchange that follows would not, so push the same deadline onto the connection
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	err = writeDNSMessage(conn, msg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to send the DNS query for '%s': %w", name, err)
	}

	resp, err := readDNSMessage(conn)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read the DNS response for '%s': %w", name, err)
	}

	err = checkDNSResponseID(resp, id)
	if err != nil {
		return nil, 0, err
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
	//nolint:gosec // The length is bounded by the check right above
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

// checkDNSResponseID rejects a response that does not answer the question that was asked
func checkDNSResponseID(resp []byte, want uint16) error {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return fmt.Errorf("error from DNS message parser Start: %w", err)
	}

	if h.ID != want {
		return fmt.Errorf("DNS response carries ID %d but the query used %d", h.ID, want)
	}

	return nil
}
