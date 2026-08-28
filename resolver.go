package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/italypaleale/go-kit/ttlcache"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
	"tailscale.com/client/local"
)

const (
	maxCacheTTL = 5 * time.Minute
	// minCacheTTL is the floor applied before handing a TTL to the cache
	minCacheTTL = time.Second
)

// TailscaleResolver resolves DNS names through Tailscale
type TailscaleResolver struct {
	lc             *local.Client
	magicDNSSuffix string
	cache          *ttlcache.Cache[string, net.IP]
}

// NewTailscaleResolver creates a new resolver that performs DNS lookups through Tailscale
func NewTailscaleResolver(lc *local.Client, magicDNSSuffix string) *TailscaleResolver {
	return &TailscaleResolver{
		lc:             lc,
		magicDNSSuffix: magicDNSSuffix,
		cache: ttlcache.NewCache[string, net.IP](&ttlcache.CacheOptions{
			MaxTTL: maxCacheTTL,
		}),
	}
}

// Resolve implements socks5.NameResolver
// It resolves the given hostname to an IP address using Tailscale.
// Results are cached for up to 5 minutes or the record's TTL, whichever is shorter.
func (r *TailscaleResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Normalize the name so the cache key and DNS query agree regardless of casing, stray whitespace, or which form an internationalized name arrived in
	name, err := normalizeDNSName(name)
	if err != nil {
		return ctx, nil, err
	}

	// Check cache first
	cached, ok := r.cache.Get(name)
	if ok {
		return ctx, cached, nil
	}

	// Perform lookups for A and AAAA records in parallel
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
		records, ttl, err := r.resolveDNS(ctx, name, "A")
		res.A = resMsg{
			records: records,
			ttl:     ttl,
			err:     err,
		}
	})
	wg.Go(func() {
		records, ttl, err := r.resolveDNS(ctx, name, "AAAA")
		res.AAAA = resMsg{
			records: records,
			ttl:     ttl,
			err:     err,
		}
	})
	wg.Wait()

	// Check if we have an A record first, then AAAA
	// When multiple records are returned, pick one at random to spread load across endpoints
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

	// If we're here, we didn't have a result
	// First, check if we had an error for A (we ignore errors for AAA)
	if res.A.err != nil {
		return ctx, nil, res.A.err
	}

	// Return a generic "no addresses found"
	return ctx, nil, fmt.Errorf("no addresses found for '%s'", name)
}

// resolveDNS performs DNS resolution using a behavior like Tailscale.
// It supports A and AAAA records as qt.
//
// - If name contains a dot (.) it's treated as "already qualified": no expansion
// - If name is short (no dot), first try "name." (root-relative)
// - If that returns NXDOMAIN, retry "name.<MagicDNSSuffix>.
// - Uses tailscaled LocalAPI (QueryDNS), so it supports MagicDNS/split DNS
func (r *TailscaleResolver) resolveDNS(ctx context.Context, name string, qt string) ([]netip.Addr, time.Duration, error) {
	isShort := !strings.Contains(name, ".")
	baseQname := ensureTrailingDot(name)

	res, _, err := r.lc.QueryDNS(ctx, baseQname, qt)
	if err != nil {
		return nil, 0, fmt.Errorf("QueryDNS(%q, %s): %w", baseQname, qt, err)
	}

	// If NXDOMAIN and it's a short name, try expanded query
	if isShort && r.isNXDOMAIN(res) && r.magicDNSSuffix != "" {
		expanded := r.expandWithSuffix(name, r.magicDNSSuffix)

		res2, _, err := r.lc.QueryDNS(ctx, expanded, qt)
		if err != nil {
			return nil, 0, fmt.Errorf("QueryDNS(%q, %s): %w", expanded, qt, err)
		}
		addrs, ttl, err := parseAandAAAA(res2)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s response (expanded): %w", qt, err)
		}
		return addrs, ttl, nil
	}

	addrs, ttl, err := parseAandAAAA(res)
	if err != nil {
		return nil, 0, fmt.Errorf("parse %s response: %w", qt, err)
	}
	return addrs, ttl, nil
}

// getCacheTTL bounds a DNS-derived TTL to the range [minCacheTTL, maxCacheTTL] before it is handed to ttlcache.Set, which panics on TTLs below 1ms
// Upstream DNS can legitimately return TTL=0 (e.g. CDN load-balancer records)
func getCacheTTL(ttl time.Duration) time.Duration {
	if ttl < minCacheTTL {
		return minCacheTTL
	}
	if ttl > maxCacheTTL {
		return maxCacheTTL
	}
	return ttl
}

// normalizeDNSName puts a hostname into the single form used both as a cache key and on the wire: trimmed, lowercased, and converted to punycode when it is internationalized
// Clients normally send an already-encoded name, but nothing guarantees it: the SOCKS5 domain field carries whatever bytes the client chose, so it may need to be normalized
func normalizeDNSName(name string) (string, error) {
	name = strings.TrimSpace(name)

	if isASCII(name) {
		return strings.ToLower(name), nil
	}

	encoded, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized domain name '%s': %w", name, err)
	}

	return encoded, nil
}

// isASCII reports whether s contains only ASCII bytes
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}

// ensureTrailingDot turns a name into a fully qualified one, which is what the DNS wire format expects
func ensureTrailingDot(s string) string {
	if s == "" {
		return "."
	}
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func (r *TailscaleResolver) expandWithSuffix(shortName, suffix string) string {
	shortName = strings.TrimSuffix(strings.TrimSpace(shortName), ".")
	suffix = strings.TrimSpace(suffix)
	suffix = strings.TrimSuffix(suffix, ".")
	if suffix == "" {
		return ensureTrailingDot(shortName)
	}
	return ensureTrailingDot(shortName + "." + suffix)
}

func (r *TailscaleResolver) isNXDOMAIN(resp []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return false
	}
	return h.RCode == dnsmessage.RCodeNameError
}

// parseAandAAAA extracts the A and AAAA answers from a DNS response, along with the smallest TTL among all records
// It is shared by both resolvers: TailscaleResolver reads responses from the Tailscale LocalAPI, RemoteDNSResolver reads them off a TCP connection through the tunnel
func parseAandAAAA(resp []byte) (addrs []netip.Addr, ttl time.Duration, err error) {
	var p dnsmessage.Parser
	_, err = p.Start(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("error from DNS message parser Start: %w", err)
	}

	err = p.SkipAllQuestions()
	if err != nil {
		return nil, 0, fmt.Errorf("error from DNS message parser SkipAllQuestions: %w", err)
	}

	out := make([]netip.Addr, 0, 1)
	var minTTL uint32
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		} else if err != nil {
			return nil, 0, fmt.Errorf("error from DNS message parser AnswerHeader: %w", err)
		}

		// Track the minimum TTL from all records
		if minTTL == 0 || ah.TTL < minTTL {
			minTTL = ah.TTL
		}

		//nolint:exhaustive
		switch ah.Type {
		case dnsmessage.TypeA:
			rec, err := p.AResource()
			if err != nil {
				return nil, 0, fmt.Errorf("error from DNS message parser AResource: %w", err)
			}
			out = append(out, netip.AddrFrom4(rec.A))
		case dnsmessage.TypeAAAA:
			rec, err := p.AAAAResource()
			if err != nil {
				return nil, 0, fmt.Errorf("error from DNS message parser AAAAResource: %w", err)
			}
			out = append(out, netip.AddrFrom16(rec.AAAA))
		default:
			err = p.SkipAnswer()
			if err != nil {
				return nil, 0, fmt.Errorf("error from DNS message parser SkipAnswer: %w", err)
			}
		}
	}

	return out, time.Duration(minTTL) * time.Second, nil
}
