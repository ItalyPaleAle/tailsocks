package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/italypaleale/go-kit/ttlcache"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
)

const maxCacheTTL = 5 * time.Minute

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
	// Check cache first
	cached, ok := r.cache.Get(name)
	if ok {
		return ctx, cached, nil
	}

	// Perform lookups for A and AAA records in parallel
	type resMsg struct {
		records []netip.Addr
		ttl     time.Duration
		err     error
	}
	var res struct {
		A   resMsg
		AAA resMsg
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
		records, ttl, err := r.resolveDNS(ctx, name, "AAA")
		res.AAA = resMsg{
			records: records,
			ttl:     ttl,
			err:     err,
		}
	})
	wg.Wait()

	// Check if we have an A record first, then AAAA
	if res.A.err == nil && len(res.A.records) > 0 {
		ip := res.A.records[0].AsSlice()
		r.cache.Set(name, ip, min(res.A.ttl, maxCacheTTL))
		return ctx, ip, nil
	}
	if res.AAA.err == nil && len(res.AAA.records) > 0 {
		ip := res.AAA.records[0].AsSlice()
		r.cache.Set(name, ip, min(res.AAA.ttl, maxCacheTTL))
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
// It supports A and AAA records as qt.
//
// - If name contains a dot (.) it's treated as "already qualified": no expansion
// - If name is short (no dot), first try "name." (root-relative)
// - If that returns NXDOMAIN, retry "name.<MagicDNSSuffix>.
// - Uses tailscaled LocalAPI (QueryDNS), so it supports MagicDNS/split DNS
func (r *TailscaleResolver) resolveDNS(ctx context.Context, name string, qt string) ([]netip.Addr, time.Duration, error) {
	name = strings.TrimSpace(name)
	isShort := !strings.Contains(name, ".") && !strings.HasSuffix(name, ".")
	baseQname := r.ensureTrailingDot(name)

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
		addrs, ttl, err := r.parseAandAAAA(res2)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s response (expanded): %w", qt, err)
		}
		return addrs, ttl, nil
	}

	addrs, ttl, err := r.parseAandAAAA(res)
	if err != nil {
		return nil, 0, fmt.Errorf("parse %s response: %w", qt, err)
	}
	return addrs, ttl, nil
}

func (r *TailscaleResolver) ensureTrailingDot(s string) string {
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
		return r.ensureTrailingDot(shortName)
	}
	return r.ensureTrailingDot(shortName + "." + suffix)
}

func (r *TailscaleResolver) isNXDOMAIN(resp []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return false
	}
	return h.RCode == dnsmessage.RCodeNameError
}

func (r *TailscaleResolver) parseAandAAAA(resp []byte) (addrs []netip.Addr, ttl time.Duration, err error) {
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
