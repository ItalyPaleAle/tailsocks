package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
)

// TailscaleResolver resolves DNS names through Tailscale
type TailscaleResolver struct {
	lc             *local.Client
	magicDNSSuffix string
}

// NewTailscaleResolver creates a new resolver that performs DNS lookups through Tailscale
func NewTailscaleResolver(lc *local.Client, magicDNSSuffix string) *TailscaleResolver {
	return &TailscaleResolver{
		lc:             lc,
		magicDNSSuffix: magicDNSSuffix,
	}
}

// Resolve implements socks5.NameResolver
// It resolves the given hostname to an IP address using Tailscale
func (r *TailscaleResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Perform lookups for A and AAA records in parallel
	type resMsg struct {
		records []netip.Addr
		err     error
	}
	var res struct {
		A   resMsg
		AAA resMsg
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		records, err := r.resolveDNS(ctx, name, "A")
		res.A = resMsg{
			records: records,
			err:     err,
		}
	})
	wg.Go(func() {
		records, err := r.resolveDNS(ctx, name, "AAA")
		res.AAA = resMsg{
			records: records,
			err:     err,
		}
	})
	wg.Wait()

	// Check if we have an A record first, then AAAA
	if res.A.err == nil && len(res.A.records) > 0 {
		return ctx, res.A.records[0].AsSlice(), nil
	}
	if res.AAA.err == nil && len(res.AAA.records) > 0 {
		return ctx, res.AAA.records[0].AsSlice(), nil
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
func (r *TailscaleResolver) resolveDNS(ctx context.Context, name string, qt string) ([]netip.Addr, error) {
	name = strings.TrimSpace(name)
	isShort := !strings.Contains(name, ".") && !strings.HasSuffix(name, ".")
	baseQname := r.ensureTrailingDot(name)

	res, _, err := r.lc.QueryDNS(ctx, baseQname, qt)
	if err != nil {
		return nil, fmt.Errorf("QueryDNS(%q, %s): %w", baseQname, qt, err)
	}

	// If NXDOMAIN and it's a short name, try expanded query
	if isShort && r.isNXDOMAIN(res) && r.magicDNSSuffix != "" {
		expanded := r.expandWithSuffix(name, r.magicDNSSuffix)
		res2, _, err := r.lc.QueryDNS(ctx, expanded, qt)
		if err != nil {
			return nil, fmt.Errorf("QueryDNS(%q, %s): %w", expanded, qt, err)
		}
		addrs, err := r.parseAandAAAA(res2)
		if err != nil {
			return nil, fmt.Errorf("parse %s response (expanded): %w", qt, err)
		}
		return addrs, nil
	}

	addrs, err := r.parseAandAAAA(res)
	if err != nil {
		return nil, fmt.Errorf("parse %s response: %w", qt, err)
	}
	return addrs, nil
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

func (r *TailscaleResolver) parseAandAAAA(resp []byte) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	_, err := p.Start(resp)
	if err != nil {
		return nil, err
	}
	err = p.SkipAllQuestions()
	if err != nil {
		return nil, err
	}

	out := make([]netip.Addr, 0, 1)
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		} else if err != nil {
			return nil, err
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			out = append(out, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			err = p.SkipAnswer()
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
