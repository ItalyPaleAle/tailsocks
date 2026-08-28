package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNormalizeDNSName verifies that every form a hostname can arrive in collapses to the single form used as a cache key and on the wire
func TestNormalizeDNSName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "already normalized", in: "example.com", want: "example.com"},
		{name: "uppercase", in: "EXAMPLE.COM", want: "example.com"},
		{name: "surrounding whitespace", in: "  Example.COM  ", want: "example.com"},
		{name: "trailing dot is kept", in: "Example.COM.", want: "example.com."},
		{name: "empty", in: "", want: ""},

		// STD3 rules would reject these, which is why an ASCII name never reaches the IDNA profile
		{name: "underscores", in: "_ldap._tcp.corp.local", want: "_ldap._tcp.corp.local"},

		// A Unicode name is converted rather than sent as raw UTF-8, which would resolve to nothing
		{name: "unicode label", in: "café.com", want: "xn--caf-dma.com"},
		{name: "unicode label uppercase", in: "CAFÉ.com", want: "xn--caf-dma.com"},
		{name: "unicode label with whitespace", in: " Café.com ", want: "xn--caf-dma.com"},
		{name: "already punycode", in: "xn--caf-dma.com", want: "xn--caf-dma.com"},
		{name: "non-latin script", in: "日本.jp", want: "xn--wgv71a.jp"}, //nolint:gosmopolitan // Non-Latin script is the point of the test
		{name: "german umlaut", in: "münchen.de", want: "xn--mnchen-3ya.de"},

		// IDNA maps these away, so they cannot be used to smuggle a lookalike name past the cache
		{name: "zero width space", in: "a\u200bb.com", want: "ab.com"},
		{name: "soft hyphen", in: "a\u00adb.com", want: "ab.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDNSName(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestNormalizeDNSNameIsIdempotent verifies that normalizing an already-normalized name changes nothing, so a cached key never drifts
func TestNormalizeDNSNameIsIdempotent(t *testing.T) {
	tests := []string{"example.com", "CAFÉ.com", "日本.jp", "_ldap._tcp.corp.local"} //nolint:gosmopolitan // Non-Latin script is the point of the test

	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			once, err := normalizeDNSName(in)
			require.NoError(t, err)

			twice, err := normalizeDNSName(once)
			require.NoError(t, err)

			assert.Equal(t, once, twice)
		})
	}
}

// TestNormalizeDNSNameRejectsInvalid verifies that a name IDNA cannot encode is reported rather than sent as raw bytes
func TestNormalizeDNSNameRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "space inside a unicode label", in: "café x.com"},
		{name: "replacement character", in: "�.com"},
		{name: "lone combining mark", in: "́.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizeDNSName(tt.in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "internationalized domain name")
		})
	}
}

// TestIsASCII verifies the check that decides whether a name can skip the IDNA profile
func TestIsASCII(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "", want: true},
		{in: "example.com", want: true},
		{in: "_ldap._tcp.corp.local", want: true},
		{in: "xn--caf-dma.com", want: true},
		{in: "café.com", want: false},
		{in: "日本.jp", want: false}, //nolint:gosmopolitan // Non-Latin script is the point of the test
		{in: "a\u200bb.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, isASCII(tt.in))
		})
	}
}
