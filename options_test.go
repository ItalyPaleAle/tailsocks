package main

import (
	"io"
	"os"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseArgs runs ParseFlags against a throwaway flag set, so each case starts from a clean slate
// ParseFlags reads the process arguments and the global flag set, both of which are restored afterwards
func parseArgs(t *testing.T, args ...string) (*Options, error) {
	t.Helper()

	prevFlags := pflag.CommandLine
	prevArgs := os.Args
	t.Cleanup(func() {
		pflag.CommandLine = prevFlags
		os.Args = prevArgs
	})

	pflag.CommandLine = pflag.NewFlagSet("tailsocks", pflag.ContinueOnError)
	pflag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"tailsocks"}, args...)

	return ParseFlags()
}

// TestParseFlagsTailnetMode verifies the default mode still requires an exit node and reports no tailcat settings
func TestParseFlagsTailnetMode(t *testing.T) {
	opts, err := parseArgs(t, "--exit-node", "home-server")
	require.NoError(t, err)

	assert.False(t, opts.TailcatMode())
	assert.Equal(t, "home-server", opts.ExitNode)
}

// TestParseFlagsRequiresExitNode verifies that the error names the alternative, since --exit-node is no longer the only way to start
func TestParseFlagsRequiresExitNode(t *testing.T) {
	_, err := parseArgs(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--exit-node")
	assert.Contains(t, err.Error(), "--experimental-tailcat")
}

// TestParseFlagsTailcatMode verifies that a token is enough to start, with no exit node and no auth
func TestParseFlagsTailcatMode(t *testing.T) {
	opts, err := parseArgs(t, "--experimental-tailcat", "tcsometoken")
	require.NoError(t, err)

	assert.True(t, opts.TailcatMode())
	assert.Equal(t, "tcsometoken", opts.Tailcat)
	assert.Equal(t, defaultTailcatDNS, opts.TailcatDNS)
}

// TestParseFlagsRejectsTailnetFlagsInTailcatMode verifies that every tailnet-only flag is refused rather than silently ignored
func TestParseFlagsRejectsTailnetFlagsInTailcatMode(t *testing.T) {
	tests := map[string][]string{
		"exit-node":                  {"--exit-node", "home-server"},
		"authkey":                    {"--authkey", "tskey-auth-xxx"},
		"oauth2":                     {"--oauth2"},
		"login-server":               {"--login-server", "https://headscale.example.com"},
		"ephemeral":                  {"--ephemeral"},
		"hostname":                   {"--hostname", "custom"},
		"exit-node-allow-lan-access": {"--exit-node-allow-lan-access"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseArgs(t, append([]string{"--experimental-tailcat", "tcsometoken"}, args...)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--"+name)
			assert.Contains(t, err.Error(), "--experimental-tailcat")
		})
	}
}

// TestParseFlagsRejectsTailcatFlagsInTailnetMode verifies the mirror case, so a typo does not leave a setting quietly unused
func TestParseFlagsRejectsTailcatFlagsInTailnetMode(t *testing.T) {
	tests := map[string][]string{
		"experimental-tailcat-key":         {"--experimental-tailcat-key", "new"},
		"experimental-tailcat-dns":         {"--experimental-tailcat-dns", "9.9.9.9:53"},
		"experimental-tailcat-derpmap-url": {"--experimental-tailcat-derpmap-url", "https://example.com/derpmap.json"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseArgs(t, append([]string{"--exit-node", "home-server"}, args...)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--"+name)
			assert.Contains(t, err.Error(), "requires --experimental-tailcat")
		})
	}
}

// TestParseFlagsTailcatDNSMustBeIP verifies that a hostname is refused, since reaching the resolver would mean resolving it first
func TestParseFlagsTailcatDNSMustBeIP(t *testing.T) {
	_, err := parseArgs(t, "--experimental-tailcat", "tcsometoken", "--experimental-tailcat-dns", "dns.example.com:53")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ip:port")
}

// TestParseFlagsTailcatDNSAcceptsIPs verifies the forms the docs point at, including the exit node's own resolver
func TestParseFlagsTailcatDNSAcceptsIPs(t *testing.T) {
	tests := []string{"9.9.9.9:53", "127.0.0.53:53", "192.168.1.1:53", "[2606:4700:4700::1111]:53"}

	for _, server := range tests {
		t.Run(server, func(t *testing.T) {
			opts, err := parseArgs(t, "--experimental-tailcat", "tcsometoken", "--experimental-tailcat-dns", server)
			require.NoError(t, err)
			assert.Equal(t, server, opts.TailcatDNS)
		})
	}
}

// TestParseFlagsTailcatDNSIgnoredWithLocalDNS verifies that --local-dns turns off the check for a setting that is no longer used
func TestParseFlagsTailcatDNSIgnoredWithLocalDNS(t *testing.T) {
	opts, err := parseArgs(t, "--experimental-tailcat", "tcsometoken", "--local-dns", "--experimental-tailcat-dns", "not-an-address")
	require.NoError(t, err)
	assert.True(t, opts.LocalDNS)
}

// TestParseFlagsStillRejectsAuthkeyWithOAuth2 verifies the pre-existing conflict check was not lost in the reshuffle
func TestParseFlagsStillRejectsAuthkeyWithOAuth2(t *testing.T) {
	_, err := parseArgs(t, "--exit-node", "home-server", "--oauth2", "--authkey", "tskey-auth-xxx")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--authkey cannot be used together with --oauth2")
}

// TestParseFlagsHelpAndVersionSkipValidation verifies that --help and --version print instead of complaining about a missing mode
func TestParseFlagsHelpAndVersionSkipValidation(t *testing.T) {
	tests := []string{"--help", "--version"}

	for _, flag := range tests {
		t.Run(flag, func(t *testing.T) {
			_, err := parseArgs(t, flag)
			require.NoError(t, err)
		})
	}
}

// TestParseFlagsRequiresAProxy verifies that disabling both listeners is still refused
func TestParseFlagsRequiresAProxy(t *testing.T) {
	_, err := parseArgs(t, "--experimental-tailcat", "tcsometoken", "--socks-addr", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one of --socks-addr and --http-addr")
}
