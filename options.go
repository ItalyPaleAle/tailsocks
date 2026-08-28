package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// Default DNS server queried through the tailcat tunnel
// tailcat mode has no MagicDNS to fall back on, so a resolver has to be named somewhere
// Override it with --tailcat-dns, which also accepts the exit node's own resolver (for example 127.0.0.53:53) or one on its LAN
const defaultTailcatDNS = "1.1.1.1:53"

// Flags that only mean something when joining a tailnet
var tailnetOnlyFlags = []string{"exit-node", "authkey", "oauth2", "login-server", "ephemeral", "hostname", "exit-node-allow-lan-access"}

// Flags that only mean something when connecting through a tailcat server
// Only the flag that selects the mode carries the "experimental-" prefix; these are meaningless without it, so repeating the warning on each one would only make them harder to read
var tailcatOnlyFlags = []string{"tailcat-key", "tailcat-dns", "tailcat-derpmap-url"}

// Options holds all CLI flag values
type Options struct {
	SocksAddr   string
	HTTPAddr    string
	StateDir    string
	Hostname    string
	AuthKey     string
	OAuth2      bool
	ExitNode    string
	AllowLAN    bool
	TCPForwards []string
	LoginServer string
	Ephemeral   *bool
	LocalDNS    bool
	ShowHelp    bool
	ShowVersion bool

	Tailcat           string
	TailcatKey        string
	TailcatDNS        string
	TailcatDERPMapURL string
}

// TailcatMode reports whether the process connects through a tailcat server rather than joining a tailnet
func (o *Options) TailcatMode() bool {
	return o.Tailcat != ""
}

// ParseFlags parses command-line flags and returns an Options struct
func ParseFlags() (*Options, error) {
	cfg := &Options{}
	var ephemeral bool

	pflag.StringVarP(&cfg.SocksAddr, "socks-addr", "a", "127.0.0.1:5040", "SOCKS5 listen address. Set to an empty value to disable the SOCKS5 proxy.")
	pflag.StringVarP(&cfg.HTTPAddr, "http-addr", "p", "", "HTTP proxy listen address (e.g. '127.0.0.1:5041'). Disabled when empty.")
	pflag.StringVarP(&cfg.StateDir, "state-dir", "s", "./tsnet-state", "Directory to store tsnet state, or the tailcat client identity in tailcat mode")
	pflag.StringVarP(&cfg.Hostname, "hostname", "n", "tailsocks", "Tailscale node name (hostname)")
	pflag.StringVarP(&cfg.AuthKey, "authkey", "k", "", "Optional Tailscale auth key (or set TS_AUTHKEY env var; if omitted, loads from disk or prompts)")
	pflag.BoolVarP(&cfg.OAuth2, "oauth2", "o", false, "Use OAuth2 credentials for authentication. When set, node is ephemeral by default.")
	pflag.StringVarP(&cfg.ExitNode, "exit-node", "x", "", "Exit node selector: IP or MagicDNS base name (e.g. 'home-exit'). Required unless --experimental-tailcat is set.")
	pflag.BoolVarP(&cfg.AllowLAN, "exit-node-allow-lan-access", "l", false, "Allow access to local LAN while using exit node")
	pflag.StringSliceVarP(&cfg.TCPForwards, "tcp", "t", nil, "Forward a local TCP port to a remote host through the exit node, in the form 'LISTEN=TARGET' (e.g. '127.0.0.1:3900=test.com:3900'). Can be repeated to forward multiple ports.")
	pflag.StringVarP(&cfg.LoginServer, "login-server", "c", "", "Optional control server URL (e.g. https://controlplane.tld for Headscale)")
	pflag.BoolVarP(&ephemeral, "ephemeral", "e", false, "Make this node ephemeral (auto-cleanup on disconnect)")
	pflag.BoolVar(&cfg.LocalDNS, "local-dns", false, "Use local DNS resolver instead of resolving DNS through the tunnel")
	pflag.StringVar(&cfg.Tailcat, "experimental-tailcat", "", "Experimental. Connect through a tailcat server instead of joining a tailnet. Accepts a token, a DNS name whose \"tailcat=\" TXT record holds one, '@path/to/file', or '-' to read the "+tailcatTokenEnvVar+" environment variable.")
	pflag.StringVar(&cfg.TailcatKey, "tailcat-key", "", "Path to the tailcat client identity, which the server allowlists with --allow. Defaults to '"+tailcatKeyFileName+"' inside --state-dir, created on first run. Use 'new' for a throwaway key.")
	pflag.StringVar(&cfg.TailcatDNS, "tailcat-dns", defaultTailcatDNS, "DNS server to query through the tailcat tunnel, as 'ip:port', so names resolve on the exit node's side. Ignored when --local-dns is set.")
	pflag.StringVar(&cfg.TailcatDERPMapURL, "tailcat-derpmap-url", "", "URL of the DERP map used to reach the tailcat server. Defaults to tailcat's own.")
	pflag.BoolVarP(&cfg.ShowVersion, "version", "v", false, "Show version")
	pflag.BoolVarP(&cfg.ShowHelp, "help", "h", false, "Show this help message")

	err := pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Check if --ephemeral flag was explicitly set
	if pflag.CommandLine.Changed("ephemeral") {
		cfg.Ephemeral = &ephemeral
	}

	// --oauth2 takes its auth from OAuth2 credentials
	// A passed --authkey would be silently ignored
	if cfg.OAuth2 && strings.TrimSpace(cfg.AuthKey) != "" {
		return nil, errors.New("--authkey cannot be used together with --oauth2")
	}

	cfg.Tailcat = strings.TrimSpace(cfg.Tailcat)

	// --help and --version print and exit, so nothing else has to be valid for them
	if cfg.ShowHelp || cfg.ShowVersion {
		return cfg, nil
	}

	// The two backends have disjoint options, so reject the ones that belong to the other mode instead of ignoring them silently
	err = validateModeFlags(cfg)
	if err != nil {
		return nil, err
	}

	// Either proxy can be turned off, but disabling both would leave nothing listening
	cfg.SocksAddr = strings.TrimSpace(cfg.SocksAddr)
	cfg.HTTPAddr = strings.TrimSpace(cfg.HTTPAddr)
	if cfg.SocksAddr == "" && cfg.HTTPAddr == "" {
		return nil, errors.New("at least one of --socks-addr and --http-addr must be set")
	}

	return cfg, nil
}

// validateModeFlags rejects flags that belong to the mode the process is not running in, and checks the requirements of the mode it is
func validateModeFlags(cfg *Options) error {
	if !cfg.TailcatMode() {
		for _, name := range tailcatOnlyFlags {
			if pflag.CommandLine.Changed(name) {
				return fmt.Errorf("--%s requires --experimental-tailcat", name)
			}
		}

		if strings.TrimSpace(cfg.ExitNode) == "" {
			return errors.New("missing --exit-node (IP like 100.x or MagicDNS base name) - alternatively, use --experimental-tailcat to route through a tailcat server without joining a tailnet")
		}

		return nil
	}

	for _, name := range tailnetOnlyFlags {
		if pflag.CommandLine.Changed(name) {
			return fmt.Errorf("--%s cannot be used together with --experimental-tailcat", name)
		}
	}

	// The DNS server is dialed through the tunnel, which only takes IPs
	// Accepting a name here would mean resolving it to reach the resolver
	cfg.TailcatDNS = strings.TrimSpace(cfg.TailcatDNS)
	if !cfg.LocalDNS {
		_, err := netip.ParseAddrPort(cfg.TailcatDNS)
		if err != nil {
			return fmt.Errorf("invalid --tailcat-dns %q: expected an 'ip:port' pair such as %q: %w", cfg.TailcatDNS, defaultTailcatDNS, err)
		}
	}

	return nil
}

// String implements fmt.Stringer and it's used for debugging
func (o *Options) String() string {
	// Show all options as JSON
	//nolint:errchkjson,musttag,gosec
	j, _ := json.Marshal(o)
	return string(j)
}
