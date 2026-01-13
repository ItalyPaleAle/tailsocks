package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// Options holds all CLI flag values
type Options struct {
	SocksAddr   string
	StateDir    string
	Hostname    string
	AuthKey     string
	OAuth2      bool
	ExitNode    string
	AllowLAN    bool
	LoginServer string
	Ephemeral   *bool
	LocalDNS    bool
	ShowHelp    bool
	ShowVersion bool
}

// ParseFlags parses command-line flags and returns an Options struct
func ParseFlags() (*Options, error) {
	cfg := &Options{}
	var ephemeral bool

	pflag.StringVarP(&cfg.SocksAddr, "socks-addr", "a", "127.0.0.1:5040", "SOCKS5 listen address")
	pflag.StringVarP(&cfg.StateDir, "state-dir", "s", "./tsnet-state", "Directory to store tsnet state")
	pflag.StringVarP(&cfg.Hostname, "hostname", "n", "tailsocks", "Tailscale node name (hostname)")
	pflag.StringVarP(&cfg.AuthKey, "authkey", "k", "", "Optional Tailscale auth key (or set TS_AUTHKEY env var; if omitted, loads from disk or prompts)")
	pflag.BoolVarP(&cfg.OAuth2, "oauth2", "o", false, "Use OAuth2 credentials for authentication. When set, node is ephemeral by default.")
	pflag.StringVarP(&cfg.ExitNode, "exit-node", "x", "", "Exit node selector: IP or MagicDNS base name (e.g. 'home-exit'). Required.")
	pflag.BoolVarP(&cfg.AllowLAN, "exit-node-allow-lan-access", "l", false, "Allow access to local LAN while using exit node")
	pflag.StringVarP(&cfg.LoginServer, "login-server", "c", "", "Optional control server URL (e.g. https://controlplane.tld for Headscale)")
	pflag.BoolVarP(&ephemeral, "ephemeral", "e", false, "Make this node ephemeral (auto-cleanup on disconnect)")
	pflag.BoolVar(&cfg.LocalDNS, "local-dns", false, "Use local DNS resolver instead of resolving DNS through Tailscale")
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

	return cfg, nil
}

// String implements fmt.Stringer and it's used for debugging
func (o *Options) String() string {
	// Show all options as JSON
	//nolint:errchkjson,musttag
	j, _ := json.Marshal(o)
	return string(j)
}
