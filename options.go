package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// Options holds all CLI flag values
type Options struct {
	SocksAddr       string
	StateDir        string
	Hostname        string
	AuthKey         string
	CredentialsFile string
	ExitNode        string
	AllowLAN        bool
	LoginServer     string
	Ephemeral       bool
	EphemeralSet    bool // Track if --ephemeral was explicitly set
	ShowHelp        bool
	ShowVersion     bool
}

// ParseFlags parses command-line flags and returns an Options struct
func ParseFlags() (*Options, error) {
	cfg := &Options{}

	pflag.StringVarP(&cfg.SocksAddr, "socks-addr", "a", "127.0.0.1:5040", "SOCKS5 listen address")
	pflag.StringVarP(&cfg.StateDir, "state-dir", "s", "./tsnet-state", "Directory to store tsnet state")
	pflag.StringVarP(&cfg.Hostname, "hostname", "n", "tailsocks", "Tailscale node name (hostname)")
	pflag.StringVarP(&cfg.AuthKey, "authkey", "k", "", "Optional Tailscale auth key (or set TS_AUTHKEY env var; if omitted, loads from disk or prompts)")
	pflag.StringVar(&cfg.CredentialsFile, "credentials-file", "", "Path to OAuth2 credentials file (default: ~/.config/tailsocks/oauth2.json)")
	pflag.StringVarP(&cfg.ExitNode, "exit-node", "x", "", "Exit node selector: IP or MagicDNS base name (e.g. 'home-exit'). Required.")
	pflag.BoolVarP(&cfg.AllowLAN, "exit-node-allow-lan-access", "l", false, "Allow access to local LAN while using exit node")
	pflag.StringVarP(&cfg.LoginServer, "login-server", "c", "", "Optional control server URL (e.g. https://controlplane.tld for Headscale)")
	pflag.BoolVarP(&cfg.Ephemeral, "ephemeral", "e", false, "Make this node ephemeral (auto-cleanup on disconnect)")
	pflag.BoolVarP(&cfg.ShowVersion, "version", "v", false, "Show version")
	pflag.BoolVarP(&cfg.ShowHelp, "help", "h", false, "Show this help message")

	err := pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Check if --ephemeral flag was explicitly set
	cfg.EphemeralSet = pflag.CommandLine.Changed("ephemeral")

	return cfg, nil
}

// String implements fmt.Stringer and it's used for debugging
func (o *Options) String() string {
	// Show all options as JSON
	j, _ := json.Marshal(o)
	return string(j)
}
