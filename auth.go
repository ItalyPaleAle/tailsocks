package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// OAuth2Credentials represents the OAuth2 client credentials
type OAuth2Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (c *OAuth2Credentials) GetAuthToken(ctx context.Context) (string, error) {
	// TODO: Implement this
	// 1. Obtain an access token using OAuth2
	// 2. Invoke the Tailscale APIs to get the auth key
	// Docs: https://tailscale.com/kb/1215/oauth-clients#generating-long-lived-auth-keys
	return "", nil
}

// getCredentialsPath returns the path for OAuth2 credentials file
func getCredentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".config", "tailsocks", "oauth2.json"), nil
}

// loadOAuth2Credentials loads OAuth2 credentials from a file
func loadOAuth2Credentials(path string) (*OAuth2Credentials, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	var creds OAuth2Credentials
	err = json.Unmarshal(data, &creds)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %w", err)
	}

	if creds.ClientID == "" {
		return nil, errors.New("client_id is required in credentials file")
	}
	if creds.ClientSecret == "" {
		return nil, errors.New("client_secret is required in credentials file")
	}

	return &creds, nil
}

// saveOAuth2Credentials saves OAuth2 credentials to a file
func saveOAuth2Credentials(path string, creds *OAuth2Credentials) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create credentials directory '%s': %w", dir, err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials as JSON: %w", err)
	}

	err = os.WriteFile(path, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write credentials file '%s': %w", path, err)
	}

	return nil
}

func getAuthKeyFromEnv() string {
	authKey := strings.TrimSpace(os.Getenv("TS_AUTHKEY"))
	if authKey != "" {
		slog.Info("Using auth key from environment TS_AUTHKEY")
		return authKey
	}

	authKey = strings.TrimSpace(os.Getenv("TS_AUTH_KEY"))
	if authKey != "" {
		slog.Info("Using auth key from environment TS_AUTH_KEY")
		return authKey
	}

	return ""
}

// determineEphemeralFlag calculates the ephemeral flag value based on CLI flags and default
func determineEphemeralFlag(opts *Options, defaultValue bool) bool {
	if opts.Ephemeral != nil {
		return *opts.Ephemeral
	}
	return defaultValue
}
