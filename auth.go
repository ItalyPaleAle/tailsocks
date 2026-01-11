package main

import (
	"bufio"
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

// getDefaultCredentialsPath returns the default path for OAuth2 credentials file
func getDefaultCredentialsPath() (string, error) {
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

// promptForAuthChoice prompts the user to choose between interactive login or OAuth2
func promptForAuthChoice() (bool, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("No authentication credentials found.")
	fmt.Println()
	fmt.Println("Please choose an authentication method:")
	fmt.Println("  1. Interactive login (one-time URL authentication)")
	fmt.Println("  2. OAuth2 client credentials (reusable, requires setup)")
	fmt.Println()
	fmt.Print("Enter your choice (1 or 2): ")

	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	input = strings.TrimSpace(input)
	switch input {
	case "1":
		return false, nil // Interactive login
	case "2":
		return true, nil // OAuth2
	default:
		return false, errors.New("invalid choice, please enter 1 or 2")
	}
}

// promptForOAuth2Credentials prompts the user to enter OAuth2 credentials
func promptForOAuth2Credentials() (*OAuth2Credentials, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("To create OAuth2 client credentials:")
	fmt.Println("  1. Visit https://login.tailscale.com/admin/settings/oauth")
	fmt.Println("  2. Generate a new OAuth client")
	fmt.Println("  3. Copy the client secret (starts with 'tskey-client-')")
	fmt.Println()

	fmt.Print("Enter OAuth2 client secret: ")
	secret, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read client secret: %w", err)
	}

	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, errors.New("client secret cannot be empty")
	}

	if !strings.HasPrefix(secret, "tskey-client-") {
		return nil, errors.New("invalid client secret format (should start with 'tskey-client-')")
	}

	return &OAuth2Credentials{
		ClientID:     "tailsocks",
		ClientSecret: secret,
	}, nil
}

// determineEphemeralFlag calculates the ephemeral flag value based on CLI flags and default
func determineEphemeralFlag(opts *Options, defaultValue bool) bool {
	if opts.Ephemeral != nil {
		return *opts.Ephemeral
	}
	return defaultValue
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

// setupAuthentication handles the authentication setup process
func setupAuthentication(opts *Options) (authKey string, ephemeral bool, err error) {
	// Priority 1: Check for TS_AUTHKEY environment variable
	authKey = strings.TrimSpace(opts.AuthKey)
	if authKey != "" {
		slog.Info("Using auth key from CLI flag")
	} else {
		authKey = getAuthKeyFromEnv()
		if authKey != "" {
			// Use the ephemeral flag from CLI if set, otherwise default to false (non-ephemeral)
			return authKey, determineEphemeralFlag(opts, false), nil
		}
	}

	// Priority 2: Try loading OAuth2 credentials from file
	credPath := opts.CredentialsFile
	if credPath == "" {
		credPath, err = getDefaultCredentialsPath()
		if err != nil {
			return "", false, err
		}
	}

	creds, err := loadOAuth2Credentials(credPath)
	if err != nil {
		return "", false, fmt.Errorf("failed to load OAuth2 credentials: %w", err)
	}

	if creds != nil {
		slog.Info("Using OAuth2 credentials from file", "path", credPath)

		// OAuth2 credentials: ephemeral by default (unless overridden by CLI flag)
		// The client secret is used directly as the auth key
		// Tailscale's oauthkey package will handle the OAuth2 flow automatically
		return creds.ClientSecret, determineEphemeralFlag(opts, true), nil
	}

	// Priority 3: No credentials found, prompt the user
	useOAuth2, err := promptForAuthChoice()
	if err != nil {
		return "", false, err
	}

	if useOAuth2 {
		// User chose OAuth2
		creds, err = promptForOAuth2Credentials()
		if err != nil {
			return "", false, err
		}

		// Save credentials
		err = saveOAuth2Credentials(credPath, creds)
		if err != nil {
			slog.Warn("Failed to save OAuth2 credentials", "error", err, "path", credPath)
			fmt.Printf("\nWarning: Could not save credentials to %s: %v\n", credPath, err)
			fmt.Println("You will need to enter them again next time")
		} else {
			fmt.Printf("\nOAuth2 credentials saved to: %s\n", credPath)
		}

		// OAuth2 credentials: ephemeral by default
		return creds.ClientSecret, determineEphemeralFlag(opts, true), nil
	}

	// User chose interactive login - return empty auth key
	// tsnet will handle the interactive login automatically
	slog.Info("Using interactive login")
	fmt.Println()
	fmt.Println("Starting interactive login...")
	fmt.Println("A URL will be displayed below for authentication.")
	fmt.Println()

	return "", determineEphemeralFlag(opts, false), nil
}
