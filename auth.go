package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// OAuth2Credentials represents the OAuth2 client credentials
type OAuth2Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// loadOAuth2Credentials loads OAuth2 credentials from a file
func loadOAuth2Credentials(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read OAuth2 credentials file: %w", err)
	}

	var creds OAuth2Credentials
	err = json.Unmarshal(data, &creds)
	if err != nil {
		return "", fmt.Errorf("failed to parse OAuth2 credentials file: %w", err)
	}

	if creds.ClientSecret == "" {
		return "", errors.New("client_secret is required in OAuth2 credentials file")
	}

	return creds.ClientSecret, nil
}
