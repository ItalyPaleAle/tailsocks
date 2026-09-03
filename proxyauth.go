package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// proxyAuthUsername is the only username accepted by the SOCKS5 and HTTP proxies when --auth-password is set
// There is exactly one credential pair, so a configurable username would not add any security a client couldn't already get from the password alone
const proxyAuthUsername = "tailsocks"

// resolveProxyAuth turns --auth-password into the username/password pair shared by the SOCKS5 and HTTP proxies
// It accepts the password itself, "-" to read it from stdin, or "@path/to/file" to read it from a file, so the secret need not appear in shell history or process listings
// It returns empty strings when --auth-password is not set, meaning both proxies remain unauthenticated
func resolveProxyAuth(opts *Options) (username string, password string, err error) {
	raw := strings.TrimSpace(opts.AuthPassword)
	if raw == "" {
		return "", "", nil
	}

	switch {
	case raw == "-":
		password, err = readPasswordFromStdin()
	case strings.HasPrefix(raw, "@"):
		password, err = readPasswordFromFile(strings.TrimPrefix(raw, "@"))
	default:
		password = raw
	}
	if err != nil {
		return "", "", err
	}

	if password == "" {
		return "", "", errors.New("--auth-password resolved to an empty password")
	}

	return proxyAuthUsername, password, nil
}

// readPasswordFromStdin reads a single line from stdin, for --auth-password -
func readPasswordFromStdin() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("failed to read --auth-password from stdin: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// readPasswordFromFile reads the password from a file, for --auth-password @path/to/file
func readPasswordFromFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("--auth-password is '@' with no file path after it")
	}

	data, err := os.ReadFile(path) // #nosec G304 -- the path is meant to be user-provided
	if err != nil {
		return "", fmt.Errorf("failed to read --auth-password from '%s': %w", path, err)
	}

	return strings.TrimSpace(string(data)), nil
}
