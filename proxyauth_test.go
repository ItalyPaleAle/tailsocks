package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveProxyAuth covers the ways --auth-password can be supplied: a literal password, "-" for stdin, and "@path" for a file
func TestResolveProxyAuth(t *testing.T) {
	t.Run("unset means no auth", func(t *testing.T) {
		user, pass, err := resolveProxyAuth(&Options{})
		require.NoError(t, err)
		assert.Empty(t, user)
		assert.Empty(t, pass)
	})

	t.Run("literal password", func(t *testing.T) {
		user, pass, err := resolveProxyAuth(&Options{AuthPassword: "hunter2"})
		require.NoError(t, err)
		assert.Equal(t, proxyAuthUsername, user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("read from file with @", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "password.txt")
		require.NoError(t, os.WriteFile(path, []byte("hunter2\n"), 0600))

		user, pass, err := resolveProxyAuth(&Options{AuthPassword: "@" + path})
		require.NoError(t, err)
		assert.Equal(t, proxyAuthUsername, user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("@ with no path is an error", func(t *testing.T) {
		_, _, err := resolveProxyAuth(&Options{AuthPassword: "@"})
		require.Error(t, err)
	})

	t.Run("@ with a nonexistent file is an error", func(t *testing.T) {
		_, _, err := resolveProxyAuth(&Options{AuthPassword: "@" + filepath.Join(t.TempDir(), "missing.txt")})
		require.Error(t, err)
	})

	t.Run("empty file is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.txt")
		require.NoError(t, os.WriteFile(path, []byte("  \n"), 0600))

		_, _, err := resolveProxyAuth(&Options{AuthPassword: "@" + path})
		require.Error(t, err)
	})

	t.Run("read from stdin with -", func(t *testing.T) {
		withStdin(t, "hunter2\n")

		user, pass, err := resolveProxyAuth(&Options{AuthPassword: "-"})
		require.NoError(t, err)
		assert.Equal(t, proxyAuthUsername, user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("empty stdin is an error", func(t *testing.T) {
		withStdin(t, "\n")

		_, _, err := resolveProxyAuth(&Options{AuthPassword: "-"})
		require.Error(t, err)
	})
}

// withStdin replaces os.Stdin for the duration of the test with a pipe fed the given content
func withStdin(t *testing.T, content string) {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	_, err = w.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	original := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = original
		_ = r.Close()
	})
}
