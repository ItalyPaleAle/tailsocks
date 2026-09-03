package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/tailcat"
)

// testToken returns a syntactically valid tailcat token, without a server behind it
func testToken(t *testing.T) string {
	t.Helper()

	priv := tailcat.NewPrivateKey()
	priv.Public.RegionID = 1

	return string(priv.Public.Addr())
}

// TestLoadTailcatTokenLiteral verifies that a token passed directly on the command line is accepted
func TestLoadTailcatTokenLiteral(t *testing.T) {
	token := testToken(t)

	blob, err := loadTailcatToken(t.Context(), "  "+token+"  ")
	require.NoError(t, err)
	assert.Equal(t, token, string(blob))
}

// TestLoadTailcatTokenFromFile verifies the "@path" form, which keeps the token out of the process arguments
func TestLoadTailcatTokenFromFile(t *testing.T) {
	token := testToken(t)
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))

	blob, err := loadTailcatToken(t.Context(), "@"+path)
	require.NoError(t, err)
	assert.Equal(t, token, string(blob))
}

// TestLoadTailcatTokenFromEnv verifies the "-" form, which reads the token from the environment
func TestLoadTailcatTokenFromEnv(t *testing.T) {
	token := testToken(t)
	t.Setenv(tailcatTokenEnvVar, token)

	blob, err := loadTailcatToken(t.Context(), "-")
	require.NoError(t, err)
	assert.Equal(t, token, string(blob))
}

// TestLoadTailcatTokenErrors verifies that every way of getting the token wrong is reported instead of failing later at connect time
func TestLoadTailcatTokenErrors(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantErr string
	}{
		{name: "empty env", arg: "-", wantErr: "is empty"},
		{name: "missing file", arg: "@" + filepath.Join(t.TempDir(), "nope"), wantErr: "failed to read"},
		{name: "no file path", arg: "@", wantErr: "no file path"},
		{name: "not a token", arg: "hello", wantErr: "not a tailcat token"},
		{name: "malformed token", arg: "tcnot-valid-base64!!", wantErr: "failed to parse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tailcatTokenEnvVar, "")

			_, err := loadTailcatToken(t.Context(), tt.arg)
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestTailcatKeyIsStable verifies that the identity survives a restart, which is what makes the server's --allow list usable
func TestTailcatKeyIsStable(t *testing.T) {
	stateDir := t.TempDir()

	first, path, err := loadOrCreateTailcatKey(stateDir, "")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(stateDir, tailcatKeyFileName), path)

	second, _, err := loadOrCreateTailcatKey(stateDir, "")
	require.NoError(t, err)

	assert.Equal(t, first.Public().String(), second.Public().String())
}

// TestTailcatKeyFileIsPrivate verifies the key is not written world-readable
func TestTailcatKeyFileIsPrivate(t *testing.T) {
	stateDir := t.TempDir()

	_, path, err := loadOrCreateTailcatKey(stateDir, "")
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(tailcatKeyFileMode), info.Mode().Perm())
}

// TestTailcatKeyUsesTailcatFormat verifies the file can be read by tailcat's own tooling, so an existing tailcat key can be pointed at directly
func TestTailcatKeyUsesTailcatFormat(t *testing.T) {
	stateDir := t.TempDir()

	priv, path, err := loadOrCreateTailcatKey(stateDir, "")
	require.NoError(t, err)

	read, err := os.ReadFile(path) //nolint:gosec
	require.NoError(t, err)

	var stored tailcat.PrivateKey
	require.NoError(t, json.Unmarshal(read, &stored))
	assert.Equal(t, priv.Public().String(), stored.Private.Public().String())
}

// TestTailcatKeyAtExplicitPath verifies that --tailcat-key can point somewhere outside the state directory
func TestTailcatKeyAtExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "client-default.private.json")

	first, gotPath, err := loadOrCreateTailcatKey(t.TempDir(), path)
	require.NoError(t, err)
	assert.Equal(t, path, gotPath)

	second, _, err := loadOrCreateTailcatKey(t.TempDir(), path)
	require.NoError(t, err)
	assert.Equal(t, first.Public().String(), second.Public().String())
}

// TestTailcatKeyEphemeral verifies that "new" never touches disk and never repeats
func TestTailcatKeyEphemeral(t *testing.T) {
	stateDir := t.TempDir()

	first, path, err := loadOrCreateTailcatKey(stateDir, "new")
	require.NoError(t, err)
	assert.Equal(t, "(ephemeral)", path)

	second, _, err := loadOrCreateTailcatKey(stateDir, "new")
	require.NoError(t, err)

	assert.NotEqual(t, first.Public().String(), second.Public().String())

	entries, err := os.ReadDir(stateDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestTailcatKeyRejectsGarbage verifies that an unreadable key file is reported rather than silently replaced
func TestTailcatKeyRejectsGarbage(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, tailcatKeyFileName)
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))

	_, _, err := loadOrCreateTailcatKey(stateDir, "")
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to parse")
}

// TestTailcatTunnelRejectsUDP verifies that a UDP dial is refused with a clear message rather than reaching tailcat's unimplemented UDP path
func TestTailcatTunnelRejectsUDP(t *testing.T) {
	tunnel := &tailcatTunnel{}

	_, err := tunnel.Dial(t.Context(), "udp", "203.0.113.1:53")
	require.Error(t, err)
	assert.ErrorContains(t, err, "TCP only")
}

// TestTailcatTunnelRequiresIP verifies that a name reaching the tunnel is rejected, since resolution happens one layer up in tunnelDialer
func TestTailcatTunnelRequiresIP(t *testing.T) {
	tunnel := &tailcatTunnel{}

	_, err := tunnel.Dial(t.Context(), "tcp", "example.com:443")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid address")
}

// TestTailcatVersionIsReported verifies that a real build reports an actual version, so the log line is never just "unknown" in practice
func TestTailcatVersionIsReported(t *testing.T) {
	version := tailcatVersion()
	t.Logf("built against tailcat %s", version)

	assert.NotEqual(t, tailcatVersionUnknown, version)
	assert.True(t, strings.HasPrefix(version, "v"), "expected a module version, got %q", version)
}
