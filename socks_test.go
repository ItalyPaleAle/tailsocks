package main

import (
	"io"
	"testing"

	"github.com/armon/go-socks5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

// startTestSocksProxy starts a SOCKS5 proxy on a random port, requiring username/password when either is non-empty, and returns its address
func startTestSocksProxy(t *testing.T, d dialer, username string, password string) string {
	t.Helper()

	l, _, err := startSocksProxy(t.Context(), d, socks5.DNSResolver{}, "127.0.0.1:0", username, password)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = l.Close()
	})

	return l.Addr().String()
}

// dialThroughSocks5 connects to addr through a SOCKS5 proxy at proxyAddr, authenticating with auth when it is non-nil
func dialThroughSocks5(t *testing.T, proxyAddr string, auth *proxy.Auth, addr string) (io.ReadWriteCloser, error) {
	t.Helper()

	d, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	require.NoError(t, err)

	return d.Dial("tcp", addr)
}

// TestSocksProxyAuthRejectsMissingCredentials ensures a client that offers no credentials cannot use the proxy when auth is configured
func TestSocksProxyAuthRejectsMissingCredentials(t *testing.T) {
	echoAddr := startEchoServer(t)
	proxyAddr := startTestSocksProxy(t, directDialer{}, "alice", "hunter2")

	_, err := dialThroughSocks5(t, proxyAddr, nil, echoAddr)
	require.Error(t, err)
}

// TestSocksProxyAuthRejectsWrongCredentials ensures a client with incorrect credentials cannot use the proxy
func TestSocksProxyAuthRejectsWrongCredentials(t *testing.T) {
	echoAddr := startEchoServer(t)
	proxyAddr := startTestSocksProxy(t, directDialer{}, "alice", "hunter2")

	_, err := dialThroughSocks5(t, proxyAddr, &proxy.Auth{User: "alice", Password: "wrong-password"}, echoAddr)
	require.Error(t, err)
}

// TestSocksProxyAuthAcceptsCorrectCredentials verifies that correct credentials let a client establish a connection and exchange data through it
func TestSocksProxyAuthAcceptsCorrectCredentials(t *testing.T) {
	echoAddr := startEchoServer(t)
	proxyAddr := startTestSocksProxy(t, directDialer{}, "alice", "hunter2")

	conn, err := dialThroughSocks5(t, proxyAddr, &proxy.Auth{User: "alice", Password: "hunter2"}, echoAddr)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	payload := []byte("hello through socks5")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestSocksProxyNoAuthConfiguredAllowsUnauthenticatedClients ensures the proxy still works without credentials when none are configured, guarding against a regression that would make auth mandatory
func TestSocksProxyNoAuthConfiguredAllowsUnauthenticatedClients(t *testing.T) {
	echoAddr := startEchoServer(t)
	proxyAddr := startTestSocksProxy(t, directDialer{}, "", "")

	conn, err := dialThroughSocks5(t, proxyAddr, nil, echoAddr)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	payload := []byte("hello")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestResolveSocksAuth covers the ways --socks-user, --socks-password, and TAILSOCKS_SOCKS_PASSWORD combine
func TestResolveSocksAuth(t *testing.T) {
	t.Run("both unset means no auth", func(t *testing.T) {
		user, pass, err := resolveSocksAuth(&Options{})
		require.NoError(t, err)
		assert.Empty(t, user)
		assert.Empty(t, pass)
	})

	t.Run("both set via flags", func(t *testing.T) {
		user, pass, err := resolveSocksAuth(&Options{SocksUser: "alice", SocksPassword: "hunter2"})
		require.NoError(t, err)
		assert.Equal(t, "alice", user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("password falls back to env var", func(t *testing.T) {
		t.Setenv(socksPasswordEnvVar, "hunter2")

		user, pass, err := resolveSocksAuth(&Options{SocksUser: "alice"})
		require.NoError(t, err)
		assert.Equal(t, "alice", user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("flag password takes priority over env var", func(t *testing.T) {
		t.Setenv(socksPasswordEnvVar, "from-env")

		user, pass, err := resolveSocksAuth(&Options{SocksUser: "alice", SocksPassword: "from-flag"})
		require.NoError(t, err)
		assert.Equal(t, "alice", user)
		assert.Equal(t, "from-flag", pass)
	})

	t.Run("username without password is an error", func(t *testing.T) {
		_, _, err := resolveSocksAuth(&Options{SocksUser: "alice"})
		require.Error(t, err)
	})

	t.Run("password without username is an error", func(t *testing.T) {
		_, _, err := resolveSocksAuth(&Options{SocksPassword: "hunter2"})
		require.Error(t, err)
	})
}
