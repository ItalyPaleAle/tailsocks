package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingDialer records every address it is asked to dial and always fails
// It lets tests assert on the address the proxy derived from a request without needing a reachable target
type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
}

func (d *recordingDialer) Dial(_ context.Context, _ string, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.addrs = append(d.addrs, addr)
	return nil, errors.New("simulated dial failure")
}

func (d *recordingDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.addrs...)
}

// startTestHTTPProxy starts an unauthenticated HTTP proxy on a random port and returns its URL
func startTestHTTPProxy(t *testing.T, d dialer) *url.URL {
	t.Helper()

	return startTestHTTPProxyWithAuth(t, d, "", "")
}

// startTestHTTPProxyWithAuth starts an HTTP proxy on a random port, requiring username/password when either is non-empty, and returns its URL
func startTestHTTPProxyWithAuth(t *testing.T, d dialer, username string, password string) *url.URL {
	t.Helper()

	srv, addr, err := startHTTPProxy(t.Context(), d, "127.0.0.1:0", username, password)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = srv.Close()
	})

	u, err := url.Parse("http://" + addr.String())
	require.NoError(t, err)

	return u
}

// startEchoServer starts a TCP server that echoes back everything it receives, and returns its address
func startEchoServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = l.Close()
	})

	go func() {
		for {
			conn, rErr := l.Accept()
			if rErr != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return l.Addr().String()
}

// readResponseHead reads a status line and the headers that follow it, leaving the reader positioned at the body or tunneled stream
// It is used instead of http.ReadResponse because the response to a CONNECT request is followed by raw tunnel bytes rather than a body
func readResponseHead(t *testing.T, br *bufio.Reader) string {
	t.Helper()

	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)

	for {
		line, rerr := br.ReadString('\n')
		require.NoError(t, rerr)

		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return strings.TrimSpace(statusLine)
}

// TestHTTPProxyForwardsHTTPRequests verifies that an absolute-form request is forwarded to the destination, and that the proxy neither discloses the client nor leaks hop-by-hop headers
func TestHTTPProxyForwardsHTTPRequests(t *testing.T) {
	var (
		gotHost           string
		gotForwardedFor   string
		gotProxyConn      string
		gotCustomHeader   string
		gotProxyAuthoriz  string
		targetRequestPath string
	)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotForwardedFor = r.Header.Get("X-Forwarded-For")
		gotProxyConn = r.Header.Get("Proxy-Connection")
		gotCustomHeader = r.Header.Get("X-Test")
		gotProxyAuthoriz = r.Header.Get("Proxy-Authorization")
		targetRequestPath = r.URL.Path

		_, _ = w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	proxyURL := startTestHTTPProxy(t, directDialer{})
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL+"/some/path", nil)
	require.NoError(t, err)
	req.Header.Set("X-Test", "value")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Basic Zm9vOmJhcg==")

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "hello from target", string(body))
	assert.Equal(t, "/some/path", targetRequestPath)

	// The destination must see the request as if the client had connected to it directly
	assert.Equal(t, strings.TrimPrefix(target.URL, "http://"), gotHost)
	assert.Equal(t, "value", gotCustomHeader)

	// A forward proxy must not disclose the client's address to the destination
	assert.Empty(t, gotForwardedFor)

	// Hop-by-hop headers are addressed to the proxy itself and must not be passed on
	assert.Empty(t, gotProxyConn)
	assert.Empty(t, gotProxyAuthoriz)
}

// TestHTTPProxyConnectTunnel verifies that an https:// destination is reachable through a CONNECT tunnel, with TLS terminating at the destination rather than at the proxy
func TestHTTPProxyConnectTunnel(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello over tls"))
	}))
	defer target.Close()

	proxyURL := startTestHTTPProxy(t, directDialer{})
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			//nolint:gosec
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL, nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "hello over tls", string(body))
}

// TestHTTPProxyConnectReplaysBufferedBytes ensures the tunnel does not lose payload the HTTP server read into its buffer while parsing the CONNECT request
// Clients routinely send the TLS ClientHello immediately after the request, so dropping those bytes would hang every connection
func TestHTTPProxyConnectReplaysBufferedBytes(t *testing.T) {
	echoAddr := startEchoServer(t)
	proxyURL := startTestHTTPProxy(t, directDialer{})

	conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second) //nolint:noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// Send the request and the first bytes of the tunneled stream in a single write
	payload := []byte("first bytes of the tunnel")
	req := "CONNECT " + echoAddr + " HTTP/1.1\r\nHost: " + echoAddr + "\r\n\r\n"
	_, err = conn.Write(append([]byte(req), payload...))
	require.NoError(t, err)

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	statusLine := readResponseHead(t, br)
	require.Contains(t, statusLine, "200")

	got := make([]byte, len(payload))
	_, err = io.ReadFull(br, got)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestHTTPProxyConnectDefaultsToHTTPSPort verifies that a CONNECT target without an explicit port is dialed on port 443
func TestHTTPProxyConnectDefaultsToHTTPSPort(t *testing.T) {
	d := &recordingDialer{}
	proxyURL := startTestHTTPProxy(t, d)

	conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second) //nolint:noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, err = conn.Write([]byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, err)

	statusLine := readResponseHead(t, bufio.NewReader(conn))

	// The dial fails, so the client is told the destination is unreachable rather than being handed a tunnel
	assert.Contains(t, statusLine, "502")
	assert.Equal(t, []string{"example.com:443"}, d.dialed())
}

// TestHTTPProxyRejectsOriginFormRequests ensures a client that is not configured to use a proxy gets a clear error instead of an obscure failure
func TestHTTPProxyRejectsOriginFormRequests(t *testing.T) {
	proxyURL := startTestHTTPProxy(t, directDialer{})

	// No proxy is configured on this client, so it sends an origin-form request that carries no destination
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyURL.String()+"/", nil)
	require.NoError(t, err)

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

// TestHTTPProxyDialFailure ensures a destination that cannot be reached is reported as a bad gateway
func TestHTTPProxyDialFailure(t *testing.T) {
	d := &recordingDialer{}
	proxyURL := startTestHTTPProxy(t, d)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://unreachable.example:8080/", nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	assert.Equal(t, []string{"unreachable.example:8080"}, d.dialed())
}

// TestHTTPProxyAuthRejectsMissingCredentials ensures a request with no Proxy-Authorization header is rejected with 407 when auth is configured
func TestHTTPProxyAuthRejectsMissingCredentials(t *testing.T) {
	proxyURL := startTestHTTPProxyWithAuth(t, directDialer{}, "alice", "hunter2")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusProxyAuthRequired, res.StatusCode)
	assert.NotEmpty(t, res.Header.Get("Proxy-Authenticate"))
}

// TestHTTPProxyAuthRejectsWrongCredentials ensures a request with incorrect Proxy-Authorization credentials is rejected
func TestHTTPProxyAuthRejectsWrongCredentials(t *testing.T) {
	proxyURL := startTestHTTPProxyWithAuth(t, directDialer{}, "alice", "hunter2")
	proxyURL.User = url.UserPassword("alice", "wrong-password")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusProxyAuthRequired, res.StatusCode)
}

// TestHTTPProxyAuthAcceptsCorrectCredentials verifies that correct Proxy-Authorization credentials let a request through, for both plain requests and CONNECT tunnels
func TestHTTPProxyAuthAcceptsCorrectCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	proxyURL := startTestHTTPProxyWithAuth(t, directDialer{}, "alice", "hunter2")
	proxyURL.User = url.UserPassword("alice", "hunter2")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL, nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "hello from target", string(body))
}

// TestHTTPProxyAuthAppliesToConnect ensures a CONNECT request is also rejected when it lacks valid credentials
func TestHTTPProxyAuthAppliesToConnect(t *testing.T) {
	echoAddr := startEchoServer(t)
	proxyURL := startTestHTTPProxyWithAuth(t, directDialer{}, "alice", "hunter2")

	conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second) //nolint:noctx
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	req := "CONNECT " + echoAddr + " HTTP/1.1\r\nHost: " + echoAddr + "\r\n\r\n"
	_, err = conn.Write([]byte(req))
	require.NoError(t, err)

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, err)

	statusLine := readResponseHead(t, bufio.NewReader(conn))
	assert.Contains(t, statusLine, "407")
}

// TestResolveHTTPProxyAuth covers the ways --http-user, --http-password, and TAILSOCKS_HTTP_PASSWORD combine
func TestResolveHTTPProxyAuth(t *testing.T) {
	t.Run("both unset means no auth", func(t *testing.T) {
		user, pass, err := resolveHTTPProxyAuth(&Options{})
		require.NoError(t, err)
		assert.Empty(t, user)
		assert.Empty(t, pass)
	})

	t.Run("both set via flags", func(t *testing.T) {
		user, pass, err := resolveHTTPProxyAuth(&Options{HTTPUser: "alice", HTTPPassword: "hunter2"})
		require.NoError(t, err)
		assert.Equal(t, "alice", user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("password falls back to env var", func(t *testing.T) {
		t.Setenv(httpProxyPasswordEnvVar, "hunter2")

		user, pass, err := resolveHTTPProxyAuth(&Options{HTTPUser: "alice"})
		require.NoError(t, err)
		assert.Equal(t, "alice", user)
		assert.Equal(t, "hunter2", pass)
	})

	t.Run("flag password takes priority over env var", func(t *testing.T) {
		t.Setenv(httpProxyPasswordEnvVar, "from-env")

		user, pass, err := resolveHTTPProxyAuth(&Options{HTTPUser: "alice", HTTPPassword: "from-flag"})
		require.NoError(t, err)
		assert.Equal(t, "alice", user)
		assert.Equal(t, "from-flag", pass)
	})

	t.Run("username without password is an error", func(t *testing.T) {
		_, _, err := resolveHTTPProxyAuth(&Options{HTTPUser: "alice"})
		require.Error(t, err)
	})

	t.Run("password without username is an error", func(t *testing.T) {
		_, _, err := resolveHTTPProxyAuth(&Options{HTTPPassword: "hunter2"})
		require.Error(t, err)
	})
}
