package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/tailcat"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// How long to wait for the client and server to find each other through the test relay
const e2eHandshakeTimeout = 30 * time.Second

// runTestDERP starts an in-process DERP relay and STUN server, and returns the region pointing at them
// Standing them up locally is what lets the whole tailcat path be exercised with no network access and no Tailscale account
func runTestDERP(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()

	logf := testLogf(t, "derp")

	d := derpserver.New(key.NewNode(), logf)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	derpPort := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // A TCP listener always carries a *net.TCPAddr

	srv := httptest.NewUnstartedServer(derpserver.Handler(d))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Config.ErrorLog = logger.StdLogger(logf)
	srv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	srv.StartTLS()

	// Without a STUN server the endpoint check has to time out before falling back to the relay, which costs seconds on every connection
	stunAddr, stunCleanup := stuntest.Serve(t)

	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		_ = d.Close()
		stunCleanup()
	})

	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{
			{
				Name:             "t1",
				RegionID:         1,
				HostName:         "127.0.0.1",
				IPv4:             "127.0.0.1",
				IPv6:             "none",
				STUNPort:         stunAddr.Port,
				STUNTestIP:       "127.0.0.1",
				DERPPort:         derpPort,
				InsecureForTests: true,
			},
		},
	}
}

// runTailcatExitNode starts a tailcat server in the same shape as "tailcat --serve=exit-node" and returns its token
func runTailcatExitNode(t *testing.T, reg *tailcfg.DERPRegion) tailcat.Addr {
	t.Helper()

	srv := &tailcat.Server{
		Key:    key.NewNode(),
		Region: reg,
		Logf:   testLogf(t, "exit-node"),
	}

	// This mirrors what the stock tailcat CLI installs for --serve=exit-node
	srv.OnTCPForward = func(dst netip.AddrPort) func(net.Conn) {
		return func(c net.Conn) {
			var d net.Dialer
			local, err := d.DialContext(context.Background(), "tcp", dst.String())
			if err != nil {
				_ = c.Close()
				return
			}
			tailcat.ProxyConns(c, local)
		}
	}

	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Close() })

	return srv.TailcatAddr()
}

// TestTailcatEndToEnd runs the whole tailcat path: a real DERP relay, a real tailcat exit node, the real setupTailcat, and then each of the three things TailSocks exposes
//
// Every request targets a name that only the DNS server behind the tunnel knows about, which is what proves resolution happened on the far side rather than locally
func TestTailcatEndToEnd(t *testing.T) {
	captureLogs(t)

	// The service the exit node reaches on our behalf
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // A test echo server: the response is only ever read by the test itself
		_, _ = io.WriteString(w, "reached "+r.Host)
	}))
	defer origin.Close()

	originPort := originPortOf(t, origin)

	// A name that resolves only through the tunnel: the local resolver has never heard of it
	dns := newDNSStub(t)
	dns.set("origin.private", dnsmessage.TypeA, netip.MustParseAddr("127.0.0.1"))

	reg := runTestDERP(t)
	token := runTailcatExitNode(t, reg)

	// Pass the token through a file, which also covers the "@path" form
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte(token), 0o600))

	stateDir := t.TempDir()
	opts := &Options{
		Tailcat:    "@" + tokenPath,
		StateDir:   stateDir,
		TailcatDNS: dns.addr(),
	}

	ctx, cancel := context.WithTimeout(t.Context(), e2eHandshakeTimeout)
	defer cancel()

	b, err := setupTailcat(ctx, opts)
	require.NoError(t, err)
	t.Cleanup(b.close)

	// The client identity is persisted, so the server's --allow list keeps working across restarts
	assert.FileExists(t, filepath.Join(stateDir, tailcatKeyFileName))

	target := "origin.private:" + originPort
	want := "reached " + target

	t.Run("socks5 proxy", func(t *testing.T) {
		ln, _, err := startSocksProxy(t.Context(), b.dial, b.resolver, "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close() //nolint:errcheck

		// proxy.Direct reaches the local SOCKS5 listener; the tunnel is on the other side of it
		d, err := proxy.SOCKS5("tcp", ln.Addr().String(), nil, proxy.Direct)
		require.NoError(t, err)

		ctxDialer, ok := d.(proxy.ContextDialer)
		require.True(t, ok)

		client := &http.Client{Transport: &http.Transport{DialContext: ctxDialer.DialContext}}
		defer client.CloseIdleConnections()

		assert.Equal(t, want, httpGet(t, client, "http://"+target+"/"))
	})

	t.Run("http proxy", func(t *testing.T) {
		srv, addr, err := startHTTPProxy(t.Context(), b.dial, "127.0.0.1:0")
		require.NoError(t, err)
		defer stopHTTPProxy(srv)

		proxyURL, err := url.Parse("http://" + addr.String())
		require.NoError(t, err)

		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		defer client.CloseIdleConnections()

		assert.Equal(t, want, httpGet(t, client, "http://"+target+"/"))
	})

	t.Run("tcp forward", func(t *testing.T) {
		ln, err := startPortForward(t.Context(), b.dial, PortForward{Listen: "127.0.0.1:0", Target: target})
		require.NoError(t, err)
		defer ln.Close() //nolint:errcheck

		// The forward dials the target itself, so the client just connects to the local end
		client := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, ln.Addr().String())
			},
		}}
		defer client.CloseIdleConnections()

		assert.Equal(t, want, httpGet(t, client, "http://"+target+"/"))
	})

	t.Run("name resolved through the tunnel", func(t *testing.T) {
		// Nothing above could have worked without the DNS server behind the tunnel answering for it
		assert.NotEmpty(t, dns.queries)

		// And the local resolver genuinely cannot resolve that name
		_, err := net.DefaultResolver.LookupHost(t.Context(), "origin.private")
		assert.Error(t, err)
	})
}

// TestTailcatReusesPersistedKey verifies that a second run presents the same identity to the server, without needing a live tunnel to check it
func TestTailcatReusesPersistedKey(t *testing.T) {
	captureLogs(t)

	stateDir := t.TempDir()

	first, _, err := loadOrCreateTailcatKey(stateDir, "")
	require.NoError(t, err)

	reg := runTestDERP(t)
	token := runTailcatExitNode(t, reg)

	ctx, cancel := context.WithTimeout(t.Context(), e2eHandshakeTimeout)
	defer cancel()

	b, err := setupTailcat(ctx, &Options{
		Tailcat:    string(token),
		StateDir:   stateDir,
		TailcatDNS: "127.0.0.1:53",
	})
	require.NoError(t, err)
	t.Cleanup(b.close)

	second, _, err := loadOrCreateTailcatKey(stateDir, "")
	require.NoError(t, err)

	assert.Equal(t, first.Public().String(), second.Public().String())
}

// TestTailcatRejectsUnknownClient verifies that a server with an allowlist ignores an identity that is not on it, and that the failure says so
func TestTailcatRejectsUnknownClient(t *testing.T) {
	captureLogs(t)

	reg := runTestDERP(t)

	srv := &tailcat.Server{Key: key.NewNode(), Region: reg, Logf: testLogf(t, "exit-node")}
	srv.OnTCPForward = func(netip.AddrPort) func(net.Conn) { return nil }
	// Allow one key that is not ours
	srv.AddAllowedClient(key.NewNode().Public())
	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Close() })

	// A short deadline: a disallowed client is never answered, so this can only end in a timeout
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, err := setupTailcat(ctx, &Options{
		Tailcat:    string(srv.TailcatAddr()),
		StateDir:   t.TempDir(),
		TailcatDNS: "127.0.0.1:53",
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "--allow")
}

// originPortOf returns the port an httptest server is listening on
func originPortOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	return port
}

// httpGet performs a request and returns the body, failing the test on any error
func httpGet(t *testing.T, client *http.Client, target string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	return strings.TrimSpace(string(body))
}

// testLogf routes a tailscale-style logger into the test log
func testLogf(t *testing.T, scope string) logger.Logf {
	t.Helper()

	return func(format string, args ...any) {
		t.Helper()
		safeLog(t, "["+scope+"] "+fmt.Sprintf(format, args...))
	}
}

// captureLogs sends slog output into the test log for the duration of the test, so a passing run stays quiet but a failing one still shows why
func captureLogs(t *testing.T) {
	t.Helper()

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&testWriter{t: t}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// testWriter adapts an io.Writer to t.Log
type testWriter struct {
	t *testing.T
}

func (w *testWriter) Write(p []byte) (int, error) {
	safeLog(w.t, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// Background goroutines in the network stack outlive the test that started them, and logging from one after it finished panics
// Everything written after cleanup is dropped instead
var (
	finishedMu sync.Mutex
	finished   = map[*testing.T]bool{}
)

func safeLog(t *testing.T, msg string) {
	t.Helper()

	finishedMu.Lock()
	defer finishedMu.Unlock()

	done, seen := finished[t]
	if done {
		return
	}
	if !seen {
		finished[t] = false
		t.Cleanup(func() {
			finishedMu.Lock()
			defer finishedMu.Unlock()
			finished[t] = true
		})
	}

	t.Log(msg)
}
