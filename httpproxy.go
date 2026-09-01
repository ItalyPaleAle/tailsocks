package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

const (
	// How long a client can hold a connection open without sending a complete request
	httpProxyReadHeaderTimeout = 30 * time.Second
	// Browsers open many parallel connections to the same origin, and the default of 2 idle connections per host would force constant reconnections
	httpProxyMaxIdleConnsPerHost = 32
	httpProxyIdleConnTimeout     = 90 * time.Second
	// Grace period granted to in-flight requests when the proxy is shutting down
	httpProxyShutdownTimeout = 5 * time.Second
	// Port assumed for CONNECT requests whose target omits one
	httpProxyDefaultConnectPort = "443"
	// Realm advertised in the Proxy-Authenticate challenge
	httpProxyAuthRealm = "tailsocks"
	// Env var read for the HTTP proxy password when --http-password is not set, so the secret need not appear in shell history or process listings
	httpProxyPasswordEnvVar = "TAILSOCKS_HTTP_PASSWORD" // #nosec G101 -- Not a credential, just the name of the env var
)

// httpProxy is an HTTP forward proxy that routes all traffic through the tailnet
// It handles the two request forms a forward proxy receives:
//   - CONNECT, which opens an opaque tunnel and is how every https:// destination is reached
//   - absolute-form requests such as "GET http://example.com/path", used for plain http:// destinations
type httpProxy struct {
	dial         func(ctx context.Context, network string, addr string) (net.Conn, error)
	reverseProxy *httputil.ReverseProxy
	log          *slog.Logger
	username     string
	password     string
}

// newHTTPProxy creates an HTTP proxy handler that sends traffic through d
// When username is non-empty, every request must present matching Basic credentials in the Proxy-Authorization header
func newHTTPProxy(d dialer, username string, password string) *httpProxy {
	log := slog.Default().With(slog.String("scope", "http"))

	p := &httpProxy{
		dial:     d.Dial,
		log:      log,
		username: username,
		password: password,
	}

	p.reverseProxy = &httputil.ReverseProxy{
		// ReverseProxy requires a Rewrite or Director, but proxy requests already carry the destination in the request URI so there is nothing to rewrite
		// Rewrite is preferred over Director because Director would append X-Forwarded-For, disclosing the client's address to the destination
		Rewrite: func(_ *httputil.ProxyRequest) {},
		Transport: &http.Transport{
			DialContext: d.Dial,
			// This process is the proxy, so it must never chain to a proxy configured in the environment
			Proxy: nil,
			// Pass through the client's own Accept-Encoding rather than transparently requesting gzip and decoding it here
			DisableCompression:  true,
			MaxIdleConnsPerHost: httpProxyMaxIdleConnsPerHost,
			IdleConnTimeout:     httpProxyIdleConnTimeout,
		},
		// Flush immediately so responses that trickle in, such as long-polling or streaming endpoints, are not held in a buffer
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warn("Failed to forward request", "host", r.Host, "error", err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	return p
}

// ServeHTTP implements http.Handler
func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.username != "" && !p.authenticate(r) {
		p.log.Debug("Rejected request with missing or invalid Proxy-Authorization", "method", r.Method, "remote", r.RemoteAddr)
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+httpProxyAuthRealm+`"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Clients that aren't configured to use a proxy send origin-form requests such as "GET /path", which carry no destination we could route to
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "This is a proxy server and requires requests with an absolute-form URI", http.StatusBadRequest)
		return
	}

	p.log.Debug("Forwarding request", "method", r.Method, "url", r.URL.String())
	p.reverseProxy.ServeHTTP(w, r)
}

// authenticate reports whether r carries Basic credentials in Proxy-Authorization matching p.username and p.password
// Comparisons are constant-time so a client cannot use response timing to guess a correct username or password one byte at a time
func (p *httpProxy) authenticate(r *http.Request) bool {
	user, pass, ok := parseProxyAuthorization(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}

	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(p.username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(p.password)) == 1
	return userMatch && passMatch
}

// parseProxyAuthorization extracts the username and password from a Basic Proxy-Authorization header value
// This mirrors http.Request.BasicAuth, which instead reads the Authorization header used by origin servers rather than proxies
func parseProxyAuthorization(header string) (username string, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}

	username, password, ok = strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}

	return username, password, true
}

// handleConnect establishes a tunnel to the requested target and pipes raw bytes in both directions
func (p *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Go parses the authority-form target of a CONNECT request into URL.Host
	addr := r.URL.Host
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		// A CONNECT target without a port means the default HTTPS port
		addr = net.JoinHostPort(addr, httpProxyDefaultConnectPort)
	}

	// Dial before hijacking, so that a failure can still be reported to the client as a regular HTTP response
	upstream, err := p.dial(r.Context(), "tcp", addr)
	if err != nil {
		p.log.Warn("Failed to dial CONNECT target", "target", addr, "error", err)
		http.Error(w, "Failed to connect to the destination", http.StatusBadGateway)
		return
	}
	defer upstream.Close() //nolint:errcheck

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.log.Error("Connection cannot be hijacked, unable to establish a CONNECT tunnel", "target", addr)
		http.Error(w, "CONNECT is not supported", http.StatusInternalServerError)
		return
	}

	client, brw, err := hijacker.Hijack()
	if err != nil {
		p.log.Warn("Failed to hijack connection for CONNECT tunnel", "target", addr, "error", err)
		http.Error(w, "Failed to establish the tunnel", http.StatusInternalServerError)
		return
	}
	defer client.Close() //nolint:errcheck

	// The ResponseWriter can no longer be used once the connection is hijacked, so the success response is written to the connection directly
	_, err = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		p.log.Warn("Failed to acknowledge CONNECT request", "target", addr, "error", err)
		return
	}

	// While parsing the request the server may have read part of what the client sent next into the buffered reader
	// Those bytes are the beginning of the tunneled stream (typically the TLS ClientHello) and are lost unless they are replayed before copying the rest of the connection
	buffered := brw.Reader.Buffered()
	if buffered > 0 {
		_, err = io.CopyN(upstream, brw, int64(buffered))
		if err != nil {
			p.log.Warn("Failed to replay buffered bytes into CONNECT tunnel", "target", addr, "error", err)
			return
		}
	}

	p.log.Debug("Established CONNECT tunnel", "target", addr, "client", client.RemoteAddr().String())
	pipeConn(client, upstream)
}

// startHTTPProxy begins listening for HTTP proxy requests on addr, routing all traffic through d
// When username is non-empty, clients must authenticate with matching Basic Proxy-Authorization credentials
// It returns the server, which should be stopped with stopHTTPProxy, and the address it is actually bound to
func startHTTPProxy(ctx context.Context, d dialer, addr string, username string, password string) (*http.Server, net.Addr, error) {
	nlc := net.ListenConfig{}
	l, err := nlc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on '%s': %w", addr, err)
	}

	log := slog.Default().With(slog.String("scope", "http"))
	srv := &http.Server{
		Handler:           newHTTPProxy(d, username, password),
		ReadHeaderTimeout: httpProxyReadHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	go func() {
		serveErr := srv.Serve(l)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Warn("HTTP proxy server stopped", "error", serveErr)
		}
	}()

	return srv, l.Addr(), nil
}

// stopHTTPProxy shuts the server down, giving in-flight requests a short grace period
// Shutdown ignores hijacked connections, so established CONNECT tunnels are severed by the Close that follows
func stopHTTPProxy(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), httpProxyShutdownTimeout)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		slog.Debug("HTTP proxy did not shut down gracefully", "error", err)
	}

	_ = srv.Close()
}

// resolveHTTPProxyAuth determines the HTTP proxy's Basic Auth credentials from --http-user and --http-password, falling back to the
// TAILSOCKS_HTTP_PASSWORD environment variable for the password when --http-password is not set
// It returns empty strings when authentication is not configured, and an error if only a username or only a password was supplied
func resolveHTTPProxyAuth(opts *Options) (username string, password string, err error) {
	username = strings.TrimSpace(opts.HTTPUser)
	password = strings.TrimSpace(opts.HTTPPassword)
	if password == "" {
		password = strings.TrimSpace(os.Getenv(httpProxyPasswordEnvVar))
	}

	if (username == "") != (password == "") {
		return "", "", fmt.Errorf("--http-user and --http-password (or %s) must both be set to enable HTTP proxy authentication", httpProxyPasswordEnvVar)
	}

	return username, password, nil
}
