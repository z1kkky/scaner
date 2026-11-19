package nucleirunner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
)

const maxProxyConnections = 2
const maxRequestsPerTunnel = 8

var reviewedTemplatePaths = [...]string{"/server-status", "/.git/HEAD"}

// egressProxy binds only a private Unix socket. The container receives that
// one socket and has no network namespace connectivity. TLS CONNECT traffic
// is terminated here so its SNI, method, Host and path can be checked.
type egressProxy struct {
	listener      *net.UnixListener
	policy        *targetscope.Policy
	ctx           context.Context
	cancel        context.CancelFunc
	ca            *x509.Certificate
	caKey         *ecdsa.PrivateKey
	caPEM         []byte
	upstreamRoots *x509.CertPool
	mu            sync.Mutex
	active        map[net.Conn]struct{}
	closed        bool
	wg            sync.WaitGroup
	coverageMu    sync.Mutex
	covered       map[probeKey]bool
	failureCount  int
	firstFailure  string
}

type probeKey struct {
	authority string
	path      string
}

func newEgressProxy(ctx context.Context, path string, policy *targetscope.Policy) (*egressProxy, error) {
	return newEgressProxyWithRoots(ctx, path, policy, nil)
}

// newEgressProxyWithRoots is the test seam for a local TLS fixture. Production
// passes nil and retains normal system-root certificate validation upstream.
func newEgressProxyWithRoots(ctx context.Context, path string, policy *targetscope.Policy, roots *x509.CertPool) (*egressProxy, error) {
	if policy == nil {
		return nil, errors.New("frozen target policy required")
	}
	ca, key, caPEM, err := makeEphemeralCA()
	if err != nil {
		return nil, fmt.Errorf("create per-job TLS inspection CA: %w", err)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on per-job egress socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	if err := chmodSocket(path); err != nil {
		_ = listener.Close()
		return nil, err
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	p := &egressProxy{listener: listener, policy: policy, ctx: proxyCtx, cancel: cancel,
		ca: ca, caKey: key, caPEM: caPEM, upstreamRoots: roots, active: make(map[net.Conn]struct{}), covered: make(map[probeKey]bool)}
	p.wg.Add(1)
	go p.accept()
	return p, nil
}

func (p *egressProxy) WriteCAPEM(path string) error {
	return os.WriteFile(path, p.caPEM, 0444)
}

func makeEphemeralCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Scaner ephemeral job CA", Organization: []string{"Scaner local scanner"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(3 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func chmodSocket(path string) error { return os.Chmod(path, 0666) }

func (p *egressProxy) accept() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.AcceptUnix()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		if len(p.active) >= maxProxyConnections {
			p.mu.Unlock()
			_ = conn.Close()
			continue
		}
		p.active[conn] = struct{}{}
		p.wg.Add(1)
		p.mu.Unlock()
		go func(c net.Conn) {
			defer p.wg.Done()
			defer func() {
				_ = c.Close()
				p.mu.Lock()
				delete(p.active, c)
				p.mu.Unlock()
			}()
			p.serve(c)
		}(conn)
	}
}

func (p *egressProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	_ = p.listener.Close()
	for c := range p.active {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

func (p *egressProxy) serve(client net.Conn) {
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	defer cancel()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReaderSize(client, 32<<10)
	req, err := http.ReadRequest(reader)
	if err != nil {
		// Nuclei may open a proxy connection and close it before sending a
		// request (for example while shutting down an idle transport). That is
		// not a probe failure; expected-path coverage below still prevents an
		// unattempted check from being reported as clean.
		if !errors.Is(err, io.EOF) {
			p.recordFailure(fmt.Sprintf("invalid proxy request: %v", err))
			writeProxyError(client, http.StatusBadRequest, "invalid proxy request")
		}
		return
	}
	defer req.Body.Close()
	if req.Method == http.MethodConnect {
		p.serveConnect(ctx, client, reader, req)
		return
	}
	if err := validateBodylessGET(req); err != nil || req.URL == nil || !req.URL.IsAbs() || req.URL.Scheme != "http" || req.URL.User != nil {
		p.recordFailure("disallowed HTTP request")
		writeProxyError(client, http.StatusForbidden, "only scoped HTTP GET is allowed")
		return
	}
	if req.Host != "" && !sameHostPort(req.Host, req.URL.Host, 80) {
		p.recordFailure("proxy Host did not match request URL")
		writeProxyError(client, http.StatusForbidden, "proxy Host does not match URL")
		return
	}
	authority, err := scopedAuthority(req.URL.Host, 80)
	if err != nil || !policyAllowsAuthority(p.policy, authority) || !allowedTemplatePath(req.URL) {
		p.recordFailure("HTTP request was outside the frozen template policy")
		writeProxyError(client, http.StatusForbidden, "target is outside the frozen template policy")
		return
	}
	if err := p.forward(ctx, client, req, "http", authority); err != nil {
		p.recordFailure("HTTP upstream request failed")
		writeProxyError(client, http.StatusBadGateway, "scoped target request failed")
		return
	}
	p.recordCovered(authority, req.URL.Path)
}

func (p *egressProxy) serveConnect(ctx context.Context, client net.Conn, reader *bufio.Reader, req *http.Request) {
	authority, err := scopedAuthority(req.Host, 0)
	if err != nil || !policyAllowsAuthority(p.policy, authority) || req.URL == nil || req.RequestURI != authority || req.URL.Path != "" || req.URL.RawQuery != "" || req.ContentLength > 0 || len(req.TransferEncoding) != 0 {
		p.recordFailure("CONNECT authority or payload was outside the frozen policy")
		writeProxyError(client, http.StatusForbidden, "target is outside the frozen policy")
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.recordFailure("could not establish CONNECT response")
		return
	}

	host, _, _ := net.SplitHostPort(authority)
	leaf, err := p.leafCertificate(host)
	if err != nil {
		p.recordFailure("could not prepare per-job TLS certificate")
		return
	}
	serverTLS := tls.Server(&bufferedConn{Conn: client, reader: reader}, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !sameHostname(hello.ServerName, host) {
				return nil, errors.New("TLS SNI does not match CONNECT authority")
			}
			return nil, nil
		},
	})
	_ = serverTLS.SetDeadline(time.Now().Add(30 * time.Second))
	if err := serverTLS.HandshakeContext(ctx); err != nil {
		p.recordFailure("TLS handshake or SNI validation failed")
		return
	}
	state := serverTLS.ConnectionState()
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		p.recordFailure("unsupported TLS application protocol")
		return
	}
	readerTLS := bufio.NewReaderSize(serverTLS, 32<<10)
	for count := 0; count < maxRequestsPerTunnel; count++ {
		_ = serverTLS.SetDeadline(time.Now().Add(30 * time.Second))
		inner, err := http.ReadRequest(readerTLS)
		if err != nil {
			p.recordFailure("could not read TLS application request")
			return
		}
		if err := p.validateTunnelRequest(inner, authority); err != nil {
			_ = inner.Body.Close()
			p.recordFailure("TLS application request was outside the frozen template policy")
			writeProxyError(serverTLS, http.StatusForbidden, "only exact-host GET template requests are allowed")
			return
		}
		inner.Close = true
		inner.Header.Set("Connection", "close")
		inner.Header.Del("Proxy-Authorization")
		inner.Header.Del("Proxy-Connection")
		inner.Header.Del("Upgrade")
		if err := p.forward(ctx, serverTLS, inner, "https", authority); err != nil {
			p.recordFailure("HTTPS upstream request failed")
			writeProxyError(serverTLS, http.StatusBadGateway, "scoped target request failed")
			return
		}
		p.recordCovered(authority, inner.URL.Path)
		_ = inner.Body.Close()
		return // one request per TLS tunnel; no opaque upgrades or pipelining
	}
}

func (p *egressProxy) validateTunnelRequest(req *http.Request, authority string) error {
	if err := validateBodylessGET(req); err != nil {
		return err
	}
	if req.URL == nil || req.URL.IsAbs() || req.URL.RequestURI() != req.RequestURI {
		return errors.New("origin-form request required")
	}
	if !sameHostPort(req.Host, authority, 443) {
		return errors.New("inner Host differs from CONNECT authority")
	}
	if !allowedTemplatePath(req.URL) {
		return errors.New("path is outside the reviewed template allowlist")
	}
	return nil
}

func validateBodylessGET(req *http.Request) error {
	if req == nil || req.Method != http.MethodGet || req.Body == nil && req.ContentLength > 0 || req.ContentLength > 0 || len(req.TransferEncoding) != 0 || req.Header.Get("Expect") != "" || req.Header.Get("Upgrade") != "" {
		return errors.New("only bodyless GET is allowed")
	}
	for _, value := range req.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return errors.New("upgrades are not allowed")
			}
		}
	}
	return nil
}

func allowedTemplatePath(u *url.URL) bool {
	if u == nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	for _, path := range reviewedTemplatePaths {
		if u.Path == path {
			return true
		}
	}
	return false
}

func (p *egressProxy) recordCovered(authority, path string) {
	p.coverageMu.Lock()
	p.covered[probeKey{authority: authority, path: path}] = true
	p.coverageMu.Unlock()
}

func (p *egressProxy) recordFailure(message string) {
	p.coverageMu.Lock()
	p.failureCount++
	if p.firstFailure == "" {
		p.firstFailure = message
	}
	p.coverageMu.Unlock()
}

// validateCoverage treats a reachable 404 as a completed probe, but never
// mistakes an unreachable endpoint or an unattempted template path for a
// clean scan. Close the proxy first so all handlers have finished recording.
func (p *egressProxy) validateCoverage() error {
	covered := make(map[probeKey]bool)
	p.coverageMu.Lock()
	for key, value := range p.covered {
		covered[key] = value
	}
	failureCount, firstFailure := p.failureCount, p.firstFailure
	p.coverageMu.Unlock()

	if failureCount > 0 {
		return fmt.Errorf("Nuclei scan incomplete: egress gateway recorded %d failed or denied request(s), first: %s", failureCount, firstFailure)
	}
	for _, host := range p.policy.Hosts() {
		for _, port := range p.policy.AllowedPorts() {
			authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
			for _, path := range reviewedTemplatePaths {
				if !covered[probeKey{authority: authority, path: path}] {
					return fmt.Errorf("Nuclei scan incomplete: no successful response for %s%s", authority, path)
				}
			}
		}
	}
	return nil
}

func (p *egressProxy) forward(ctx context.Context, client net.Conn, req *http.Request, scheme, authority string) error {
	urlCopy := *req.URL
	urlCopy.Scheme = scheme
	urlCopy.Host = authority
	urlCopy.User = nil
	urlCopy.Fragment = ""
	out := req.Clone(ctx)
	out.URL = &urlCopy
	out.Host = authority
	out.RequestURI = ""
	out.Close = true
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Connection")
	out.Header.Del("Upgrade")
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            p.policy.DialContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: 32 << 10,
		ResponseHeaderTimeout:  10 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.upstreamRoots},
	}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(out)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if location := resp.Header.Get("Location"); location != "" {
			resolved, err := req.URL.Parse(location)
			if err != nil || !policyAllowsURL(p.policy, resolved) || !allowedTemplatePath(resolved) {
				return errors.New("redirect is outside the frozen template policy")
			}
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil || len(body) > maxResponseSize {
		return errors.New("target response exceeded limit")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Connection", "close")
	resp.Close = true
	return resp.Write(client)
}

func (p *egressProxy) leafCertificate(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Scaner local scanner"}},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, p.ca.Raw}, PrivateKey: key}, nil
}

func sameHostname(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, ".")) && a != "" && b != ""
}

func scopedAuthority(value string, defaultPort uint16) (string, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		if defaultPort == 0 {
			return "", errors.New("explicit port required")
		}
		host, portText = value, strconv.Itoa(int(defaultPort))
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", errors.New("hostname required")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("valid TCP port required")
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

func sameHostPort(a, b string, defaultPort uint16) bool {
	ca, ea := scopedAuthority(a, defaultPort)
	cb, eb := scopedAuthority(b, defaultPort)
	return ea == nil && eb == nil && ca == cb
}

func policyAllowsAuthority(policy *targetscope.Policy, authority string) bool {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || len(policy.Addresses(host)) == 0 {
		return false
	}
	for _, allowed := range policy.AllowedPorts() {
		if uint64(allowed) == port {
			return true
		}
	}
	return false
}

func writeProxyError(w io.Writer, code int, message string) {
	status := http.StatusText(code)
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, status, len(message), message)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

var _ net.Conn = (*bufferedConn)(nil)
