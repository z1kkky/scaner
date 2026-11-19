package nucleirunner

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
)

type policyResolver struct{}

func (policyResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (policyResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host + ".", nil
}
func (policyResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}
func (policyResolver) ResolveTarget(_ context.Context, host string) ([]string, []netip.Addr, error) {
	return []string{host}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func testPolicy(t *testing.T, dial func(context.Context, string, string) (net.Conn, error), ports []uint16) *targetscope.Policy {
	t.Helper()
	p, err := targetscope.FreezeWithDial(context.Background(), policyResolver{}, "example.com", []string{"example.com"}, ports, dial)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProxyAllowsOnlyFrozenHostAndPort(t *testing.T) {
	var calls atomic.Int32
	fixture, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	go func() {
		for {
			conn, err := fixture.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 2048)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(conn)
		}
	}()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Addr().String())
	}
	policy := testPolicy(t, dial, []uint16{80})
	sock := filepath.Join(t.TempDir(), "proxy.sock")
	proxy, err := newEgressProxy(context.Background(), sock, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	request := func(value string) string {
		t.Helper()
		conn, err := net.DialTimeout("unix", sock, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = io.WriteString(conn, value); err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	allowed := request("GET http://example.com/server-status HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if !strings.Contains(allowed, "200 OK") || !strings.HasSuffix(allowed, "ok") {
		t.Fatalf("allowed request response: %q", allowed)
	}
	before := calls.Load()
	wrongHost := request("GET http://outside.example/path HTTP/1.1\r\nHost: outside.example\r\nConnection: close\r\n\r\n")
	if !strings.Contains(wrongHost, "403 Forbidden") {
		t.Fatalf("wrong-host response: %q", wrongHost)
	}
	wrongPort := request("GET http://example.com:81/path HTTP/1.1\r\nHost: example.com:81\r\nConnection: close\r\n\r\n")
	if !strings.Contains(wrongPort, "403 Forbidden") {
		t.Fatalf("wrong-port response: %q", wrongPort)
	}
	wrongMethod := request("POST http://example.com/path HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	if !strings.Contains(wrongMethod, "403 Forbidden") {
		t.Fatalf("wrong-method response: %q", wrongMethod)
	}
	wrongPath := request("GET http://example.com/other HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if !strings.Contains(wrongPath, "403 Forbidden") {
		t.Fatalf("wrong-path response: %q", wrongPath)
	}
	if got := calls.Load(); got != before {
		t.Fatalf("denied requests reached target dialer: before=%d after=%d", before, got)
	}
}

func TestHTTPProxyFailureMakesScanIncomplete(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := closed.Addr().String()
	closedPort := closed.Addr().(*net.TCPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	policy := testPolicy(t, dial, []uint16{uint16(closedPort)})
	proxy, err := newEgressProxy(context.Background(), filepath.Join(t.TempDir(), "proxy.sock"), policy)
	if err != nil {
		t.Fatal(err)
	}
	sock := proxy.listener.Addr().String()
	status := requestHTTPProxy(t, sock, "example.com", uint16(closedPort), "/server-status")
	if status != http.StatusBadGateway {
		t.Fatalf("unreachable target status = %d, want 502", status)
	}
	_ = proxy.Close()
	if err := proxy.validateCoverage(); err == nil || !strings.Contains(err.Error(), "failed or denied") {
		t.Fatalf("unreachable target was not reported as incomplete: %v", err)
	}
}

func TestUntrustedUpstreamTLSCertificateMakesScanIncomplete(t *testing.T) {
	var calls atomic.Int32
	fixture, _ := newTLSFixture(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Listener.Addr().String())
	}
	policy := testPolicy(t, dial, []uint16{443})
	proxy, err := newEgressProxy(context.Background(), filepath.Join(t.TempDir(), "proxy.sock"), policy)
	if err != nil {
		t.Fatal(err)
	}
	status, _, requestErr := tlsProxyRequest(t, proxy.listener.Addr().String(), "example.com:443", "example.com", "GET /server-status HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if requestErr != nil || status != http.StatusBadGateway {
		t.Fatalf("untrusted upstream response status=%d error=%v, want 502", status, requestErr)
	}
	_ = proxy.Close()
	if err := proxy.validateCoverage(); err == nil || !strings.Contains(err.Error(), "failed or denied") {
		t.Fatalf("invalid upstream certificate was not reported as incomplete: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("untrusted upstream certificate reached handler: %d requests", got)
	}
}

func TestReachableHTTP404CountsAsCoverageButMissingTemplatePathDoesNot(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer fixture.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(fixture.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	portN, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(portN)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(fixture.URL, "http://"))
	}
	policy := testPolicy(t, dial, []uint16{port})
	proxy, err := newEgressProxy(context.Background(), filepath.Join(t.TempDir(), "proxy.sock"), policy)
	if err != nil {
		t.Fatal(err)
	}
	sock := proxy.listener.Addr().String()
	if got := requestHTTPProxy(t, sock, "example.com", port, "/server-status"); got != http.StatusNotFound {
		t.Fatalf("status path status=%d, want reachable 404", got)
	}
	waitForCovered(t, proxy, net.JoinHostPort("example.com", strconv.Itoa(int(port))), "/server-status")
	if err := proxy.validateCoverage(); err == nil || !strings.Contains(err.Error(), "/.git/HEAD") {
		t.Fatalf("missing template path was not reported: %v", err)
	}
	if got := requestHTTPProxy(t, sock, "example.com", port, "/.git/HEAD"); got != http.StatusNotFound {
		t.Fatalf("git path status=%d, want reachable 404", got)
	}
	_ = proxy.Close()
	if err := proxy.validateCoverage(); err != nil {
		t.Fatalf("reachable 404 responses should count as completed coverage: %v", err)
	}
}

func waitForCovered(t *testing.T, proxy *egressProxy, authority, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		proxy.coverageMu.Lock()
		covered := proxy.covered[probeKey{authority: authority, path: path}]
		proxy.coverageMu.Unlock()
		if covered {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("coverage for %s%s was not recorded", authority, path)
}

func requestHTTPProxy(t *testing.T, socket, host string, port uint16, path string) int {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if _, err := fmt.Fprintf(conn, "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority, path, authority); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

func TestTLSConnectEnforcesSNIHostMethodAndPath(t *testing.T) {
	var calls atomic.Int32
	fixture, roots := newTLSFixture(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Host != "example.com:443" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/server-status" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "Apache Server Status")
			return
		}
		http.NotFound(w, r)
	}))
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Listener.Addr().String())
	}
	policy := testPolicy(t, dial, []uint16{443})
	proxy, err := newEgressProxyWithRoots(context.Background(), filepath.Join(t.TempDir(), "proxy.sock"), policy, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	sock := proxy.listener.Addr().String()

	before := calls.Load()
	if _, _, err := tlsProxyRequest(t, sock, "example.com:443", "outside.example", "GET /server-status HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err == nil {
		t.Fatal("mismatched SNI was accepted")
	}
	if got := calls.Load(); got != before {
		t.Fatalf("mismatched SNI reached target: %d", got-before)
	}

	for _, raw := range []string{
		"GET /server-status HTTP/1.1\r\nHost: outside.example:443\r\n\r\n",
		"POST /server-status HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 0\r\n\r\n",
		"GET /server-status HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 3\r\n\r\nabc",
		"GET /not-allowed HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
	} {
		status, _, err := tlsProxyRequest(t, sock, "example.com:443", "example.com", raw)
		if err != nil || status != http.StatusForbidden {
			t.Errorf("request %q status=%d err=%v; want 403", raw, status, err)
		}
	}
	if got := calls.Load(); got != before {
		t.Fatalf("denied TLS requests reached target: before=%d after=%d", before, got)
	}

	status, body, err := tlsProxyRequest(t, sock, "example.com:443", "example.com", "GET /server-status HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n")
	if err != nil || status != http.StatusOK || body != "Apache Server Status" {
		t.Fatalf("allowed TLS request status=%d body=%q err=%v", status, body, err)
	}
}

func TestConnectRejectsWrongAuthorityAndCleartextPayload(t *testing.T) {
	var calls atomic.Int32
	fixture, roots := newTLSFixture(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(100)
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Listener.Addr().String())
	}
	proxy, err := newEgressProxyWithRoots(context.Background(), filepath.Join(t.TempDir(), "proxy.sock"), testPolicy(t, dial, []uint16{443}), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	sock := proxy.listener.Addr().String()

	for _, authority := range []string{"outside.example:443", "example.com:8443"} {
		conn, err := net.DialTimeout("unix", sock, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		line, _ := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if !strings.Contains(line, "403 Forbidden") {
			t.Errorf("CONNECT %s response=%q", authority, line)
		}
	}

	before := calls.Load()
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("allowed CONNECT response=%q", line)
	}
	for {
		line, _ = br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	_, _ = io.WriteString(conn, "GET /server-status HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.ReadAll(conn)
	_ = conn.Close()
	if got := calls.Load(); got != before {
		t.Fatalf("cleartext CONNECT payload reached upstream: before=%d after=%d", before, got)
	}
}

func TestTLSRedirectIsRejectedWithoutFollowingExternalTarget(t *testing.T) {
	var authorities []string
	var mu sync.Mutex
	fixture, roots := newTLSFixture(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorities = append(authorities, r.Host)
		mu.Unlock()
		http.Redirect(w, r, "https://outside.example:443/server-status", http.StatusFound)
	}))
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		authorities = append(authorities, address)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Listener.Addr().String())
	}
	policy := testPolicy(t, dial, []uint16{443})
	proxy, err := newEgressProxyWithRoots(context.Background(), filepath.Join(t.TempDir(), "proxy.sock"), policy, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: "127.0.0.1:18080"}, nil },
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", proxy.listener.Addr().String())
		},
		TLSClientConfig:   &tls.Config{RootCAs: rootsForProxy(t, proxy.caPEM), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	resp, err := client.Get("https://example.com:443/server-status")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("external redirect response status=%d, want 502", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, authority := range authorities {
		if strings.Contains(authority, "outside.example") {
			t.Fatalf("proxy dialed redirect target: %q", authority)
		}
	}
}

func tlsProxyRequest(t *testing.T, socket, authority, sni, request string) (int, string, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		return 0, "", err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	if strings.Contains(line, "403 Forbidden") {
		return http.StatusForbidden, "", nil
	}
	if !strings.Contains(line, "200 Connection Established") {
		return 0, "", fmt.Errorf("unexpected CONNECT response %q", line)
	}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		if line == "\r\n" {
			break
		}
	}
	tlsConn := tls.Client(&bufferedConn{Conn: conn, reader: br}, &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: []string{"http/1.1"}}) // test endpoint deliberately uses the ephemeral job certificate
	if err := tlsConn.Handshake(); err != nil {
		return 0, "", err
	}
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func newTLSFixture(t *testing.T, host string, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return server, pool
}

func rootsForProxy(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not parse proxy CA")
	}
	return pool
}

func TestNucleiOutputRejectsOutOfPolicyOrUnreviewedTemplates(t *testing.T) {
	policy := testPolicy(t, nil, []uint16{80})
	valid := []byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://example.com/server-status","info":{"name":"status","severity":"low"}}` + "\n")
	findings, err := parseOutput(valid, policy)
	if err != nil || len(findings) != 1 {
		t.Fatalf("valid output: findings=%v err=%v", findings, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"template-id":"arbitrary-template","matched-at":"http://example.com/","info":{"name":"bad","severity":"high"}}`),
		[]byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://outside.example/","info":{"name":"bad","severity":"high"}}`),
		[]byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://example.com:81/","info":{"name":"bad","severity":"high"}}`),
		[]byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://example.com/server-status","info":{"name":"status","severity":"unknown"}}`),
		[]byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://example.com/server-status","info":{"name":"status","severity":""}}`),
		[]byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://example.com/server-status","info":{"name":"status"}}`),
	} {
		if _, err := parseOutput(raw, policy); err == nil {
			t.Errorf("accepted out-of-policy output: %s", raw)
		}
	}
}

func TestNucleiOutputNormalizesValidSeverity(t *testing.T) {
	policy := testPolicy(t, nil, []uint16{80})
	valid := []byte(`{"template-id":"scaner-apache-server-status","matched-at":"http://example.com/server-status","info":{"name":"status","severity":" HIGH "}}` + "\n")
	findings, err := parseOutput(valid, policy)
	if err != nil || len(findings) != 1 || findings[0]["severity"] != "high" {
		t.Fatalf("valid severity was not normalized: findings=%v err=%v", findings, err)
	}
}

func TestEmbeddedTemplatesMatchReviewedAllowlistAndUseGET(t *testing.T) {
	for _, name := range []string{"apache-status.yaml", "exposed-git.yaml"} {
		got, err := templates.ReadFile("templates/" + name)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("..", "check", "nuclei_templates", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("embedded template %s differs from reviewed check allowlist", name)
		}
		if !strings.Contains(string(got), "method: GET") || strings.Contains(string(got), "method: POST") {
			t.Errorf("template %s is not GET-only", name)
		}
	}
}

func TestNucleiTargetsOnlyUseFrozenHostsAndPorts(t *testing.T) {
	policy := testPolicy(t, nil, []uint16{80, 443})
	targets, err := nucleiTargets(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets=%v", targets)
	}
	for _, target := range targets {
		u, err := url.Parse(target)
		if err != nil || (u.Host != "example.com:80" && u.Host != "example.com:443") {
			t.Errorf("unexpected target %q: %v", target, err)
		}
	}
}

func TestNucleiTargetsHaveFiniteUpperBound(t *testing.T) {
	hosts := make([]string, maxNucleiTargets+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("node%d.example.com", i)
	}
	policy, err := targetscope.Freeze(context.Background(), policyResolver{}, "example.com", hosts, []uint16{80})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nucleiTargets(policy); err == nil {
		t.Fatalf("accepted more than %d frozen host-port pairs", maxNucleiTargets)
	}
}
