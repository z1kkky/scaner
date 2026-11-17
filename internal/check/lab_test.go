package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

type labTXTResolver struct{}

func (labTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	switch {
	case name == "127.0.0.1":
		return []string{"v=spf1 -all"}, nil
	case name == "_dmarc.127.0.0.1":
		return []string{"v=DMARC1; p=reject"}, nil
	case name == "mail._domainkey.127.0.0.1":
		return []string{"v=DKIM1; p=AQAB"}, nil
	default:
		return nil, errors.New("unexpected lab DNS lookup")
	}
}

// TestScannerLab runs every built-in check against a local controlled target.
// It uses real HTTP/TLS and TCP connections while all destinations remain on
// loopback; the injected network adapters only map the scanner's fixed target
// ports to ephemeral listeners in this test process.
func TestScannerLab(t *testing.T) {
	const domain = "127.0.0.1"
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = io.WriteString(w, `<meta name="generator" content="WordPress 6.7.1">`)
		case "/.git/HEAD":
			_, _ = io.WriteString(w, "ref: refs/heads/main\n")
		case "/.env":
			_, _ = io.WriteString(w, "DATABASE_PASSWORD=lab-secret-must-not-leak\n")
		case "/backup.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("PK\x03\x04"))
		case "/uploads/":
			_, _ = io.WriteString(w, "<title>Index of /uploads/</title>")
		case "/wp-admin/":
			http.Redirect(w, r, "https://127.0.0.1/wp-login.php", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	tlsServer.Config.ErrorLog = log.New(io.Discard, "", 0)
	tlsServer.StartTLS()
	defer tlsServer.Close()
	cert, err := x509.ParseCertificate(tlsServer.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	plainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("HTTP redirect lab got %s, want HEAD", r.Method)
		}
		w.Header().Set("Location", "https://127.0.0.1/")
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	defer plainServer.Close()

	var dialer net.Dialer
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		target := tlsServer.Listener.Addr().String()
		if port == "80" {
			target = plainServer.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, target)
	}
	transport := &http.Transport{
		DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: domain},
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	openPortPeer := make(chan net.Conn, 1)

	checks := NewDefaultChecks(DefaultChecksOptions{})
	for _, c := range checks {
		switch typed := c.(type) {
		case *TLSCheck:
			typed.rootCAs, typed.dialContext = roots, dial
		case *HeadersCheck:
			typed.Client = client
		case *ExposuresCheck:
			typed.client = client
		case *PortsCheck:
			typed.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				if port != "23" {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
				}
				left, right := net.Pipe()
				openPortPeer <- right
				return left, nil
			}
		case *CMSCheck:
			typed.client = client
		case *EmailCheck:
			typed.Resolver = labTXTResolver{}
			typed.DKIMSelectors = []string{"mail"}
		}
	}

	results := make(map[string]Detail, len(checks))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, c := range checks {
		detailed := c.(DetailedCheck)
		detail, err := detailed.RunDetailed(ctx, domain)
		if err != nil {
			t.Fatalf("lab check %s: %v", c.Name(), err)
		}
		results[c.Name()] = detail
	}

	if len(results["tls"].Probes) != 5 || len(results["tls"].Findings) != 0 {
		t.Fatalf("TLS lab result: %+v", results["tls"])
	}
	if len(results["headers"].Findings) != 0 {
		t.Fatalf("secure headers unexpectedly produced findings: %+v", results["headers"].Findings)
	}
	wantExposureFindings := map[string]bool{
		"exposures.git_reachable":               false,
		"exposures.env_reachable":               false,
		"exposures.backup_reachable":            false,
		"exposures.directory_listing_reachable": false,
		"exposures.admin_interface_reachable":   false,
	}
	for _, finding := range results["exposures"].Findings {
		if _, ok := wantExposureFindings[finding.ID]; !ok {
			t.Errorf("unexpected lab exposure finding: %+v", finding)
		}
		wantExposureFindings[finding.ID] = true
	}
	for id, found := range wantExposureFindings {
		if !found {
			t.Errorf("missing lab exposure finding %s", id)
		}
	}
	if len(results["cms"].Findings) != 1 || results["cms"].Findings[0].ID != "cms.detected_wordpress" {
		t.Fatalf("CMS lab result: %+v", results["cms"])
	}
	if len(results["ports"].Findings) != 1 || results["ports"].Findings[0].ID != "ports.open_23" {
		t.Fatalf("ports lab result: %+v", results["ports"])
	}
	if len(results["email"].Findings) != 0 || len(results["email"].Probes) != 3 {
		t.Fatalf("email lab result: %+v", results["email"])
	}

	peer := <-openPortPeer
	closed := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(peer)
		closed <- data
	}()
	select {
	case data := <-closed:
		if len(data) != 0 {
			t.Fatalf("port probe sent %d application bytes", len(data))
		}
	case <-time.After(time.Second):
		t.Fatal("port probe left its TCP connection open")
	}
	_ = peer.Close()

	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "lab-secret-must-not-leak") {
		t.Fatal("lab secret leaked into scanner results")
	}
}
