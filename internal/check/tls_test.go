package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTLSCheckValidCertificateAndHTTPSRedirect(t *testing.T) {
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("TLS check should only perform a handshake, not send an HTTP request")
	}))
	tlsServer.StartTLS()
	defer tlsServer.Close()

	cert, err := x509.ParseCertificate(tlsServer.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	redirectHits := 0
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHits++
		if r.Method != http.MethodHead {
			t.Errorf("redirect probe used %s, want HEAD", r.Method)
		}
		http.Redirect(w, r, "https://127.0.0.1/login", http.StatusPermanentRedirect)
	}))
	defer httpServer.Close()

	check := &TLSCheck{rootCAs: roots, dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		target := tlsServer.Listener.Addr().String()
		if port == "80" {
			target = httpServer.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}}
	detail, err := check.RunDetailed(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("RunDetailed: %v", err)
	}
	if redirectHits != 1 {
		t.Fatalf("redirect endpoint hit %d times, want one", redirectHits)
	}
	if len(detail.Probes) != 5 || len(detail.Findings) != 0 {
		t.Fatalf("unexpected detail: %+v", detail)
	}
	for _, probe := range detail.Probes {
		if probe.Status != "completed" {
			t.Errorf("probe %s status = %s, want completed", probe.ID, probe.Status)
		}
	}
}

func TestTLSCheckKeepsNetworkFailureOutOfFindings(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	check := &TLSCheck{dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if port == "443" {
			return nil, errors.New("test secret: refused")
		}
		return (&net.Dialer{}).DialContext(ctx, network, httpServer.Listener.Addr().String())
	}}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err == nil {
		t.Fatal("expected TLS network error")
	}
	for i := 0; i < 4; i++ {
		if detail.Probes[i].Status != "failed" {
			t.Errorf("TLS probe %s status = %s, want failed", detail.Probes[i].ID, detail.Probes[i].Status)
		}
	}
	if detail.Probes[4].Status != "completed" || len(detail.Findings) != 1 || detail.Findings[0].ID != "tls.http_redirect_missing" {
		t.Fatalf("network error contaminated independent redirect result: %+v", detail)
	}
	for _, finding := range detail.Findings {
		if strings.Contains(finding.Evidence, "test secret") {
			t.Fatal("network error details leaked into public evidence")
		}
	}
}

func TestTLSCertificateExpiryAndHostnameFindings(t *testing.T) {
	check := &TLSCheck{}
	detail := Detail{Probes: []ProbeResult{
		{ID: "tls.cert_expiry", Type: tlsExpiryProbe, Location: "example.test:443"},
		{ID: "tls.cert_hostname", Type: tlsHostnameProbe, Location: "example.test:443"},
	}}
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(-time.Minute),
		DNSNames: []string{"other.example"},
	}
	check.checkExpiry(&detail, cert, now)
	check.checkHostname(&detail, cert, "example.test")
	if len(detail.Findings) != 2 {
		t.Fatalf("got %d findings, want expired and hostname mismatch: %+v", len(detail.Findings), detail.Findings)
	}
	if detail.Findings[0].ID != "tls.certificate_expired" || detail.Findings[1].ID != "tls.certificate_hostname_mismatch" {
		t.Fatalf("unexpected findings: %+v", detail.Findings)
	}
}

func TestTLSProtocolFindings(t *testing.T) {
	for _, test := range []struct {
		version uint16
		want    bool
	}{
		{tls.VersionTLS10, true},
		{tls.VersionTLS11, true},
		{tls.VersionTLS12, false},
		{tls.VersionTLS13, false},
	} {
		detail := Detail{Probes: make([]ProbeResult, 4)}
		(&TLSCheck{}).checkProtocol(&detail, test.version, "example.test")
		if got := len(detail.Findings) != 0; got != test.want {
			t.Errorf("version %s has finding = %v, want %v", tls.VersionName(test.version), got, test.want)
		}
		if detail.Probes[3].Status != "completed" {
			t.Errorf("version %s probe status = %q, want completed", tls.VersionName(test.version), detail.Probes[3].Status)
		}
	}
}

func TestRedirectsToSameHTTPSHost(t *testing.T) {
	for _, test := range []struct {
		location string
		domain   string
		want     bool
	}{
		{"https://example.test/login", "example.test", true},
		{"https://EXAMPLE.TEST/login", "example.test", true},
		{"https://example.test:443/login", "example.test", true},
		{"https://example.test:8443/login", "example.test", false},
		{"https://other.test/login", "example.test", false},
		{"/login", "example.test", false},
	} {
		t.Run(fmt.Sprintf("%s_%t", test.location, test.want), func(t *testing.T) {
			location, err := url.Parse(test.location)
			if err != nil {
				t.Fatal(err)
			}
			if got := redirectsToSameHTTPSHost(location, test.domain); got != test.want {
				t.Errorf("redirectsToSameHTTPSHost(%q, %q) = %v, want %v", test.location, test.domain, got, test.want)
			}
		})
	}
}
