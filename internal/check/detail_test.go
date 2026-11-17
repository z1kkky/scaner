package check

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type txtFunc func(context.Context, string) ([]string, error)

func (f txtFunc) LookupTXT(ctx context.Context, name string) ([]string, error) { return f(ctx, name) }

func TestHeadersDetailedPages(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "TOP_SECRET"})
		}
		if r.URL.Path == "/" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
	}))
	defer server.Close()
	c := &HeadersCheck{Client: server.Client(), PagePaths: []string{"/login", "/login", "/"}}
	detail, err := c.RunDetailed(context.Background(), strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Probes) != 10 {
		t.Fatalf("got %d probes", len(detail.Probes))
	}
	probes := map[string]ProbeResult{}
	for _, p := range detail.Probes {
		if _, ok := probes[p.ID]; ok {
			t.Fatalf("duplicate ID %s", p.ID)
		}
		probes[p.ID] = p
	}
	if probes["headers.session_cookies@/"].Status != "skipped" || probes["headers.session_cookies@/login"].Status != "completed" {
		t.Fatal(probes)
	}
	if len(detail.Findings) != 5 {
		t.Fatalf("findings: %+v", detail.Findings)
	}
	for _, f := range detail.Findings {
		if f.ID == "" || f.Probe == "" || f.Evidence == "" || f.Location != "/login" || probes[f.ProbeID].ID == "" || strings.Contains(f.Evidence, "TOP_SECRET") {
			t.Fatalf("bad finding %+v", f)
		}
	}
}

func TestHeadersDetailedFailureAndRedirect(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		foreignHits := 0
		foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits++ }))
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if redirect {
				http.Redirect(w, r, foreign.URL, http.StatusFound)
			}
		}))
		c := &HeadersCheck{Client: server.Client(), PagePaths: []string{"/login"}}
		domain := strings.TrimPrefix(server.URL, "https://")
		if !redirect {
			server.Close()
		}
		d, err := c.RunDetailed(context.Background(), domain)
		server.Close()
		foreign.Close()
		if redirect && err != nil || !redirect && err == nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if foreignHits != 0 {
			t.Fatal("followed external redirect")
		}
		if !redirect {
			for _, p := range d.Probes {
				if p.Status != "failed" {
					t.Fatal(p)
				}
			}
			if len(d.Findings) != 0 {
				t.Fatal("network error became finding")
			}
		}
	}
}

func TestEmailSelectorsAndDNSFailures(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "dns_error", "unknown_selector", "revoked", "invalid_key", "multiple", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := map[string]int{}
			c := &EmailCheck{DKIMSelectors: []string{"mail", "mail"}, Resolver: txtFunc(func(ctx context.Context, name string) ([]string, error) {
				calls[name]++
				if mode == "dns_error" {
					return nil, errors.New("SECRET resolver failure")
				}
				if mode == "missing" {
					return nil, &net.DNSError{IsNotFound: true}
				}
				if name == "example.com" {
					if mode == "redirect" {
						return []string{"v=spf1 redirect=other.example"}, nil
					}
					return []string{"v=spf1 -all"}, nil
				}
				if name == "_dmarc.example.com" {
					return []string{"v=DMARC1; p=reject"}, nil
				}
				switch mode {
				case "revoked":
					return []string{"p="}, nil
				case "invalid_key":
					return []string{"v=DKIM1; p=not-base64!"}, nil
				case "multiple":
					return []string{"p=YWJj", "p=ZGVm"}, nil
				}
				return []string{"v=DKIM1; p=YWJj"}, nil
			})}
			if mode == "unknown_selector" {
				c.DKIMSelectors = nil
			}
			d, err := c.RunDetailed(context.Background(), "example.com")
			if err != nil || len(d.Probes) != 3 {
				t.Fatalf("%+v %v", d, err)
			}
			for _, n := range calls {
				if n != 1 {
					t.Fatal("duplicate lookup")
				}
			}
			if mode == "dns_error" {
				if len(d.Findings) != 0 {
					t.Fatal(d)
				}
				for _, p := range d.Probes {
					if p.Status != "failed" || strings.Contains(p.Message, "SECRET") {
						t.Fatal(p)
					}
				}
			}
			if mode == "valid" && len(d.Findings) != 0 {
				t.Fatal(d)
			}
			if mode == "missing" && len(d.Findings) != 3 {
				t.Fatal(d)
			}
			if mode == "unknown_selector" && (d.Probes[2].Status != "skipped" || calls["mail._domainkey.example.com"] != 0) {
				t.Fatal(d)
			}
			if mode == "redirect" && d.Probes[0].Status != "incomplete" {
				t.Fatal(d)
			}
			if mode == "revoked" || mode == "invalid_key" || mode == "multiple" {
				if len(d.Findings) != 1 || d.Findings[0].ProbeID != d.Probes[2].ID {
					t.Fatal(d)
				}
			}
		})
	}
}
