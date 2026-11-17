package check

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type exposureRoundTripper func(*http.Request) (*http.Response, error)

func (f exposureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestExposuresCheckFindsSensitivePathsWithoutReturningBodies(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	transport := exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		seen[req.URL.Path]++
		mu.Unlock()
		status, contentType, body := http.StatusNotFound, "text/plain", "not found"
		location := ""
		switch req.URL.Path {
		case "/.git/HEAD":
			status, body = http.StatusOK, "ref: refs/heads/main\n"
		case "/.env":
			status, body = http.StatusOK, "DB_PASSWORD=never-return-this-secret\n"
		case "/backup.zip":
			status, contentType, body = http.StatusOK, "application/zip", "PK\x03\x04"+strings.Repeat("x", exposureResponseLimit*3)
		case "/uploads/":
			status, contentType, body = http.StatusOK, "text/html", "<title>Index of /uploads/</title>"
		case "/wp-admin/":
			status, location = http.StatusFound, "https://example.test/wp-login.php"
		}
		resp := exposureHTTPResponse(req, status, contentType, body)
		if location != "" {
			resp.Header.Set("Location", location)
		}
		return resp, nil
	})
	check := &ExposuresCheck{client: &http.Client{Transport: transport}}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("RunDetailed: %v", err)
	}
	if len(detail.Probes) != len(exposureTargets) || len(detail.Findings) != 5 {
		t.Fatalf("got %d probes and %d findings, want %d and 5", len(detail.Probes), len(detail.Findings), len(exposureTargets))
	}
	wantIDs := map[string]bool{
		"exposures.git_reachable":               false,
		"exposures.env_reachable":               false,
		"exposures.backup_reachable":            false,
		"exposures.directory_listing_reachable": false,
		"exposures.admin_interface_reachable":   false,
	}
	for _, finding := range detail.Findings {
		if _, ok := wantIDs[finding.ID]; !ok {
			t.Errorf("unexpected finding ID %q", finding.ID)
		}
		wantIDs[finding.ID] = true
		if strings.Contains(finding.Evidence, "never-return-this-secret") || strings.Contains(finding.Description, "never-return-this-secret") {
			t.Fatal("response secret leaked into finding")
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("missing finding %s", id)
		}
	}
	for _, probe := range detail.Probes {
		if probe.Status != "completed" {
			t.Errorf("probe %s status = %q, want completed", probe.ID, probe.Status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, target := range exposureTargets {
		if seen[target.path] != 1 {
			t.Errorf("path %s requested %d times, want once", target.path, seen[target.path])
		}
	}
}

func TestExposuresCheckDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	transport := exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		seen[req.URL.Path]++
		mu.Unlock()
		if req.URL.Path == "/.git/HEAD" {
			resp := exposureHTTPResponse(req, http.StatusFound, "text/plain", "redirect")
			resp.Header.Set("Location", "https://other.test/.git/HEAD")
			return resp, nil
		}
		return exposureHTTPResponse(req, http.StatusNotFound, "text/plain", "not found"), nil
	})
	check := &ExposuresCheck{client: &http.Client{Transport: transport}}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("RunDetailed: %v", err)
	}
	if len(detail.Findings) != 0 || seen["/.git/HEAD"] != 1 || seen["/.git/HEAD"]+seen["/.env"]+seen["/config/.env"] != 3 {
		t.Fatalf("redirect was followed or reported as exposure: findings=%+v requests=%v", detail.Findings, seen)
	}
	for path := range seen {
		if strings.Contains(path, "other.test") {
			t.Fatalf("followed cross-origin redirect: %s", path)
		}
	}
}

func TestExposuresCheckBoundsBodyReadsAndClosesResponses(t *testing.T) {
	var mu sync.Mutex
	var bodies []*countingBody
	transport := exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		body := &countingBody{reader: strings.NewReader(strings.Repeat("x", exposureResponseLimit*20))}
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: body, Request: req}, nil
	})
	check := &ExposuresCheck{client: &http.Client{Transport: transport}}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err == nil {
		t.Fatal("oversized inconclusive responses should report partial coverage")
	}
	if len(detail.Findings) != 0 {
		t.Fatalf("unrecognized oversized body generated findings: %+v", detail.Findings)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != len(exposureTargets) {
		t.Fatalf("got %d response bodies, want %d", len(bodies), len(exposureTargets))
	}
	for i, body := range bodies {
		if body.readBytes > exposureResponseLimit+1 {
			t.Errorf("body %d read %d bytes, limit is %d", i, body.readBytes, exposureResponseLimit+1)
		}
		if !body.closed {
			t.Errorf("body %d was not closed", i)
		}
	}
}

func TestExposuresCheckTimeoutDoesNotCreateFindings(t *testing.T) {
	transport := exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	check := &ExposuresCheck{client: &http.Client{Transport: transport}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	detail, err := check.RunDetailed(ctx, "example.test")
	if err == nil {
		t.Fatal("expected canceled requests")
	}
	if len(detail.Findings) != 0 {
		t.Fatalf("timeout generated findings: %+v", detail.Findings)
	}
}

func TestExposuresCheckCapsConcurrentRequests(t *testing.T) {
	var current, peak atomic.Int32
	transport := exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		n := current.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return exposureHTTPResponse(req, http.StatusNotFound, "text/plain", "not found"), nil
	})
	check := &ExposuresCheck{client: &http.Client{Transport: transport}}
	if _, err := check.RunDetailed(context.Background(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got < 2 || got > exposureMaxParallel {
		t.Fatalf("peak concurrent requests = %d, want 2..%d", got, exposureMaxParallel)
	}
}

type countingBody struct {
	reader    *strings.Reader
	readBytes int
	closed    bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.readBytes += n
	return n, err
}

func (b *countingBody) Close() error {
	b.closed = true
	return nil
}

func exposureHTTPResponse(req *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}},
		Body: io.NopCloser(strings.NewReader(body)), Request: req,
	}
}
