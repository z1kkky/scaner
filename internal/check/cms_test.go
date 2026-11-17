package check

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCMSCheckFindsGeneratorWithoutReturningPageContent(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{Transport: exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		if req.Method != http.MethodGet || req.URL.Path != "/" {
			t.Errorf("CMS probe requested %s %s, want GET /", req.Method, req.URL.Path)
		}
		body := `<html><head><meta content="WordPress 6.4.2" name="generator"></head><body>PRIVATE_PAGE_TEXT</body></html>`
		return exposureHTTPResponse(req, http.StatusOK, "text/html", body), nil
	})}
	check := &CMSCheck{client: client}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("RunDetailed: %v", err)
	}
	if requests.Load() != 1 || len(detail.Probes) != 1 || detail.Probes[0].Status != "completed" || len(detail.Findings) != 1 {
		t.Fatalf("unexpected CMS detail: %+v", detail)
	}
	finding := detail.Findings[0]
	if finding.ID != "cms.detected_wordpress" || !strings.Contains(finding.Title, "6.4.2") || finding.Severity != SeverityInfo {
		t.Fatalf("unexpected CMS finding: %+v", finding)
	}
	if strings.Contains(finding.Evidence, "PRIVATE_PAGE_TEXT") || strings.Contains(finding.Description, "PRIVATE_PAGE_TEXT") {
		t.Fatal("homepage contents leaked into finding")
	}
}

func TestIdentifyCMSRecognizesCommonPublicMarkers(t *testing.T) {
	tests := []struct {
		name, header, body, wantName, wantVersion string
	}{
		{"wordpress generator", "", `<meta name="generator" content="WordPress 6.7.1">`, "WordPress", "6.7.1"},
		{"drupal header", "Drupal 10.4", "", "Drupal", "10.4"},
		{"joomla marker", "", `<script src="/media/system/js/core.js"></script>`, "Joomla", ""},
		{"magento marker", "", `<script>require(["mage/cookies"])</script>`, "Magento", ""},
		{"no marker", "", `<p>An article about WordPress and Drupal.</p>`, "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := http.Header{}
			if test.header != "" {
				headers.Set("X-Generator", test.header)
			}
			name, version := identifyCMS(headers, []byte(test.body))
			if name != test.wantName || version != test.wantVersion {
				t.Errorf("identifyCMS() = (%q, %q), want (%q, %q)", name, version, test.wantName, test.wantVersion)
			}
		})
	}
}

func TestCMSCheckDoesNotFollowRedirectOrLeakNetworkErrors(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{Transport: exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		if req.URL.Host == "other.test" {
			t.Fatal("CMS probe followed a redirect to another origin")
		}
		resp := exposureHTTPResponse(req, http.StatusFound, "text/plain", "redirect")
		resp.Header.Set("Location", "https://other.test/")
		return resp, nil
	})}
	detail, err := (&CMSCheck{client: client}).RunDetailed(context.Background(), "example.test")
	if err != nil || requests.Load() != 1 || len(detail.Findings) != 0 || detail.Probes[0].Status != "completed" {
		t.Fatalf("redirect result: detail=%+v err=%v requests=%d", detail, err, requests.Load())
	}

	client = &http.Client{Transport: exposureRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("private resolver detail")
	})}
	detail, err = (&CMSCheck{client: client}).RunDetailed(context.Background(), "example.test")
	if err == nil || len(detail.Findings) != 0 || detail.Probes[0].Status != "failed" {
		t.Fatalf("network failure should be inconclusive: detail=%+v err=%v", detail, err)
	}
	for _, finding := range detail.Findings {
		if strings.Contains(finding.Evidence, "private resolver detail") {
			t.Fatal("network error leaked into evidence")
		}
	}
}

func TestCMSCheckCapsBodyRead(t *testing.T) {
	body := &countingBody{reader: strings.NewReader(strings.Repeat("x", cmsResponseLimit*10))}
	client := &http.Client{Transport: exposureRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: body, Request: req}, nil
	})}
	detail, err := (&CMSCheck{client: client}).RunDetailed(context.Background(), "example.test")
	if err == nil || detail.Probes[0].Status != "failed" || len(detail.Findings) != 0 {
		t.Fatalf("oversized page should be inconclusive: detail=%+v err=%v", detail, err)
	}
	if body.readBytes > cmsResponseLimit+1 || !body.closed {
		t.Fatalf("body read=%d closed=%v, want <=%d and closed", body.readBytes, body.closed, cmsResponseLimit+1)
	}
}

var _ io.ReadCloser = (*countingBody)(nil)
