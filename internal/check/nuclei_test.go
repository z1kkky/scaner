package check

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNucleiOptInAndBundledTemplateAllowlist(t *testing.T) {
	for _, c := range NewDefaultChecks(DefaultChecksOptions{}) {
		if c.Name() == "nuclei" {
			t.Fatal("Nuclei must not be enabled by default")
		}
	}
	checks := NewDefaultChecks(DefaultChecksOptions{EnableNuclei: true})
	if checks[len(checks)-1].Name() != "nuclei" {
		t.Fatal("explicit opt-in should add Nuclei to the check set")
	}

	var templates []string
	if err := fs.WalkDir(nucleiTemplates, "nuclei_templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			data, err := nucleiTemplates.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.Contains(string(data), "id: scaner-") || !strings.Contains(string(data), "http:") {
				t.Errorf("unexpected non-HTTP template in allowlist: %s", path)
			}
			templates = append(templates, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(templates) != 2 {
		t.Fatalf("expected the deliberately small allowlist of 2 templates, got %d", len(templates))
	}
}

func TestNucleiCheckUsesBundledTemplatesAndResourceLimits(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell is unavailable")
	}
	root := t.TempDir()
	output := filepath.Join(root, "args")
	script := filepath.Join(root, "fake-nuclei")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"" + output + "\"\nprintf '%s\\n' '{\"template-id\":\"scaner-apache-server-status\",\"matched-at\":\"https://example.com/server-status\",\"info\":{\"name\":\"Public Apache server-status page\",\"severity\":\"low\"}}'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	detail, err := (&NucleiCheck{Executable: script}).RunDetailed(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Probes[0].Status != "completed" || len(detail.Findings) != 1 || detail.Findings[0].Severity != SeverityLow {
		t.Fatalf("unexpected Nuclei result: %+v", detail)
	}
	args, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"-t", "-pt http", "-c 1", "-rl 2", "-timeout 5", "-retries 0", "-omit-raw", "-no-interactsh", "-duc"} {
		if !strings.Contains(string(args), expected) {
			t.Errorf("Nuclei invocation omitted safety option %q: %s", expected, args)
		}
	}
}

func TestNucleiMalformedSeverityFailsWithoutCompletingProbe(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell is unavailable")
	}
	for _, tc := range []struct {
		name     string
		severity string
	}{
		{name: "unknown", severity: `"unknown"`},
		{name: "empty", severity: `""`},
		{name: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "fake-nuclei")
			info := `"name":"example","severity":` + tc.severity
			if tc.name == "missing" {
				info = `"name":"example"`
			}
			line := `{"template-id":"scaner-example","matched-at":"https://example.com/","info":{` + info + `}}`
			body := "#!/bin/sh\nprintf '%s\\n' '" + line + "'\n"
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			detail, err := (&NucleiCheck{Executable: script}).RunDetailed(context.Background(), "example.com")
			if err == nil {
				t.Fatal("malformed severity was accepted")
			}
			if detail.Probes[0].Status == "completed" {
				t.Fatalf("malformed output completed probe: %+v", detail.Probes[0])
			}
		})
	}
}

func TestParseNucleiOutputNormalizesValidSeverity(t *testing.T) {
	findings, err := parseNucleiOutput([]byte(`{"template-id":"scaner-example","matched-at":"https://example.com/","info":{"name":"Example","severity":" HIGH "}}`), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != SeverityHigh {
		t.Fatalf("valid severity not normalized: %+v", findings)
	}
}

func TestNucleiCheckRejectsUnnormalizedTarget(t *testing.T) {
	for _, domain := range []string{"https://example.com/path", "example.com/path", "user@example.com", ""} {
		if _, err := (&NucleiCheck{Executable: "/does/not/run"}).RunDetailed(context.Background(), domain); err == nil {
			t.Errorf("expected target %q to be rejected", domain)
		}
	}
}

// Set SCANER_NUCLEI_BIN to run the real engine against a loopback-only TLS
// fixture. This never targets an external host.
func TestNucleiCheckRealBinaryAgainstLocalFixture(t *testing.T) {
	bin := os.Getenv("SCANER_NUCLEI_BIN")
	if bin == "" {
		t.Skip("set SCANER_NUCLEI_BIN to run the local Nuclei integration test")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/server-status" {
			_, _ = w.Write([]byte("Apache Server Status: local fixture"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	domain := strings.TrimPrefix(server.URL, "https://")
	detail, err := (&NucleiCheck{Executable: bin}).RunDetailed(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Probes[0].Status != "completed" || len(detail.Findings) != 1 || detail.Findings[0].ID != "nuclei.scaner-apache-server-status" {
		t.Fatalf("expected the bundled Apache status template to match the local fixture; got %+v", detail)
	}
}
