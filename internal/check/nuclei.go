package check

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// These templates are shipped with the scanner instead of loading the
// operator's or upstream's mutable template directory.
//
//go:embed nuclei_templates/*.yaml
var nucleiTemplates embed.FS

const (
	nucleiProbeID        = "nuclei.templates"
	nucleiMaxOutput      = 1 << 20
	nucleiRateLimit      = 2
	nucleiConcurrency    = 1
	nucleiRequestTimeout = 5
)

// NucleiCheck runs only the small, bundled HTTP misconfiguration allowlist.
// The category is never part of the default set; an operator must opt in.
type NucleiCheck struct {
	Executable string
}

func NewNucleiCheck() *NucleiCheck { return &NucleiCheck{Executable: "nuclei"} }
func (*NucleiCheck) Name() string  { return "nuclei" }

func (c *NucleiCheck) Run(ctx context.Context, domain string) ([]Finding, error) {
	detail, err := c.RunDetailed(ctx, domain)
	return detail.Findings, err
}

type nucleiEvent struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func (c *NucleiCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	detail := Detail{Probes: []ProbeResult{{ID: nucleiProbeID, Type: "nuclei_template", Status: "failed", Location: domain}}}
	if strings.ContainsAny(domain, "/?#@ \t\r\n") || domain == "" {
		return detail, errors.New("nuclei requires a normalized bare domain")
	}
	target := "https://" + domain
	u, err := url.Parse(target)
	if err != nil || u.Host != domain || u.User != nil {
		return detail, errors.New("nuclei target must be a normalized domain")
	}
	executable := c.Executable
	if executable == "" {
		executable = "nuclei"
	}
	path, err := exec.LookPath(executable)
	if err != nil {
		return detail, fmt.Errorf("nuclei executable is unavailable: %w", err)
	}
	root, err := os.MkdirTemp("", "scaner-nuclei-")
	if err != nil {
		return detail, fmt.Errorf("prepare isolated nuclei configuration: %w", err)
	}
	defer os.RemoveAll(root)
	if err := writeEmbeddedTemplates(root); err != nil {
		return detail, err
	}
	for _, dir := range []string{"home", "config", "cache"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			return detail, fmt.Errorf("prepare isolated nuclei %s: %w", dir, err)
		}
	}
	targets := filepath.Join(root, "targets.txt")
	if err := os.WriteFile(targets, []byte(target+"\n"), 0o600); err != nil {
		return detail, fmt.Errorf("prepare nuclei target: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := []string{"-list", targets, "-t", filepath.Join(root, "templates"), "-pt", "http", "-jsonl", "-silent", "-no-color", "-omit-raw", "-duc", "-no-interactsh", "-c", fmt.Sprint(nucleiConcurrency), "-rl", fmt.Sprint(nucleiRateLimit), "-timeout", fmt.Sprint(nucleiRequestTimeout), "-retries", "0"}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(root, "home"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_CACHE_HOME=" + filepath.Join(root, "cache")}
	var output boundedBuffer
	output.limit = nucleiMaxOutput
	var stderr boundedBuffer
	stderr.limit = 64 << 10
	cmd.Stdout, cmd.Stderr = &output, &stderr
	err = cmd.Run()
	if output.exceeded || stderr.exceeded {
		return detail, errors.New("nuclei output exceeded a safety limit")
	}
	if err != nil {
		return detail, fmt.Errorf("nuclei scan failed: %w", err)
	}
	findings, err := parseNucleiOutput(output.Bytes(), domain)
	if err != nil {
		return detail, err
	}
	detail.Findings = findings
	detail.Probes[0].Status = "completed"
	return detail, nil
}

func writeEmbeddedTemplates(root string) error {
	if err := os.Mkdir(filepath.Join(root, "templates"), 0o700); err != nil {
		return fmt.Errorf("prepare bundled nuclei templates: %w", err)
	}
	entries, err := fs.Glob(nucleiTemplates, "nuclei_templates/*.yaml")
	if err != nil {
		return err
	}
	for _, name := range entries {
		data, err := nucleiTemplates.ReadFile(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "templates", filepath.Base(name)), data, 0o600); err != nil {
			return fmt.Errorf("write bundled nuclei template: %w", err)
		}
	}
	return nil
}

func parseNucleiOutput(raw []byte, domain string) ([]Finding, error) {
	var findings []Finding
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		var event nucleiEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("parse nuclei JSONL output: %w", err)
		}
		if event.TemplateID == "" || event.Info.Name == "" || event.MatchedAt == "" {
			return nil, errors.New("nuclei returned a finding with missing required fields")
		}
		severity := Severity(strings.ToLower(strings.TrimSpace(event.Info.Severity)))
		if severity != SeverityInfo && severity != SeverityLow && severity != SeverityMedium && severity != SeverityHigh && severity != SeverityCritical {
			return nil, fmt.Errorf("nuclei returned unsupported severity %q", event.Info.Severity)
		}
		findings = append(findings, Finding{
			CheckName: "nuclei", ID: "nuclei." + event.TemplateID, ProbeID: nucleiProbeID,
			Probe: "nuclei_template", Location: event.MatchedAt, Severity: severity,
			Title: event.Info.Name, Description: "Результат проверки по встроенному allowlist-шаблону Nuclei.",
			Fix:      "Проверьте результат вручную и устраните подтверждённую причину.",
			Evidence: "Шаблон " + event.TemplateID + " сработал для " + domain + ".",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read nuclei JSONL output: %w", err)
	}
	return findings, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return n, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
