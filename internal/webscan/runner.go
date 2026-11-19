// Package webscan composes the existing guarded scanner checks with the
// disposable Nuclei runner for verified web jobs.
package webscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/runner"
	"github.com/z1kkky/scaner/internal/targetscope"
	"github.com/z1kkky/scaner/internal/web"
)

type checkFactory func(*targetscope.Policy) []check.Check

// Config injects the isolated Nuclei runner. Checks is private to tests; the
// production constructor always uses the repository's guarded default set.
type Config struct {
	Nuclei  web.Runner
	Timeout time.Duration
	checks  checkFactory
}

type Runner struct {
	nuclei  web.Runner
	timeout time.Duration
	checks  checkFactory
}

func New(cfg Config) *Runner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.checks == nil {
		cfg.checks = func(policy *targetscope.Policy) []check.Check {
			return check.NewDefaultChecks(check.DefaultChecksOptions{TargetPolicy: policy})
		}
	}
	return &Runner{nuclei: cfg.Nuclei, timeout: cfg.Timeout, checks: cfg.checks}
}

// Reconcile forwards startup container recovery to the isolated Nuclei runner.
// A missing optional Nuclei runner owns no containers to reconcile.
func (r *Runner) Reconcile(ctx context.Context, ownerID string) error {
	if reconciler, ok := r.nuclei.(web.ContainerReconciler); ok {
		return reconciler.Reconcile(ctx, ownerID)
	}
	return nil
}

// LiveReady propagates sticky cleanup failures from the container runner.
func (r *Runner) LiveReady() error {
	if readiness, ok := r.nuclei.(web.LiveReadiness); ok {
		return readiness.LiveReady()
	}
	return nil
}

type HostReport struct {
	Host       string          `json:"host"`
	Categories []runner.Result `json:"categories"`
}

type NucleiReport struct {
	Status   string          `json:"status"`
	Engine   string          `json:"engine,omitempty"`
	Findings []check.Finding `json:"findings"`
	Error    string          `json:"error,omitempty"`
}

type Report struct {
	Status   string          `json:"status"`
	Hosts    []HostReport    `json:"hosts"`
	Nuclei   NucleiReport    `json:"nuclei"`
	Findings []check.Finding `json:"findings"`
}

type nucleiEnvelope struct {
	Engine   string          `json:"engine"`
	Findings json.RawMessage `json:"findings"`
}

type nucleiFinding struct {
	TemplateID string `json:"template_id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
}

const expectedNucleiEngine = "Nuclei v3.11.1"

func (r *Runner) Run(ctx context.Context, req web.ScanRequest) (json.RawMessage, error) {
	if !req.Authorized {
		return nil, errors.New("written authorization attestation required")
	}
	if req.Policy == nil || req.Policy.Root() == "" || len(req.Hosts) == 0 {
		return nil, errors.New("frozen target policy and explicit hosts required")
	}
	policyHosts := req.Policy.Hosts()
	for _, host := range req.Hosts {
		if !contains(policyHosts, host) {
			return nil, fmt.Errorf("host %q is outside frozen target policy", host)
		}
	}

	report := Report{Status: "completed", Hosts: make([]HostReport, 0, len(req.Hosts)), Findings: []check.Finding{}}
	for _, host := range req.Hosts {
		if err := ctx.Err(); err != nil {
			report.Status = "incomplete"
			break
		}
		checks := r.checks(req.Policy)
		result := runner.Run(ctx, host, checks, r.timeout)
		report.Hosts = append(report.Hosts, HostReport{Host: host, Categories: result.Results})
		for _, category := range result.Results {
			report.Findings = append(report.Findings, category.Findings...)
			if category.Status != runner.StatusCompleted {
				report.Status = "incomplete"
			}
		}
	}

	report.Nuclei = NucleiReport{Status: "failed", Findings: []check.Finding{}}
	if r.nuclei == nil {
		report.Nuclei.Error = "container Nuclei runner is not configured"
		report.Status = "incomplete"
	} else if ctx.Err() != nil {
		report.Nuclei.Status = "cancelled"
		report.Nuclei.Error = ctx.Err().Error()
		report.Status = "incomplete"
	} else {
		raw, err := r.nuclei.Run(ctx, req)
		envelope, findings, parseErr := parseNucleiEnvelope(raw)
		if parseErr == nil {
			report.Nuclei.Engine = envelope.Engine
			for _, finding := range findings {
				mapped := check.Finding{
					CheckName: "nuclei", ID: "nuclei." + finding.TemplateID,
					ProbeID: "nuclei." + finding.TemplateID, Probe: "nuclei_template",
					Location: finding.MatchedAt, Severity: check.Severity(strings.ToLower(strings.TrimSpace(finding.Severity))),
					Title: finding.Title, Description: "Результат проверки по встроенному allowlist-шаблону Nuclei.",
					Fix: "Проверьте результат вручную и устраните подтверждённую причину.", Evidence: "Шаблон " + finding.TemplateID + " сработал для " + finding.MatchedAt + ".",
				}
				report.Nuclei.Findings = append(report.Nuclei.Findings, mapped)
				report.Findings = append(report.Findings, mapped)
			}
		}
		if err != nil || parseErr != nil {
			report.Nuclei.Status = "failed"
			report.Nuclei.Error = errors.Join(err, parseErr).Error()
			report.Status = "incomplete"
		} else {
			report.Nuclei.Status = "completed"
		}
	}

	data, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode web scan report: %w", err)
	}
	if report.Status != "completed" {
		return data, errors.New("scan report is incomplete; review category status and coverage")
	}
	return data, nil
}

func parseNucleiEnvelope(raw []byte) (nucleiEnvelope, []nucleiFinding, error) {
	var envelope nucleiEnvelope
	if len(raw) == 0 {
		return envelope, nil, errors.New("Nuclei runner returned an empty report")
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return envelope, nil, fmt.Errorf("invalid Nuclei report: %w", err)
	}
	if envelope.Engine != expectedNucleiEngine {
		return envelope, nil, fmt.Errorf("unexpected Nuclei engine %q; require %q", envelope.Engine, expectedNucleiEngine)
	}
	findingsJSON := bytes.TrimSpace(envelope.Findings)
	if len(findingsJSON) == 0 || findingsJSON[0] != '[' {
		return envelope, nil, errors.New("Nuclei report must include a findings array")
	}
	var findings []nucleiFinding
	if err := json.Unmarshal(findingsJSON, &findings); err != nil {
		return envelope, nil, fmt.Errorf("invalid Nuclei findings: %w", err)
	}
	for i, finding := range findings {
		if strings.TrimSpace(finding.TemplateID) == "" || strings.TrimSpace(finding.Title) == "" || strings.TrimSpace(finding.MatchedAt) == "" {
			return envelope, nil, fmt.Errorf("Nuclei finding %d is missing required fields", i)
		}
		switch check.Severity(strings.ToLower(strings.TrimSpace(finding.Severity))) {
		case check.SeverityInfo, check.SeverityLow, check.SeverityMedium, check.SeverityHigh, check.SeverityCritical:
		default:
			return envelope, nil, fmt.Errorf("Nuclei finding %d has unsupported severity %q", i, finding.Severity)
		}
	}
	return envelope, findings, nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
