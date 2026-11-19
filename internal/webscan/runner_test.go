package webscan

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/targetscope"
	"github.com/z1kkky/scaner/internal/web"
)

type fakeResolver struct{}

func (fakeResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host, nil
}
func (fakeResolver) LookupCNAMEChain(_ context.Context, host string) ([]string, error) {
	return []string{host}, nil
}
func (fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}
func (fakeResolver) ResolveTarget(_ context.Context, host string) ([]string, []netip.Addr, error) {
	return []string{host}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type fakeNuclei struct {
	result json.RawMessage
	err    error
	got    web.ScanRequest
}

func (r *fakeNuclei) Run(_ context.Context, req web.ScanRequest) (json.RawMessage, error) {
	r.got = req
	return r.result, r.err
}

type recoveryNuclei struct {
	owner string
	err   error
}

func (*recoveryNuclei) Run(context.Context, web.ScanRequest) (json.RawMessage, error) {
	return nil, nil
}
func (n *recoveryNuclei) Reconcile(_ context.Context, owner string) error {
	n.owner = owner
	return n.err
}
func (n *recoveryNuclei) LiveReady() error { return n.err }

func TestRunnerForwardsContainerRecoveryAndReadiness(t *testing.T) {
	nuclei := &recoveryNuclei{}
	r := New(Config{Nuclei: nuclei})
	const owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := r.Reconcile(context.Background(), owner); err != nil {
		t.Fatalf("reconcile forwarding: %v", err)
	}
	if nuclei.owner != owner {
		t.Fatalf("reconcile owner = %q, want %q", nuclei.owner, owner)
	}
	nuclei.err = errors.New("cleanup failed")
	if err := r.LiveReady(); !errors.Is(err, nuclei.err) {
		t.Fatalf("container readiness failure was lost: %v", err)
	}
}

type findingCheck struct{}

func (c findingCheck) Name() string { return "headers" }
func (c findingCheck) Run(_ context.Context, domain string) ([]check.Finding, error) {
	return []check.Finding{{CheckName: "headers", Title: "header finding on " + domain, Severity: check.SeverityLow}}, nil
}

func frozenPolicy(t *testing.T, hosts []string) *targetscope.Policy {
	t.Helper()
	policy, err := targetscope.Freeze(context.Background(), fakeResolver{}, "example.test", hosts, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestRunnerRunsGuardedChecksForEachSelectedHostWithSamePolicy(t *testing.T) {
	policy := frozenPolicy(t, []string{"example.test", "api.example.test"})
	var policies []*targetscope.Policy
	nuclei := &fakeNuclei{result: json.RawMessage(`{"engine":"Nuclei v3.11.1","findings":[]}`)}
	r := New(Config{Nuclei: nuclei, checks: func(got *targetscope.Policy) []check.Check {
		policies = append(policies, got)
		return []check.Check{findingCheck{}}
	}})
	request := web.ScanRequest{Root: "example.test", Hosts: []string{"example.test", "api.example.test"}, Ports: []uint16{443}, Policy: policy, Authorized: true}
	raw, err := r.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("run web checks: %v", err)
	}
	if len(policies) != 2 || policies[0] != policy || policies[1] != policy {
		t.Fatalf("checks did not receive the same frozen policy: %#v", policies)
	}
	if nuclei.got.Policy != policy || !nuclei.got.Authorized {
		t.Fatalf("Nuclei did not receive the same authorized request policy: %+v", nuclei.got)
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(report.Hosts) != 2 || report.Hosts[0].Host != "example.test" || report.Hosts[1].Host != "api.example.test" {
		t.Fatalf("selected hosts were not both checked: %+v", report.Hosts)
	}
	for _, host := range report.Hosts {
		if len(host.Categories) != 1 || len(host.Categories[0].Findings) != 1 {
			t.Fatalf("missing category result for %s: %+v", host.Host, host.Categories)
		}
	}
}

func TestRunnerKeepsFindingsWhenNucleiFails(t *testing.T) {
	policy := frozenPolicy(t, []string{"example.test"})
	nuclei := &fakeNuclei{result: json.RawMessage(`{"engine":"Nuclei v3.11.1","findings":[]}`), err: errors.New("Docker unavailable")}
	r := New(Config{Nuclei: nuclei, checks: func(*targetscope.Policy) []check.Check { return []check.Check{findingCheck{}} }})
	request := web.ScanRequest{Root: "example.test", Hosts: []string{"example.test"}, Ports: []uint16{443}, Policy: policy, Authorized: true}
	raw, err := r.Run(context.Background(), request)
	if err == nil {
		t.Fatal("Nuclei failure was reported as a clean scan")
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode partial report: %v", err)
	}
	if report.Status != "incomplete" || report.Nuclei.Status != "failed" || report.Nuclei.Error == "" {
		t.Fatalf("Nuclei failure status was lost: %+v", report)
	}
	if len(report.Findings) != 1 || report.Findings[0].Title != "header finding on example.test" {
		t.Fatalf("pre-failure scanner findings were lost: %+v", report.Findings)
	}
}

func TestRunnerRejectsMalformedNucleiReportsWithoutLosingOtherFindings(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "empty", raw: nil},
		{name: "missing engine", raw: json.RawMessage(`{"findings":[]}`)},
		{name: "wrong engine", raw: json.RawMessage(`{"engine":"Nuclei v3.10.0","findings":[]}`)},
		{name: "missing findings", raw: json.RawMessage(`{"engine":"Nuclei v3.11.1"}`)},
		{name: "findings is null", raw: json.RawMessage(`{"engine":"Nuclei v3.11.1","findings":null}`)},
		{name: "unknown severity", raw: json.RawMessage(`{"engine":"Nuclei v3.11.1","findings":[{"template_id":"t","title":"name","severity":"mystery","matched_at":"https://example.test/"}]}`)},
		{name: "missing severity", raw: json.RawMessage(`{"engine":"Nuclei v3.11.1","findings":[{"template_id":"t","title":"name","matched_at":"https://example.test/"}]}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := frozenPolicy(t, []string{"example.test"})
			nuclei := &fakeNuclei{result: tc.raw}
			r := New(Config{Nuclei: nuclei, checks: func(*targetscope.Policy) []check.Check {
				return []check.Check{findingCheck{}}
			}})
			request := web.ScanRequest{Root: "example.test", Hosts: []string{"example.test"}, Ports: []uint16{443}, Policy: policy, Authorized: true}
			raw, err := r.Run(context.Background(), request)
			if err == nil {
				t.Fatal("malformed Nuclei output was reported as a clean scan")
			}
			var report Report
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("decode incomplete report: %v", err)
			}
			if report.Status != "incomplete" || report.Nuclei.Status != "failed" || report.Nuclei.Error == "" {
				t.Fatalf("malformed Nuclei output was not marked failed/incomplete: %+v", report)
			}
			if len(report.Findings) != 1 || report.Findings[0].Title != "header finding on example.test" {
				t.Fatalf("ordinary scanner findings were lost: %+v", report.Findings)
			}
		})
	}
}

func TestRunnerAcceptsValidCleanNucleiReport(t *testing.T) {
	policy := frozenPolicy(t, []string{"example.test"})
	nuclei := &fakeNuclei{result: json.RawMessage(`{"engine":"Nuclei v3.11.1","findings":[]}`)}
	r := New(Config{Nuclei: nuclei, checks: func(*targetscope.Policy) []check.Check {
		return []check.Check{findingCheck{}}
	}})
	request := web.ScanRequest{Root: "example.test", Hosts: []string{"example.test"}, Ports: []uint16{443}, Policy: policy, Authorized: true}
	raw, err := r.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("valid empty Nuclei findings should complete: %v", err)
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Status != "completed" || report.Nuclei.Status != "completed" || len(report.Nuclei.Findings) != 0 {
		t.Fatalf("valid clean Nuclei report not accepted: %+v", report)
	}
}
