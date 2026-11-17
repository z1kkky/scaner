package scanner

import (
	"testing"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/runner"
)

func TestCalculateScoreUsesHighestSeverityPerRule(t *testing.T) {
	results := []runner.Result{
		{Check: "headers", Status: runner.StatusCompleted, Findings: []check.Finding{
			{ID: "headers.missing_csp", Severity: check.SeverityMedium},
			{ID: "headers.missing_csp", Severity: check.SeverityMedium, Location: "/login"},
			{ID: "headers.missing_csp", Severity: check.SeverityLow, Location: "/about"},
			{ID: "headers.missing_hsts", Severity: check.SeverityHigh},
			{ID: "cms.detected_wordpress", Severity: check.SeverityInfo},
		}},
		{Check: "tls", Status: runner.StatusCompleted},
	}

	score, grade := calculateScore(results)
	if score == nil || *score != 70 || grade != "C" {
		t.Fatalf("calculateScore() = (%v, %q), want (70, C)", score, grade)
	}
}

func TestCalculateScoreClampsAndMapsGradeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		findings int
		want     int32
		grade    string
	}{
		{0, 100, "A"},
		{1, 65, "D"},
		{2, 30, "F"},
	} {
		findings := make([]check.Finding, tc.findings)
		for i := range findings {
			findings[i] = check.Finding{ID: string(rune('a' + i)), Severity: check.SeverityCritical}
		}
		score, grade := calculateScore([]runner.Result{{Check: "tls", Status: runner.StatusCompleted, Findings: findings}})
		if score == nil || *score != tc.want || grade != tc.grade {
			t.Errorf("%d critical findings: got (%v, %q), want (%d, %q)", tc.findings, score, grade, tc.want, tc.grade)
		}
	}
}

func TestCalculateScoreOmitsUnknownOrIncompleteResults(t *testing.T) {
	for _, result := range []runner.Result{
		{Check: "tls", Status: runner.StatusIncomplete},
		{Check: "tls", Status: runner.StatusCompleted, Findings: []check.Finding{{ID: "unknown", Severity: "unexpected"}}},
	} {
		if score, grade := calculateScore([]runner.Result{result}); score != nil || grade != "" {
			t.Errorf("calculateScore(%+v) = (%v, %q), want no score", result, score, grade)
		}
	}
}

func TestFullCheckSetRequiresEveryAvailableCategory(t *testing.T) {
	available := []string{"tls", "headers", "email"}
	for _, tc := range []struct {
		requested []string
		want      bool
	}{
		{[]string{"tls", "headers", "email"}, true},
		{[]string{"tls", "headers"}, false},
		{[]string{"tls", "headers", "nuclei"}, false},
	} {
		if got := fullCheckSet(tc.requested, available); got != tc.want {
			t.Errorf("fullCheckSet(%v) = %v, want %v", tc.requested, got, tc.want)
		}
	}
}
