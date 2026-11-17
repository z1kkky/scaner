package runner

import (
	"context"
	"testing"
	"time"

	"github.com/z1kkky/scaner/internal/check"
)

// fakeCheck — поддельная проверка для теста раннера.
// Она ждёт delay (или отмены контекста) и возвращает одну находку.
type fakeCheck struct {
	name  string
	delay time.Duration
}

func (f fakeCheck) Name() string { return f.name }

func (f fakeCheck) Run(ctx context.Context, domain string) ([]check.Finding, error) {
	// select ждёт, что случится раньше: таймер или отмена контекста.
	select {
	case <-time.After(f.delay):
		return []check.Finding{{CheckName: f.name, Title: "ok"}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// panicCheck падает с паникой — раннер должен это пережить.
type panicCheck struct{}

func (panicCheck) Name() string { return "panic" }
func (panicCheck) Run(context.Context, string) ([]check.Finding, error) {
	panic("бум")
}

func TestRun_ParallelAndTimeout(t *testing.T) {
	checks := []check.Check{
		fakeCheck{name: "b-fast", delay: 50 * time.Millisecond},
		fakeCheck{name: "a-fast", delay: 50 * time.Millisecond},
		fakeCheck{name: "c-slow", delay: 10 * time.Second}, // не уложится в таймаут
		panicCheck{},
	}

	start := time.Now()
	rep := Run(context.Background(), "example.com", checks, 300*time.Millisecond)
	elapsed := time.Since(start)

	// Если бы проверки шли по очереди, ждали бы >10 секунд.
	if elapsed > 2*time.Second {
		t.Fatalf("сканирование заняло %v — проверки не параллельны или таймаут не сработал", elapsed)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("ожидали 4 результата, получили %d", len(rep.Results))
	}

	// Результаты отсортированы по имени.
	want := []string{"a-fast", "b-fast", "c-slow", "panic"}
	for i, r := range rep.Results {
		if r.Check != want[i] {
			t.Errorf("результат %d: ожидали %s, получили %s", i, want[i], r.Check)
		}
	}

	for _, r := range rep.Results[:2] {
		if r.Status != StatusCompleted || r.ErrorCode != "" || len(r.Findings) != 1 {
			t.Errorf("ожидали завершённую проверку с находкой: %+v", r)
		}
	}
	if r := rep.Results[2]; r.Status != StatusFailed || r.ErrorCode != "timeout" || !r.TimedOut || len(r.Findings) != 0 {
		t.Errorf("ожидали таймаут без находок: %+v", r)
	}
	if r := rep.Results[3]; r.Status != StatusFailed || r.ErrorCode != "internal_error" || len(r.Findings) != 0 {
		t.Errorf("ожидали внутреннюю ошибку без находок: %+v", r)
	}
}

func TestRun_FailedHeadersCheck(t *testing.T) {
	checks := []check.Check{&check.HeadersCheck{}}
	rep := Run(context.Background(), "invalid host", checks, time.Second)
	r := rep.Results[0]
	if r.Status != StatusFailed || r.ErrorCode != "check_failed" || len(r.Findings) != 0 {
		t.Errorf("ожидали ошибку проверки заголовков без находок: %+v", r)
	}
}

type detailCheck struct {
	detail check.Detail
	err    error
}

func (detailCheck) Name() string { return "detailed" }
func (d detailCheck) Run(context.Context, string) ([]check.Finding, error) {
	panic("must use detailed method")
}
func (d detailCheck) RunDetailed(context.Context, string) (check.Detail, error) {
	return d.detail, d.err
}

func TestDetailedResultCoverage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probes []check.ProbeResult
		want   Status
		err    error
	}{
		{name: "clean", probes: []check.ProbeResult{{Status: "completed"}}, want: StatusCompleted},
		{name: "not applicable", probes: []check.ProbeResult{{Status: "completed"}, {Status: "skipped"}}, want: StatusCompleted},
		{name: "unknown DKIM", probes: []check.ProbeResult{{Status: "completed"}, {Status: "skipped", CoverageUnknown: true}}, want: StatusIncomplete},
		{name: "failed page", probes: []check.ProbeResult{{Status: "completed"}, {Status: "failed"}}, want: StatusIncomplete, err: context.DeadlineExceeded},
		{name: "all failed", probes: []check.ProbeResult{{Status: "failed"}}, want: StatusFailed},
		{name: "all skipped", probes: []check.ProbeResult{{Status: "skipped"}}, want: StatusSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := check.Detail{Findings: []check.Finding{{ID: "retained"}}, Probes: tc.probes}
			result := runOne(context.Background(), "example.com", detailCheck{detail: d, err: tc.err}, time.Second)
			if result.Status != tc.want || len(result.Probes) != len(tc.probes) || len(result.Findings) != 1 {
				t.Fatalf("bad detailed result: %+v", result)
			}
			if tc.err != nil && (!result.TimedOut || result.ErrorCode != "timeout") {
				t.Fatal(result)
			}
		})
	}
}
