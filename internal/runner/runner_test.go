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

func (f fakeCheck) Run(ctx context.Context, domain string) []check.Finding {
	// select ждёт, что случится раньше: таймер или отмена контекста.
	select {
	case <-time.After(f.delay):
		return []check.Finding{{CheckName: f.name, Title: "ok"}}
	case <-ctx.Done():
		return nil
	}
}

// panicCheck падает с паникой — раннер должен это пережить.
type panicCheck struct{}

func (panicCheck) Name() string                                { return "panic" }
func (panicCheck) Run(context.Context, string) []check.Finding { panic("бум") }

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

	if !rep.Results[2].TimedOut {
		t.Error("медленная проверка должна быть помечена timed_out")
	}
	if len(rep.Results[3].Findings) != 1 || rep.Results[3].Findings[0].Title != "Внутренняя ошибка проверки" {
		t.Errorf("паника не превратилась в находку: %+v", rep.Results[3])
	}
}
