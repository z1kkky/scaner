// Пакет runner запускает все проверки параллельно и собирает результаты.
package runner

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/z1kkky/scaner/internal/check"
)

type Status string

const (
	StatusCompleted  Status = "completed"
	StatusIncomplete Status = "incomplete"
	StatusFailed     Status = "failed"
	StatusSkipped    Status = "skipped"
)

// Result — итог одной проверки.
type Result struct {
	Probes     []check.ProbeResult `json:"probes,omitempty"`
	Check      string              `json:"check"`
	Findings   []check.Finding     `json:"findings"`
	DurationMs int64               `json:"duration_ms"`
	TimedOut   bool                `json:"timed_out,omitempty"` // omitempty: не писать поле, если false
	Status     Status              `json:"status"`
	ErrorCode  string              `json:"error_code,omitempty"`
}

// Report — итог сканирования домена целиком.
type Report struct {
	Domain     string    `json:"domain"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	Results    []Result  `json:"results"`
}

// Run запускает каждую проверку в своей горутине и ждёт, пока все закончат.
//
// Горутина — это очень лёгкий «поток»: go f() запускает f параллельно
// с остальным кодом. Их можно запускать тысячами.
//
// timeout — сколько времени даём КАЖДОЙ проверке.
func Run(ctx context.Context, domain string, checks []check.Check, timeout time.Duration) Report {
	started := time.Now()
	var all []Result
	for result := range Stream(ctx, domain, checks, timeout) {
		all = append(all, result)
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Check < all[j].Check })
	return Report{
		Domain:     domain,
		StartedAt:  started.UTC(),
		DurationMs: time.Since(started).Milliseconds(),
		Results:    all,
	}
}

// Stream запускает проверки параллельно и выдаёт результаты по мере готовности.
// Отмена ctx передаётся всем запущенным проверкам.
func Stream(ctx context.Context, domain string, checks []check.Check, timeout time.Duration) <-chan Result {
	// Канал — «труба», по которой горутины безопасно передают данные.
	// Буфер размером len(checks): каждая горутина сможет положить результат
	// и завершиться, не дожидаясь, пока его заберут.
	results := make(chan Result, len(checks))

	// WaitGroup — счётчик запущенных горутин. Add(1) перед запуском,
	// Done() по завершении, Wait() ждёт, пока счётчик станет нулём.
	var wg sync.WaitGroup

	for _, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- runOne(ctx, domain, c, timeout) // кладём результат в канал
		}()
	}

	// Отдельная горутина ждёт всех и закрывает канал.
	// Закрытый канал — сигнал для цикла ниже: «больше ничего не будет».
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// runOne выполняет одну проверку со своим таймаутом.
func runOne(parent context.Context, domain string, c check.Check, timeout time.Duration) (res Result) {
	start := time.Now()
	res.Check = c.Name()

	// WithTimeout создаёт дочерний контекст, который сам отменится
	// через timeout. cancel() нужно вызвать всегда — освобождает ресурсы.
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	res.Status = StatusFailed
	res.Findings = []check.Finding{}
	defer func() {
		if recover() != nil {
			res.ErrorCode = "internal_error"
		}
		res.DurationMs = time.Since(start).Milliseconds()
	}()

	var findings []check.Finding
	var err error
	if detailed, ok := c.(check.DetailedCheck); ok {
		var detail check.Detail
		detail, err = detailed.RunDetailed(ctx, domain)
		findings, res.Probes = detail.Findings, detail.Probes
	} else {
		findings, err = c.Run(ctx, domain)
	}
	// Preserve useful results even when the category deadline expires.
	res.Findings = findings
	if res.Findings == nil {
		res.Findings = []check.Finding{}
	}

	switch {
	case ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded):
		res.TimedOut = true
		res.ErrorCode = "timeout"
	case ctx.Err() == context.Canceled || errors.Is(err, context.Canceled):
		res.ErrorCode = "canceled"
	case err != nil:
		res.ErrorCode = "check_failed"
	default:
		res.Status = StatusCompleted
		if findings != nil {
			res.Findings = findings
		}
	}
	if len(res.Probes) > 0 {
		completed, failed, skipped, unknown := 0, 0, 0, 0
		for _, p := range res.Probes {
			switch p.Status {
			case "completed":
				completed++
			case "failed":
				failed++
			case "skipped":
				skipped++
				if p.CoverageUnknown {
					unknown++
				}
			}
		}
		switch {
		case completed > 0 && completed+skipped == len(res.Probes) && unknown == 0:
			res.Status = StatusCompleted
		case skipped == len(res.Probes):
			res.Status = StatusSkipped
		case failed == len(res.Probes):
			res.Status = StatusFailed
		default:
			res.Status = StatusIncomplete
		}
		if res.Status == StatusIncomplete && (res.ErrorCode == "" || res.ErrorCode == "check_failed") {
			res.ErrorCode = "partial_coverage"
		}
		if res.Status == StatusFailed && res.ErrorCode == "" {
			res.ErrorCode = "check_failed"
		}
	}
	return res
}
