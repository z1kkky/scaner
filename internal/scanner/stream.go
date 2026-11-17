package scanner

import (
	"context"
	"errors"
	"time"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/runner"
)

type Request struct {
	ScanID        string
	Domain        string
	Checks        []string
	PagePaths     []string
	DKIMSelectors []string
}

type Started struct {
	Checks    []string
	StartedAt time.Time
}

type SummaryStatus string

const (
	SummaryCompleted SummaryStatus = "completed"
	SummaryPartial   SummaryStatus = "partial"
	SummaryFailed    SummaryStatus = "failed"
)

type Summary struct {
	Status          SummaryStatus
	CompletedChecks int
	RequestedChecks int
	FinishedAt      time.Time
}

type Event struct {
	ScanID    string
	Sequence  uint64
	Started   *Started
	CheckDone *runner.Result
	Finished  *Summary
}

// Run отправляет события сканирования. send вызывается последовательно.
// Имена запрошенных категорий передаются после проверки транспортом.
func Run(ctx context.Context, req Request, available []check.Check, timeout time.Duration, send func(Event) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if req.ScanID == "" || req.Domain == "" {
		return errors.New("scan_id and domain are required")
	}

	byName := make(map[string]check.Check, len(available))
	defaultNames := make([]string, 0, len(available))
	for _, c := range available {
		if configurable, ok := c.(check.Configurable); ok {
			c = configurable.WithOptions(check.Options{PagePaths: req.PagePaths, DKIMSelectors: req.DKIMSelectors})
		}
		name := c.Name()
		byName[name] = c
		defaultNames = append(defaultNames, name)
	}
	names := req.Checks
	if len(names) == 0 {
		names = defaultNames
	}

	var selected []check.Check
	var skipped []string
	actual := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		actual = append(actual, name)
		if c, ok := byName[name]; ok {
			selected = append(selected, c)
		} else {
			skipped = append(skipped, name)
		}
	}

	var sequence uint64
	emit := func(event Event) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		sequence++
		event.ScanID = req.ScanID
		event.Sequence = sequence
		return send(event)
	}
	if err := emit(Event{Started: &Started{Checks: actual, StartedAt: time.Now().UTC()}}); err != nil {
		return err
	}
	results := runner.Stream(ctx, req.Domain, selected, timeout)
	for _, name := range skipped {
		result := runner.Result{Check: name, Status: runner.StatusSkipped, Findings: []check.Finding{}}
		if err := emit(Event{CheckDone: &result}); err != nil {
			return err
		}
	}

	summary := Summary{RequestedChecks: len(actual)}
	var failed int
	for range selected {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-results:
			if result.Status == runner.StatusCompleted {
				summary.CompletedChecks++
			}
			if result.Status == runner.StatusFailed {
				failed++
			}
			if err := emit(Event{CheckDone: &result}); err != nil {
				return err
			}
		}
	}

	switch {
	case summary.RequestedChecks == 0, failed == summary.RequestedChecks:
		summary.Status = SummaryFailed
	case summary.CompletedChecks == summary.RequestedChecks:
		summary.Status = SummaryCompleted
	default:
		summary.Status = SummaryPartial
	}
	summary.FinishedAt = time.Now().UTC()
	return emit(Event{Finished: &summary})
}
