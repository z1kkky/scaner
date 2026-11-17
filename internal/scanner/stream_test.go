package scanner

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/runner"
)

type testCheck struct {
	name string
	run  func(context.Context) error
}

func (c testCheck) Name() string { return c.name }

func (c testCheck) Run(ctx context.Context, _ string) ([]check.Finding, error) {
	return nil, c.run(ctx)
}

func TestRunStreamsResultsBeforeOtherChecksFinish(t *testing.T) {
	release := make(chan struct{})
	checks := []check.Check{
		testCheck{"tls", func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}},
		testCheck{"headers", func(context.Context) error { return nil }},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var events []Event
	err := Run(ctx, Request{ScanID: "test", Domain: "example.com"}, checks, time.Second, func(event Event) error {
		events = append(events, event)
		if event.CheckDone != nil && event.CheckDone.Check == "headers" {
			close(release)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("ожидали четыре события, получили %+v", events)
	}
	for i, event := range events {
		if event.ScanID != "test" || event.Sequence != uint64(i+1) {
			t.Fatalf("неверный идентификатор или номер события: %+v", event)
		}
	}
	if started := events[0].Started; started == nil || !reflect.DeepEqual(started.Checks, []string{"tls", "headers"}) {
		t.Fatalf("неверное первое событие: %+v", started)
	}
	for i, name := range []string{"headers", "tls"} {
		if result := events[i+1].CheckDone; result == nil || result.Check != name || result.Status != runner.StatusCompleted {
			t.Fatalf("ожидали завершённую проверку %q, получили %+v", name, result)
		}
	}
	if summary := events[3].Finished; summary == nil || summary.Status != SummaryCompleted || summary.CompletedChecks != 2 || summary.RequestedChecks != 2 {
		t.Fatalf("неверный итог: %+v", summary)
	}
}

func TestRunSkippedAndFailedChecks(t *testing.T) {
	checks := []check.Check{testCheck{"headers", func(context.Context) error { return errors.New("request failed") }}}
	req := Request{ScanID: "test", Domain: "example.com", Checks: []string{"headers", "email", "email"}}
	var events []Event
	err := Run(context.Background(), req, checks, time.Second, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil || len(events) != 4 {
		t.Fatalf("ожидали четыре события без ошибки, получили %+v, %v", events, err)
	}
	if result := events[1].CheckDone; result == nil || result.Check != "email" || result.Status != runner.StatusSkipped {
		t.Fatalf("ожидали пропущенную проверку email, получили %+v", result)
	}
	if result := events[2].CheckDone; result == nil || result.Check != "headers" || result.Status != runner.StatusFailed {
		t.Fatalf("ожидали сбой проверки headers, получили %+v", result)
	}
	if summary := events[3].Finished; summary == nil || summary.Status != SummaryPartial || summary.CompletedChecks != 0 || summary.RequestedChecks != 2 {
		t.Fatalf("неверный итог: %+v", summary)
	}
}

func TestRunCancelsChecksWhenSendingFails(t *testing.T) {
	stopped := make(chan struct{})
	checks := []check.Check{
		testCheck{"tls", func(ctx context.Context) error {
			<-ctx.Done()
			close(stopped)
			return ctx.Err()
		}},
		testCheck{"headers", func(context.Context) error { return nil }},
	}
	req := Request{ScanID: "test", Domain: "example.com"}
	sendErr := errors.New("connection lost")
	err := Run(context.Background(), req, checks, time.Minute, func(event Event) error {
		if event.CheckDone != nil {
			return sendErr
		}
		return nil
	})
	if !errors.Is(err, sendErr) {
		t.Fatalf("ожидали ошибку отправки, получили %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("проверка не получила отмену контекста")
	}
}
