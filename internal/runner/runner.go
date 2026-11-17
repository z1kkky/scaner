// Пакет runner запускает все проверки параллельно и собирает результаты.
package runner

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/z1kkky/scaner/internal/check"
)

// Result — итог одной проверки.
type Result struct {
	Check      string          `json:"check"`
	Findings   []check.Finding `json:"findings"`
	DurationMs int64           `json:"duration_ms"`
	TimedOut   bool            `json:"timed_out,omitempty"` // omitempty: не писать поле, если false
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

	// range по каналу читает значения, пока канал не закроют.
	var all []Result
	for r := range results {
		all = append(all, r)
	}

	// Горутины финишируют в случайном порядке — сортируем,
	// чтобы отчёт всегда выглядел одинаково.
	sort.Slice(all, func(i, j int) bool { return all[i].Check < all[j].Check })

	return Report{
		Domain:     domain,
		StartedAt:  started.UTC(),
		DurationMs: time.Since(started).Milliseconds(),
		Results:    all,
	}
}

// runOne выполняет одну проверку со своим таймаутом.
func runOne(parent context.Context, domain string, c check.Check, timeout time.Duration) (res Result) {
	start := time.Now()
	res.Check = c.Name()

	// WithTimeout создаёт дочерний контекст, который сам отменится
	// через timeout. cancel() нужно вызвать всегда — освобождает ресурсы.
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	// recover ловит панику (аварийное падение) внутри проверки.
	// Без этого ошибка в одной проверке уронила бы весь сканер.
	defer func() {
		if p := recover(); p != nil {
			res.Findings = []check.Finding{{
				CheckName:   c.Name(),
				Title:       "Внутренняя ошибка проверки",
				Severity:    check.SeverityInfo,
				Description: fmt.Sprint(p),
			}}
		}
		res.DurationMs = time.Since(start).Milliseconds()
	}()

	res.Findings = c.Run(ctx, domain)
	if res.Findings == nil {
		// Пустой срез вместо nil, чтобы в JSON было [] а не null.
		res.Findings = []check.Finding{}
	}
	// Если дедлайн истёк, отметим это — результат может быть неполным.
	res.TimedOut = ctx.Err() == context.DeadlineExceeded
	return res
}
