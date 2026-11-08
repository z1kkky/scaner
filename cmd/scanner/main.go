// Команда scanner — CLI для запуска проверок вручную.
//
// Использование:
//
//	go run ./cmd/scanner example.com
//	go run ./cmd/scanner -timeout 20s example.com
//
// Результат печатается в JSON. Позже тот же раннер будет вызываться
// из gRPC-сервиса, а CLI останется для отладки.
//
// ВАЖНО: сканируйте только свои домены или домены, владелец которых
// дал согласие. В веб-сервисе владение будет проверяться через DNS/файл.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/runner"
)

func main() {
	// flag разбирает аргументы командной строки вида -timeout 20s.
	timeout := flag.Duration("timeout", 10*time.Second, "таймаут на каждую проверку")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Использование: scanner [-timeout 10s] <домен>")
		flag.PrintDefaults()
	}
	flag.Parse()

	// flag.Args() — то, что осталось после флагов, т.е. домен.
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	domain, err := normalizeDomain(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(2)
	}

	// Список проверок. Новую проверку добавляем сюда одной строкой.
	checks := []check.Check{
		&check.HeadersCheck{},
	}

	// Ctrl+C отменит контекст, и все проверки аккуратно остановятся.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	report := runner.Run(ctx, domain, checks, *timeout)

	// Печатаем отчёт красиво, с отступами.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // не превращать < > & в < и т.п.
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка вывода:", err)
		os.Exit(1)
	}
}

// normalizeDomain превращает "https://Example.com/path" в "example.com".
// Пользователи часто вставляют URL целиком — прощаем это.
func normalizeDomain(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	// Отрезаем всё после первого '/', '?' или '#'.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.ContainsAny(s, " @") {
		return "", fmt.Errorf("некорректный домен")
	}
	return s, nil
}
