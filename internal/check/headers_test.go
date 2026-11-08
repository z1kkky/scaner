package check

// Тесты в Go лежат рядом с кодом в файлах *_test.go.
// Запуск: go test ./...
// Каждая функция TestXxx(t *testing.T) — отдельный тест.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer поднимает локальный HTTPS-сервер, который отвечает
// с заданными заголовками. Никакого реального интернета — тест быстрый
// и не зависит от чужих сайтов.
func newTestServer(t *testing.T, headers map[string]string) (*httptest.Server, string) {
	t.Helper() // при ошибке Go покажет строку в тесте, а не здесь
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close) // закрыть сервер, когда тест закончится

	// srv.URL выглядит как "https://127.0.0.1:41234" — отрезаем схему,
	// получаем то, что проверка ожидает как «домен».
	domain := strings.TrimPrefix(srv.URL, "https://")
	return srv, domain
}

func runHeaders(t *testing.T, headers map[string]string) []Finding {
	t.Helper()
	srv, domain := newTestServer(t, headers)
	// srv.Client() доверяет самоподписанному сертификату тестового сервера.
	c := &HeadersCheck{Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.Run(ctx, domain)
}

func TestHeaders_AllGood(t *testing.T) {
	findings := runHeaders(t, map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
	})
	if len(findings) != 0 {
		t.Fatalf("ожидали 0 проблем, получили %d: %+v", len(findings), findings)
	}
}

func TestHeaders_AllMissing(t *testing.T) {
	findings := runHeaders(t, nil)
	if len(findings) != 4 {
		t.Fatalf("ожидали 4 проблемы, получили %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.CheckName != "headers" || f.Fix == "" {
			t.Errorf("неполная находка: %+v", f)
		}
	}
}

// Табличный тест — типичный приём в Go: много случаев в одном цикле.
func TestHeaders_Cases(t *testing.T) {
	good := map[string]string{
		"Strict-Transport-Security": "max-age=31536000",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Frame-Options":           "SAMEORIGIN",
		"X-Content-Type-Options":    "nosniff",
	}

	cases := []struct {
		name      string
		change    map[string]string // какие заголовки заменить в good
		wantTitle string            // какую проблему ждём ("" — никакой)
	}{
		{"короткий HSTS", map[string]string{"Strict-Transport-Security": "max-age=300"}, "Слишком короткий срок HSTS"},
		{"кривой HSTS", map[string]string{"Strict-Transport-Security": "includeSubDomains"}, "Слишком короткий срок HSTS"},
		{"нет XFO, но есть frame-ancestors", map[string]string{"X-Frame-Options": "", "Content-Security-Policy": "frame-ancestors 'self'"}, ""},
		{"XFO с неверным значением", map[string]string{"X-Frame-Options": "ALLOW-FROM https://x"}, "Сайт можно встроить в чужую страницу"},
		{"nosniff в другом регистре", map[string]string{"X-Content-Type-Options": "NoSniff"}, ""},
	}

	for _, tc := range cases {
		// t.Run запускает подтест с именем — в выводе видно, какой случай упал.
		t.Run(tc.name, func(t *testing.T) {
			h := map[string]string{}
			for k, v := range good {
				h[k] = v
			}
			for k, v := range tc.change {
				if v == "" {
					delete(h, k)
				} else {
					h[k] = v
				}
			}
			findings := runHeaders(t, h)

			if tc.wantTitle == "" {
				if len(findings) != 0 {
					t.Fatalf("ожидали 0 проблем, получили: %+v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Title != tc.wantTitle {
				t.Fatalf("ожидали одну проблему %q, получили: %+v", tc.wantTitle, findings)
			}
		})
	}
}

func TestHeaders_Unreachable(t *testing.T) {
	// Порт 1 на localhost почти наверняка закрыт — соединение не установится.
	c := &HeadersCheck{}
	findings := c.Run(context.Background(), "127.0.0.1:1")
	if len(findings) != 1 || findings[0].Severity != SeverityInfo {
		t.Fatalf("ожидали одну info-находку, получили: %+v", findings)
	}
}
