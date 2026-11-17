package check

// Тесты в Go лежат рядом с кодом в файлах *_test.go.
// Запуск: go test ./...
// Каждая функция TestXxx(t *testing.T) — отдельный тест.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func runHeaders(t *testing.T, headers map[string]string) []Finding {
	t.Helper()
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.String() != "https://example.com/" {
			t.Fatalf("неожиданный запрос: %s %s", req.Method, req.URL)
		}

		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
		for name, value := range headers {
			response.Header.Set(name, value)
		}
		return response, nil
	})}
	c := &HeadersCheck{Client: client}
	findings, err := c.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("проверка заголовков завершилась ошибкой: %v", err)
	}
	return findings
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
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})}
	c := &HeadersCheck{Client: client}
	findings, err := c.Run(context.Background(), "example.com")
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(findings) != 0 {
		t.Fatalf("ожидали ошибку без находок, получили: %+v, %v", findings, err)
	}
}
