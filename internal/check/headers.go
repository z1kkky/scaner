package check

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HeadersCheck проверяет заголовки безопасности HTTP-ответа:
// HSTS, CSP, X-Frame-Options, X-Content-Type-Options.
//
// Проверка неинвазивная: делаем один обычный GET главной страницы,
// как это сделал бы браузер, и смотрим на заголовки ответа.
type HeadersCheck struct {
	// Client — HTTP-клиент для запроса. Если nil, используется клиент
	// по умолчанию (см. client()). В тестах сюда подставляем клиент
	// тестового сервера.
	Client *http.Client
}

// Name возвращает имя проверки. Благодаря методам Name и Run
// тип *HeadersCheck подходит под интерфейс Check.
func (h *HeadersCheck) Name() string { return "headers" }

// minHSTSMaxAge — минимальный разумный срок HSTS: полгода в секундах.
const minHSTSMaxAge = 180 * 24 * 60 * 60

// client возвращает HTTP-клиент: заданный в структуре или стандартный.
func (h *HeadersCheck) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{
		// Общий таймаут на запрос — страховка на случай,
		// если вызывающий забыл про дедлайн в контексте.
		Timeout: 15 * time.Second,
		// Идём не дальше 5 редиректов, чтобы не зациклиться.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (h *HeadersCheck) Run(ctx context.Context, domain string) []Finding {
	// Готовим запрос. NewRequestWithContext привязывает запрос к ctx:
	// если время вышло, запрос оборвётся сам.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return []Finding{h.unreachable(err)}
	}
	// Честно представляемся, чтобы владелец видел в логах, кто приходил.
	req.Header.Set("User-Agent", "scaner/0.1 (+https://github.com/z1kkky/scaner)")

	resp, err := h.client().Do(req)
	if err != nil {
		return []Finding{h.unreachable(err)}
	}
	// defer выполнится при выходе из функции. Тело ответа нам не нужно,
	// но закрыть его обязательно, иначе утечёт соединение.
	defer resp.Body.Close()

	// Дальше просто анализируем заголовки — отдельная функция,
	// чтобы логику было легко читать и тестировать.
	return analyzeHeaders(resp.Header)
}

// analyzeHeaders смотрит на заголовки и возвращает список проблем.
func analyzeHeaders(hdr http.Header) []Finding {
	var findings []Finding // nil-срез; append сам выделит память

	// --- HSTS ---
	// Говорит браузеру: «ходи ко мне только по HTTPS».
	hsts := hdr.Get("Strict-Transport-Security") // Get не зависит от регистра имени
	if hsts == "" {
		findings = append(findings, Finding{
			CheckName:   "headers",
			Title:       "Нет заголовка HSTS",
			Severity:    SeverityMedium,
			Description: "Браузер может открыть сайт по незащищённому HTTP. В публичном Wi-Fi злоумышленник сможет подменить страницу или перехватить данные.",
			Fix:         "Добавьте заголовок: Strict-Transport-Security: max-age=31536000; includeSubDomains",
		})
	} else if age, ok := hstsMaxAge(hsts); !ok || age < minHSTSMaxAge {
		findings = append(findings, Finding{
			CheckName:   "headers",
			Title:       "Слишком короткий срок HSTS",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("HSTS включён, но max-age меньше полугода (сейчас: %q). Защита быстро «забывается» браузером.", hsts),
			Fix:         "Установите max-age не меньше 31536000 (один год).",
		})
	}

	// --- CSP ---
	// Ограничивает, откуда странице можно грузить скрипты. Главная защита от XSS.
	csp := hdr.Get("Content-Security-Policy")
	if csp == "" {
		findings = append(findings, Finding{
			CheckName:   "headers",
			Title:       "Нет политики безопасности контента (CSP)",
			Severity:    SeverityMedium,
			Description: "Если на сайт попадёт чужой скрипт (например, через уязвимый плагин), браузер выполнит его без ограничений. Так крадут данные карт и аккаунты.",
			Fix:         "Добавьте заголовок Content-Security-Policy. Начните с: default-src 'self' — и расширяйте по мере необходимости.",
		})
	}

	// --- X-Frame-Options ---
	// Запрещает встраивать сайт в чужой <iframe> (защита от кликджекинга).
	// Современная замена — директива frame-ancestors в CSP, её тоже засчитываем.
	xfo := strings.ToUpper(strings.TrimSpace(hdr.Get("X-Frame-Options")))
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo != "DENY" && xfo != "SAMEORIGIN" && !hasFrameAncestors {
		findings = append(findings, Finding{
			CheckName:   "headers",
			Title:       "Сайт можно встроить в чужую страницу",
			Severity:    SeverityMedium,
			Description: "Злоумышленник может показать ваш сайт внутри своего под прозрачным слоем и заставить посетителя нажать не ту кнопку (кликджекинг).",
			Fix:         "Добавьте заголовок X-Frame-Options: SAMEORIGIN (или frame-ancestors 'self' в CSP).",
		})
	}

	// --- X-Content-Type-Options ---
	// Запрещает браузеру «угадывать» тип файла.
	if strings.ToLower(strings.TrimSpace(hdr.Get("X-Content-Type-Options"))) != "nosniff" {
		findings = append(findings, Finding{
			CheckName:   "headers",
			Title:       "Браузер может неверно определить тип файла",
			Severity:    SeverityLow,
			Description: "Без этого заголовка загруженная картинка или текстовый файл может быть выполнен браузером как скрипт.",
			Fix:         "Добавьте заголовок: X-Content-Type-Options: nosniff",
		})
	}

	return findings
}

// hstsMaxAge достаёт число из "max-age=31536000; includeSubDomains".
// Возвращает (число, true) или (0, false), если max-age не найден.
// Функции в Go могут возвращать несколько значений — это частый приём.
func hstsMaxAge(value string) (int, bool) {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if k, v, found := strings.Cut(part, "="); found && strings.EqualFold(strings.TrimSpace(k), "max-age") {
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"`))
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

// unreachable превращает сетевую ошибку в находку уровня info,
// чтобы в отчёте было видно, что проверка не смогла отработать.
func (h *HeadersCheck) unreachable(err error) Finding {
	return Finding{
		CheckName:   h.Name(),
		Title:       "Не удалось получить главную страницу по HTTPS",
		Severity:    SeverityInfo,
		Description: "Заголовки не проверены: " + err.Error(),
		Fix:         "Убедитесь, что сайт открывается по https:// и сертификат действителен.",
	}
}
