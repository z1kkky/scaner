package check

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

func (h *HeadersCheck) WithOptions(opts Options) Check {
	copy := *h
	copy.PagePaths = append([]string(nil), opts.PagePaths...)
	return &copy
}

var headerProbes = []string{"hsts", "csp", "frame_protection", "nosniff", "session_cookies"}

func (h *HeadersCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	var detail Detail
	var errs []error
	paths := []string{"/"}
	seen := map[string]bool{"/": true}
	for _, path := range h.PagePaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}
	// Cookies and headers are specific to the requested page. Do not follow a
	// redirect to another origin, or silently replace /login with another page.
	client := *h.client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range paths {
		probes := make([]ProbeResult, 0, len(headerProbes))
		for _, kind := range headerProbes {
			probes = append(probes, ProbeResult{ID: "headers." + kind + "@" + path, Type: "headers_" + kind, Status: "completed", Location: path})
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+path, nil)
		var resp *http.Response
		if err == nil {
			req.Header.Set("User-Agent", "scaner/0.1 (+https://github.com/z1kkky/scaner)")
			resp, err = client.Do(req)
		}
		if err != nil {
			errs = append(errs, err)
			for i := range probes {
				probes[i].Status = "failed"
				probes[i].Message = "Не удалось получить HTTP-ответ."
			}
			detail.Probes = append(detail.Probes, probes...)
			continue
		}
		resp.Body.Close()
		for _, f := range analyzeHeaders(resp.Header) {
			f.Location = path
			f.ProbeID += "@" + path
			f.Evidence = "Защитный HTTP-заголовок отсутствует или не соответствует проверяемому правилу."
			detail.Findings = append(detail.Findings, f)
		}
		sessionFound := false
		for _, cookie := range resp.Cookies() {
			if !sessionCookie(cookie.Name) {
				continue
			}
			sessionFound = true
			missing := []string{}
			if !cookie.Secure {
				missing = append(missing, "Secure")
			}
			if !cookie.HttpOnly {
				missing = append(missing, "HttpOnly")
			}
			if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 || cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
				missing = append(missing, "SameSite")
			}
			if len(missing) > 0 {
				detail.Findings = append(detail.Findings, Finding{CheckName: "headers", ID: "headers.unsafe_session_cookie", ProbeID: "headers.session_cookies@" + path, Probe: "headers_session_cookies", Location: path, Severity: SeverityMedium, Title: "Сессионная cookie недостаточно защищена", Description: "Браузер может передать сессионную cookie в небезопасном контексте.", Fix: "Установите Secure, HttpOnly и подходящую политику SameSite.", Evidence: "Отсутствуют или некорректны атрибуты: " + strings.Join(missing, ", ")})
			}
		}
		if !sessionFound {
			probes[len(probes)-1].Status = "skipped"
			probes[len(probes)-1].Message = "Сессионные cookies с известными именами не обнаружены."
		}
		detail.Probes = append(detail.Probes, probes...)
	}
	return detail, errors.Join(errs...)
}

func sessionCookie(name string) bool {
	name = strings.ToLower(name)
	name = strings.TrimPrefix(strings.TrimPrefix(name, "__host-"), "__secure-")
	switch name {
	case "session", "sessionid", "session_id", "sid", "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid":
		return true
	}
	return false
}
