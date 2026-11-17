package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	exposureGitProbe       = "exposures_git"
	exposureEnvProbe       = "exposures_env"
	exposureBackupProbe    = "exposures_backup"
	exposureDirectoryProbe = "exposures_directory_listing"
	exposureAdminProbe     = "exposures_admin_interface"
	exposureResponseLimit  = 4096
	exposureMaxParallel    = 4
)

type exposureTarget struct {
	path     string
	typeName string
}

var exposureTargets = []exposureTarget{
	{path: "/.git/HEAD", typeName: exposureGitProbe},
	{path: "/.env", typeName: exposureEnvProbe},
	{path: "/config/.env", typeName: exposureEnvProbe},
	{path: "/backup.zip", typeName: exposureBackupProbe},
	{path: "/backup.tar.gz", typeName: exposureBackupProbe},
	{path: "/db.sql", typeName: exposureBackupProbe},
	{path: "/uploads/", typeName: exposureDirectoryProbe},
	{path: "/files/", typeName: exposureDirectoryProbe},
	{path: "/admin/", typeName: exposureAdminProbe},
	{path: "/admin/login", typeName: exposureAdminProbe},
	{path: "/wp-admin/", typeName: exposureAdminProbe},
	{path: "/wp-login.php", typeName: exposureAdminProbe},
	{path: "/administrator/", typeName: exposureAdminProbe},
	{path: "/phpmyadmin/", typeName: exposureAdminProbe},
}

var envAssignment = regexp.MustCompile(`(?m)^(?:export\s+)?[A-Z_][A-Z0-9_]{1,}=`)
var passwordInput = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?password["']?(?:\s|/|>)`)

// ExposuresCheck probes a fixed list of common sensitive paths. Response bodies
// are read only up to a small limit and are never copied into findings.
type ExposuresCheck struct {
	publicTargetsOnly bool
	client            *http.Client
	dialContext       func(context.Context, string, string) (net.Conn, error)
}

func (*ExposuresCheck) Name() string { return "exposures" }

func (c *ExposuresCheck) Run(ctx context.Context, domain string) ([]Finding, error) {
	detail, err := c.RunDetailed(ctx, domain)
	return detail.Findings, err
}

func (c *ExposuresCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	detail := Detail{Probes: make([]ProbeResult, len(exposureTargets))}
	findings := make([][]Finding, len(exposureTargets))
	errs := make([]error, len(exposureTargets))
	client := c.httpClient()
	client = cloneHTTPClient(client)
	if c.client == nil {
		defer client.CloseIdleConnections()
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sem := make(chan struct{}, exposureMaxParallel)
	var wg sync.WaitGroup

	for i, target := range exposureTargets {
		detail.Probes[i] = ProbeResult{
			ID:   "exposures." + strings.TrimPrefix(target.typeName, "exposures_") + "@" + target.path,
			Type: target.typeName, Status: "failed", Location: target.path,
		}
		wg.Add(1)
		go func(index int, target exposureTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errs[index] = ctx.Err()
				detail.Probes[index].Message = "Проверка отменена до HTTP-запроса."
				return
			}
			probe, finding, err := c.runTarget(ctx, client, domain, target)
			detail.Probes[index] = probe
			if finding != nil {
				findings[index] = []Finding{*finding}
			}
			errs[index] = err
		}(i, target)
	}
	wg.Wait()
	for i := range exposureTargets {
		detail.Findings = append(detail.Findings, findings[i]...)
	}
	joined := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			joined = append(joined, err)
		}
	}
	return detail, errors.Join(joined...)
}

func (c *ExposuresCheck) runTarget(ctx context.Context, client *http.Client, domain string, target exposureTarget) (ProbeResult, *Finding, error) {
	probe := ProbeResult{
		ID:   "exposures." + strings.TrimPrefix(target.typeName, "exposures_") + "@" + target.path,
		Type: target.typeName, Status: "failed", Location: target.path,
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+target.path, nil)
	if err != nil {
		probe.Message = "Не удалось сформировать HTTP-запрос."
		return probe, nil, err
	}
	req.Header.Set("User-Agent", "scaner/0.1 (+https://github.com/z1kkky/scaner)")
	resp, err := client.Do(req)
	if err != nil {
		probe.Message = "Не удалось получить HTTP-ответ для безопасной проверки пути."
		return probe, nil, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, exposureResponseLimit+1))
	if readErr != nil {
		probe.Message = "Не удалось прочитать ограниченный фрагмент HTTP-ответа."
		return probe, nil, readErr
	}
	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests {
		probe.Message = "Сервер не дал надёжно завершить проверку пути."
		return probe, nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		probe.Status = "completed"
		if target.typeName == exposureAdminProbe && redirectsToAdminLogin(resp, domain) {
			probe.Message = "Административная панель перенаправляет на форму входа; перенаправление не выполнялось."
			return probe, exposureFinding(target), nil
		}
		probe.Message = "Путь перенаправляет; перенаправление не выполнялось."
		return probe, nil, nil
	}
	probe.Status = "completed"
	if resp.StatusCode != http.StatusOK {
		probe.Message = "Чувствительное содержимое на проверяемом пути не обнаружено."
		return probe, nil, nil
	}

	if exposureMatches(target.typeName, target.path, resp.Header.Get("Content-Type"), body) {
		probe.Message = "На пути доступно содержимое, соответствующее проверке."
		return probe, exposureFinding(target), nil
	}
	if len(body) > exposureResponseLimit {
		probe.Status = "failed"
		probe.Message = "Ответ превысил лимит чтения; результат не удалось подтвердить."
		return probe, nil, fmt.Errorf("response exceeded %d-byte inspection limit", exposureResponseLimit)
	}
	probe.Message = "Чувствительное содержимое на проверяемом пути не обнаружено."
	return probe, nil, nil
}

func (c *ExposuresCheck) httpClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	if c.dialContext != nil {
		return &http.Client{Transport: &http.Transport{DialContext: c.dialContext, MaxResponseHeaderBytes: 64 << 10}, Timeout: 5 * time.Second}
	}
	if c.publicTargetsOnly {
		return NewPublicHTTPClient()
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext, MaxResponseHeaderBytes: 64 << 10},
		Timeout:   5 * time.Second,
	}
}

func cloneHTTPClient(client *http.Client) *http.Client {
	copy := *client
	return &copy
}

func exposureMatches(typeName, path, contentType string, body []byte) bool {
	if len(body) > exposureResponseLimit {
		body = body[:exposureResponseLimit]
	}
	lower := strings.ToLower(string(body))
	switch typeName {
	case exposureGitProbe:
		trimmed := strings.TrimSpace(string(body))
		return strings.HasPrefix(trimmed, "ref: refs/") || (len(trimmed) == 40 && isHex(trimmed))
	case exposureEnvProbe:
		return envAssignment.Match(body)
	case exposureBackupProbe:
		mediaType, _, _ := mime.ParseMediaType(contentType)
		switch strings.ToLower(mediaType) {
		case "application/zip", "application/x-zip-compressed", "application/gzip", "application/x-gzip", "application/octet-stream", "application/x-sql":
			return true
		}
		if strings.HasSuffix(path, ".zip") && strings.HasPrefix(string(body), "PK\x03\x04") {
			return true
		}
		if strings.HasSuffix(path, ".tar.gz") && len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b {
			return true
		}
		return strings.HasSuffix(path, ".sql") && (strings.Contains(lower, "create table ") || strings.Contains(lower, "insert into ") || strings.Contains(lower, "-- mysql dump"))
	case exposureDirectoryProbe:
		return strings.Contains(lower, "index of /") || strings.Contains(lower, "parent directory")
	case exposureAdminProbe:
		return strings.Contains(lower, "<form") && passwordInput.Match(body)
	default:
		return false
	}
}

func redirectsToAdminLogin(resp *http.Response, domain string) bool {
	location, err := resp.Location()
	if err != nil || location == nil || resp.Request == nil || resp.Request.URL == nil {
		return false
	}
	resolved := resp.Request.URL.ResolveReference(location)
	if !strings.EqualFold(resolved.Scheme, "https") || !strings.EqualFold(resolved.Hostname(), domain) {
		return false
	}
	if port := resolved.Port(); port != "" && port != "443" {
		return false
	}
	switch strings.ToLower(resolved.Path) {
	case "/wp-login.php", "/administrator/", "/administrator/index.php", "/admin/login", "/login":
		return true
	default:
		return false
	}
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func exposureFinding(target exposureTarget) *Finding {
	idPart := strings.TrimPrefix(target.typeName, "exposures_")
	finding := &Finding{
		CheckName: "exposures", ID: "exposures." + idPart + "_reachable",
		ProbeID: "exposures." + idPart + "@" + target.path, Probe: target.typeName,
		Location: target.path, Evidence: "Ответ подтверждает доступность проверяемого типа содержимого; тело ответа не сохранялось.",
	}
	switch target.typeName {
	case exposureGitProbe:
		finding.Severity, finding.Title = SeverityMedium, "Доступны метаданные Git"
		finding.Description = "Публичный доступ к Git-метаданным может раскрыть структуру и историю проекта."
		finding.Fix = "Удалите каталог .git из публичной директории веб-сервера и запретите его отдачу."
	case exposureEnvProbe:
		finding.Severity, finding.Title = SeverityCritical, "Доступен файл конфигурации окружения"
		finding.Description = "Файл .env может содержать пароли, ключи API и другие секреты."
		finding.Fix = "Удалите файл из публичной директории; при возможной утечке немедленно смените секреты."
	case exposureBackupProbe:
		finding.Severity, finding.Title = SeverityHigh, "Доступна резервная копия или дамп"
		finding.Description = "Публичная копия может раскрыть исходные файлы или данные сайта."
		finding.Fix = "Переместите копии за пределы web root и запретите их публичную раздачу."
	case exposureDirectoryProbe:
		finding.Severity, finding.Title = SeverityLow, "Включён листинг каталога"
		finding.Description = "Посетители могут просматривать имена файлов в каталоге."
		finding.Fix = "Отключите автоматический листинг каталога на веб-сервере."
	case exposureAdminProbe:
		finding.Severity, finding.Title = SeverityLow, "Доступна веб-форма административной панели"
		finding.Description = "Публично доступная панель управления повышает заметность точки входа для атакующих."
		finding.Fix = "Ограничьте доступ к панели управления сетевыми правилами и многофакторной аутентификацией."
	}
	return finding
}
