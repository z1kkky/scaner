package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const cmsResponseLimit = 8 << 10

var (
	metaTagPattern  = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	metaAttrPattern = regexp.MustCompile(`(?is)([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

// CMSCheck passively fingerprints common CMS markers on the HTTPS homepage.
// It does not crawl, exploit or probe version-specific vulnerabilities.
type CMSCheck struct {
	publicTargetsOnly bool
	client            *http.Client
	dialContext       func(context.Context, string, string) (net.Conn, error)
}

func (*CMSCheck) Name() string { return "cms" }

func (c *CMSCheck) Run(ctx context.Context, domain string) ([]Finding, error) {
	detail, err := c.RunDetailed(ctx, domain)
	return detail.Findings, err
}

func (c *CMSCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	probe := ProbeResult{ID: "cms.version", Type: "cms_version", Status: "failed", Location: "/"}
	detail := Detail{Probes: []ProbeResult{probe}}
	client := cloneHTTPClient(c.httpClient())
	if c.client == nil {
		defer client.CloseIdleConnections()
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		detail.Probes[0].Message = "Не удалось сформировать HTTP-запрос."
		return detail, err
	}
	req.Header.Set("User-Agent", "scaner/0.1 (+https://github.com/z1kkky/scaner)")
	resp, err := client.Do(req)
	if err != nil {
		detail.Probes[0].Message = "Не удалось получить главную страницу для пассивного определения CMS."
		return detail, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests {
		detail.Probes[0].Message = "Сервер не дал надёжно завершить определение CMS."
		return detail, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		detail.Probes[0].Status = "completed"
		detail.Probes[0].Message = "Страница перенаправляет; перенаправление не выполнялось."
		return detail, nil
	}
	if resp.StatusCode != http.StatusOK {
		detail.Probes[0].Status = "completed"
		detail.Probes[0].Message = "CMS-маркер на доступной главной странице не обнаружен."
		return detail, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cmsResponseLimit+1))
	if err != nil {
		detail.Probes[0].Message = "Не удалось прочитать ограниченный фрагмент главной страницы."
		return detail, err
	}
	name, version := identifyCMS(resp.Header, body)
	if name != "" {
		detail.Probes[0].Status = "completed"
		detail.Probes[0].Message = "Обнаружен публичный маркер CMS."
		title := "Обнаружена CMS " + name
		if version != "" {
			title += " " + version
		}
		detail.Findings = append(detail.Findings, Finding{
			CheckName: "cms", ID: "cms.detected_" + strings.ToLower(name), ProbeID: "cms.version", Probe: "cms_version",
			Location: "/", Severity: SeverityInfo, Title: title,
			Description: "Сканер распознал CMS по публичным маркерам; наличие CMS само по себе не означает уязвимость.",
			Fix:         "Поддерживайте CMS и её расширения в актуальном состоянии.",
			Evidence:    "Распознан публичный маркер CMS; содержимое страницы не сохранялось.",
		})
		return detail, nil
	}
	if len(body) > cmsResponseLimit {
		detail.Probes[0].Message = "Страница превысила лимит чтения; результат не удалось подтвердить."
		return detail, errors.New("homepage exceeded CMS inspection limit")
	}
	detail.Probes[0].Status = "completed"
	detail.Probes[0].Message = "Известные CMS-маркеры не обнаружены."
	return detail, nil
}

func (c *CMSCheck) httpClient() *http.Client {
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

func identifyCMS(headers http.Header, body []byte) (string, string) {
	if name, version := parseCMSGenerator(headers.Get("X-Generator")); name != "" {
		return name, version
	}
	content := string(body)
	for _, tag := range metaTagPattern.FindAllString(content, -1) {
		attrs := parseHTMLAttributes(tag)
		if strings.EqualFold(attrs["name"], "generator") {
			if name, version := parseCMSGenerator(attrs["content"]); name != "" {
				return name, version
			}
		}
	}
	lower := strings.ToLower(content)
	switch {
	case strings.Contains(lower, "/wp-content/") || strings.Contains(lower, "/wp-includes/") || strings.Contains(lower, "wp-json"):
		return "WordPress", ""
	case strings.Contains(lower, "drupalsettings") || strings.Contains(lower, "/sites/default/files/"):
		return "Drupal", ""
	case strings.Contains(lower, "/media/system/js/") || strings.Contains(lower, "com_content"):
		return "Joomla", ""
	case strings.Contains(lower, "mage/cookies") || strings.Contains(lower, "magento_ui"):
		return "Magento", ""
	default:
		return "", ""
	}
}

func parseCMSGenerator(value string) (string, string) {
	lower := strings.ToLower(value)
	name, marker := "", ""
	switch {
	case strings.Contains(lower, "wordpress"):
		name, marker = "WordPress", "wordpress"
	case strings.Contains(lower, "drupal"):
		name, marker = "Drupal", "drupal"
	case strings.Contains(lower, "joomla"):
		name, marker = "Joomla", "joomla"
	case strings.Contains(lower, "magento"):
		name, marker = "Magento", "magento"
	default:
		return "", ""
	}
	versionPattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(marker) + `(?:\s|/|!)+([0-9]+(?:\.[0-9]+){0,3})`)
	match := versionPattern.FindStringSubmatch(value)
	if len(match) == 2 {
		return name, match[1]
	}
	return name, ""
}

func parseHTMLAttributes(tag string) map[string]string {
	attrs := make(map[string]string)
	for _, match := range metaAttrPattern.FindAllStringSubmatch(tag, -1) {
		value := match[2]
		if value == "" {
			value = match[3]
		}
		if value == "" {
			value = match[4]
		}
		attrs[strings.ToLower(match[1])] = value
	}
	return attrs
}
