package check

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
)

type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}
type EmailCheck struct {
	Resolver      TXTResolver
	DKIMSelectors []string
}

func (*EmailCheck) Name() string { return "email" }
func (e *EmailCheck) WithOptions(opts Options) Check {
	copy := *e
	copy.DKIMSelectors = append([]string(nil), opts.DKIMSelectors...)
	return &copy
}
func (e *EmailCheck) Run(ctx context.Context, domain string) ([]Finding, error) {
	detail, err := e.RunDetailed(ctx, domain)
	return detail.Findings, err
}
func (e *EmailCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	resolver := e.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var detail Detail
	targets := []struct{ kind, name string }{{"spf", domain}, {"dmarc", "_dmarc." + domain}}
	seen := map[string]bool{}
	for _, selector := range e.DKIMSelectors {
		if !seen[selector] {
			targets = append(targets, struct{ kind, name string }{"dkim", selector + "._domainkey." + domain})
			seen[selector] = true
		}
	}
	for _, target := range targets {
		probe := ProbeResult{ID: "email." + target.kind, Type: "email_" + target.kind, Status: "completed", Location: target.name}
		if target.kind == "dkim" {
			probe.ID += "@" + target.name
		}
		records, err := resolver.LookupTXT(ctx, target.name)
		var dnsErr *net.DNSError
		if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			probe.Status = "failed"
			probe.Message = "Не удалось получить TXT-записи DNS."
			detail.Probes = append(detail.Probes, probe)
			continue
		}
		var matches []string
		for _, record := range records {
			trimmed := strings.TrimSpace(record)
			if target.kind == "spf" {
				fields := strings.Fields(trimmed)
				if len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1") {
					matches = append(matches, trimmed)
				}
			} else {
				tags := dnsTags(trimmed)
				if target.kind == "dmarc" && strings.EqualFold(tags["v"], "DMARC1") || target.kind == "dkim" && (strings.EqualFold(tags["v"], "DKIM1") || hasTag(tags, "p")) {
					matches = append(matches, trimmed)
				}
			}
		}
		rule, title, evidence := "", "", ""
		switch {
		case len(matches) == 0:
			rule = "missing_" + target.kind
			title = "Не найдена запись " + strings.ToUpper(target.kind)
			evidence = "Подходящая TXT-запись не найдена."
		case len(matches) > 1:
			rule = "multiple_" + target.kind
			title = "Несколько записей " + strings.ToUpper(target.kind)
			evidence = "Найдено несколько конфликтующих TXT-записей."
		default:
			tags := dnsTags(matches[0])
			switch target.kind {
			case "spf":
				// This checks the declared terminal policy, not SPF DNS expansion.
				fields := strings.Fields(strings.ToLower(matches[0]))
				terminal, redirect := "", false
				for _, field := range fields[1:] {
					if strings.TrimLeft(field, "+-~?") == "all" && terminal == "" {
						terminal = field
					}
					if strings.HasPrefix(field, "redirect=") && len(field) > len("redirect=") {
						redirect = true
					}
				}
				if terminal != "" && terminal != "-all" && terminal != "~all" || terminal == "" && !redirect {
					rule = "weak_spf"
					title = "SPF не задаёт ограничивающую политику"
				}
				if terminal == "" && redirect {
					probe.Status = "incomplete"
					probe.Message = "Политика redirect найдена; целевой SPF пока не проверен."
				}

			case "dmarc":
				p := strings.ToLower(tags["p"])
				if p != "reject" && p != "quarantine" {
					rule = "weak_dmarc"
					title = "DMARC не ограничивает поддельные письма"
				}
			case "dkim":
				if tags["p"] == "" {
					rule = "revoked_dkim"
					title = "Ключ DKIM отозван или отсутствует"
				} else if decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(tags["p"]), "")); err != nil || len(decoded) == 0 {
					rule = "invalid_dkim"
					title = "Некорректная кодировка ключа DKIM"
				}
			}
			if rule != "" {
				evidence = "TXT-запись найдена, но проверяемое правило политики не выполнено."
			}
		}
		if rule != "" {
			detail.Findings = append(detail.Findings, Finding{CheckName: "email", ID: "email." + rule, ProbeID: probe.ID, Probe: probe.Type, Location: target.name, Evidence: evidence, Severity: SeverityMedium, Title: title, Description: "Почтовая защита домена может быть недостаточной.", Fix: "Проверьте DNS-настройки у почтового провайдера и настройте SPF, DMARC и действующий DKIM-ключ."})
		}
		detail.Probes = append(detail.Probes, probe)
	}
	if len(e.DKIMSelectors) == 0 {
		detail.Probes = append(detail.Probes, ProbeResult{ID: "email.dkim", Type: "email_dkim", Status: "skipped", CoverageUnknown: true, Location: domain, Message: "Селектор DKIM не задан."})
	}
	return detail, nil
}
func dnsTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

func hasTag(tags map[string]string, key string) bool { _, ok := tags[key]; return ok }
