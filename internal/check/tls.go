package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	tlsExpiryProbe   = "tls_cert_expiry"
	tlsHostnameProbe = "tls_cert_hostname"
	tlsChainProbe    = "tls_cert_chain"
	tlsProtocolProbe = "tls_protocol"
	tlsRedirectProbe = "tls_http_redirect"
)

// TLSCheck inspects the certificate, negotiated protocol and HTTP-to-HTTPS
// redirect behavior of a domain. It never sends application data over TLS.
type TLSCheck struct {
	publicTargetsOnly bool
	dialContext       func(context.Context, string, string) (net.Conn, error)
	rootCAs           *x509.CertPool
}

func (*TLSCheck) Name() string { return "tls" }

func (c *TLSCheck) Run(ctx context.Context, domain string) ([]Finding, error) {
	detail, err := c.RunDetailed(ctx, domain)
	return detail.Findings, err
}

func (c *TLSCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	detail := Detail{Probes: []ProbeResult{
		{ID: "tls.cert_expiry", Type: tlsExpiryProbe, Status: "failed", Location: domain + ":443"},
		{ID: "tls.cert_hostname", Type: tlsHostnameProbe, Status: "failed", Location: domain + ":443"},
		{ID: "tls.cert_chain", Type: tlsChainProbe, Status: "failed", Location: domain + ":443"},
		{ID: "tls.protocol", Type: tlsProtocolProbe, Status: "failed", Location: domain + ":443"},
		{ID: "tls.http_redirect", Type: tlsRedirectProbe, Status: "failed", Location: "http://" + domain + ":80/"},
	}}
	var errs []error
	now := time.Now()

	conn, err := c.handshake(ctx, domain)
	if err != nil {
		errs = append(errs, err)
		for i := 0; i < 4; i++ {
			detail.Probes[i].Message = "Не удалось безопасно проверить TLS-соединение."
		}
	} else {
		state := conn.ConnectionState()
		conn.Close()
		if len(state.PeerCertificates) == 0 {
			err = errors.New("peer did not provide a certificate")
			errs = append(errs, err)
			for i := 0; i < 3; i++ {
				detail.Probes[i].Message = "Сертификат сервера не получен."
			}
		} else {
			leaf := state.PeerCertificates[0]
			c.checkExpiry(&detail, leaf, now)
			c.checkHostname(&detail, leaf, domain)
			c.checkChain(&detail, state.PeerCertificates, now)
		}
		c.checkProtocol(&detail, state.Version, domain)
	}

	if err := c.checkHTTPRedirect(ctx, domain, &detail); err != nil {
		errs = append(errs, err)
	}
	return detail, errors.Join(errs...)
}

func (c *TLSCheck) checkProtocol(detail *Detail, version uint16, domain string) {
	p := &detail.Probes[3]
	p.Status = "completed"
	if version >= tls.VersionTLS12 {
		p.Message = "Используется TLS 1.2 или новее."
		return
	}
	p.Message = "Сервер согласовал устаревшую версию TLS."
	detail.Findings = append(detail.Findings, Finding{
		CheckName: "tls", ID: "tls.weak_protocol", ProbeID: p.ID, Probe: p.Type,
		Location: p.Location, Severity: SeverityHigh, Title: "Поддерживается устаревший TLS",
		Description: "TLS 1.0 и 1.1 не обеспечивают современный уровень защиты соединения.",
		Fix:         "Оставьте TLS 1.2 и TLS 1.3, отключив TLS 1.0 и 1.1.",
		Evidence:    "Согласован протокол " + tls.VersionName(version) + ".",
	})
}

func (c *TLSCheck) handshake(ctx context.Context, domain string) (*tls.Conn, error) {
	dial := c.dial()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dial(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: domain, InsecureSkipVerify: true, // Validate each certificate property separately below.
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func (c *TLSCheck) checkExpiry(detail *Detail, cert *x509.Certificate, now time.Time) {
	p := &detail.Probes[0]
	p.Status = "completed"
	if now.Before(cert.NotBefore) {
		p.Message = "Сертификат ещё не вступил в силу."
		detail.Findings = append(detail.Findings, Finding{
			CheckName: "tls", ID: "tls.certificate_not_yet_valid", ProbeID: p.ID, Probe: p.Type,
			Location: p.Location, Severity: SeverityHigh, Title: "Сертификат ещё не действует",
			Description: "Клиенты могут отклонять сертификат до начала срока его действия.",
			Fix:         "Проверьте дату начала действия и часы сервера.", Evidence: "Срок действия начинается " + cert.NotBefore.UTC().Format(time.RFC3339) + ".",
		})
		return
	}
	if now.After(cert.NotAfter) {
		p.Message = "Срок действия сертификата истёк."
		detail.Findings = append(detail.Findings, Finding{
			CheckName: "tls", ID: "tls.certificate_expired", ProbeID: p.ID, Probe: p.Type,
			Location: p.Location, Severity: SeverityHigh, Title: "TLS-сертификат истёк",
			Description: "Браузеры и API-клиенты могут отклонять HTTPS-соединение.",
			Fix:         "Продлите и установите TLS-сертификат.", Evidence: "Срок действия закончился " + cert.NotAfter.UTC().Format(time.RFC3339) + ".",
		})
		return
	}
	if cert.NotAfter.Sub(now) <= 30*24*time.Hour {
		p.Message = "Срок действия сертификата скоро закончится."
		detail.Findings = append(detail.Findings, Finding{
			CheckName: "tls", ID: "tls.certificate_expiring", ProbeID: p.ID, Probe: p.Type,
			Location: p.Location, Severity: SeverityMedium, Title: "TLS-сертификат скоро истекает",
			Description: "После окончания срока браузеры и API-клиенты начнут отклонять HTTPS-соединение.",
			Fix:         "Продлите сертификат до даты окончания его действия.", Evidence: "Срок действия закончится " + cert.NotAfter.UTC().Format(time.RFC3339) + ".",
		})
		return
	}
	p.Message = "Сертификат действует ещё более 30 дней."
}

func (c *TLSCheck) checkHostname(detail *Detail, cert *x509.Certificate, domain string) {
	p := &detail.Probes[1]
	p.Status = "completed"
	if err := cert.VerifyHostname(domain); err != nil {
		p.Message = "Имя домена не совпадает с сертификатом."
		detail.Findings = append(detail.Findings, Finding{
			CheckName: "tls", ID: "tls.certificate_hostname_mismatch", ProbeID: p.ID, Probe: p.Type,
			Location: p.Location, Severity: SeverityHigh, Title: "Сертификат выдан для другого имени",
			Description: "Браузеры предупреждают о несовпадении домена и имени в сертификате.",
			Fix:         "Установите сертификат, в котором указано это доменное имя.", Evidence: "Имя домена отсутствует среди имён сертификата.",
		})
		return
	}
	p.Message = "Имя домена соответствует сертификату."
}

func (c *TLSCheck) checkChain(detail *Detail, certs []*x509.Certificate, now time.Time) {
	p := &detail.Probes[2]
	p.Status = "completed"
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots: c.rootCAs, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		p.Message = "Не удалось подтвердить доверенную цепочку сертификата."
		detail.Findings = append(detail.Findings, Finding{
			CheckName: "tls", ID: "tls.certificate_chain_invalid", ProbeID: p.ID, Probe: p.Type,
			Location: p.Location, Severity: SeverityHigh, Title: "Цепочка TLS-сертификата не доверена",
			Description: "Клиенты не могут подтвердить, что сертификат выдан доверенным центром сертификации.",
			Fix:         "Установите полный корректный набор сертификатов от доверенного центра.", Evidence: "Проверка доверенной цепочки не пройдена.",
		})
		return
	}
	p.Message = "Цепочка сертификата подтверждена системным хранилищем доверия."
}

func (c *TLSCheck) checkHTTPRedirect(ctx context.Context, domain string, detail *Detail) error {
	transport := &http.Transport{DialContext: c.dial()}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+domain+"/", nil)
	if err != nil {
		detail.Probes[4].Message = "Не удалось сформировать HTTP-запрос."
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		detail.Probes[4].Message = "Не удалось получить HTTP-ответ для проверки перенаправления."
		return err
	}
	resp.Body.Close()
	p := &detail.Probes[4]
	p.Status = "completed"
	location, parseErr := resp.Location()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && parseErr == nil && redirectsToSameHTTPSHost(location, domain) {
		p.Message = "HTTP перенаправляет на HTTPS для того же домена."
		return nil
	}
	p.Message = "HTTP не перенаправляет на HTTPS для того же домена."
	detail.Findings = append(detail.Findings, Finding{
		CheckName: "tls", ID: "tls.http_redirect_missing", ProbeID: p.ID, Probe: p.Type,
		Location: p.Location, Severity: SeverityMedium, Title: "HTTP не перенаправляет на HTTPS",
		Description: "Пользователь может открыть сайт по незащищённому HTTP, если введёт адрес без HTTPS.",
		Fix:         "Настройте постоянное перенаправление HTTP на HTTPS для этого домена.",
		Evidence:    fmt.Sprintf("HTTP-ответ: %d.", resp.StatusCode),
	})
	return nil
}

func redirectsToSameHTTPSHost(location *url.URL, domain string) bool {
	if location == nil || !strings.EqualFold(location.Scheme, "https") || !strings.EqualFold(location.Hostname(), domain) {
		return false
	}
	return location.Port() == "" || location.Port() == "443"
}

func (c *TLSCheck) dial() func(context.Context, string, string) (net.Conn, error) {
	if c.dialContext != nil {
		return c.dialContext
	}
	if c.publicTargetsOnly {
		return publicDialContext
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext
}
