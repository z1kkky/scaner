package check

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	portsTCPProbe   = "ports_tcp"
	portTimeout     = 750 * time.Millisecond
	portMaxParallel = 4
)

type tcpPortTarget struct {
	port     uint16
	name     string
	severity Severity
}

// This allowlist checks common remotely exposed services only. It is not a
// general port scanner and sends no application payload after connecting.
var tcpPortTargets = []tcpPortTarget{
	{port: 21, name: "FTP", severity: SeverityMedium},
	{port: 22, name: "SSH", severity: SeverityInfo},
	{port: 23, name: "Telnet", severity: SeverityHigh},
	{port: 25, name: "SMTP", severity: SeverityInfo},
	{port: 3306, name: "MySQL", severity: SeverityHigh},
	{port: 5432, name: "PostgreSQL", severity: SeverityHigh},
	{port: 6379, name: "Redis", severity: SeverityCritical},
	{port: 8080, name: "HTTP alternate", severity: SeverityInfo},
	{port: 8443, name: "HTTPS alternate", severity: SeverityInfo},
	{port: 9200, name: "Elasticsearch", severity: SeverityHigh},
}

// PortsCheck performs a bounded TCP connect check over a small fixed allowlist.
type PortsCheck struct {
	publicTargetsOnly bool
	dialContext       func(context.Context, string, string) (net.Conn, error)
}

func (*PortsCheck) Name() string { return "ports" }

func (c *PortsCheck) Run(ctx context.Context, domain string) ([]Finding, error) {
	detail, err := c.RunDetailed(ctx, domain)
	return detail.Findings, err
}

func (c *PortsCheck) RunDetailed(ctx context.Context, domain string) (Detail, error) {
	detail := Detail{Probes: make([]ProbeResult, len(tcpPortTargets))}
	findings := make([]*Finding, len(tcpPortTargets))
	errs := make([]error, len(tcpPortTargets))
	sem := make(chan struct{}, portMaxParallel)
	var wg sync.WaitGroup
	for i, target := range tcpPortTargets {
		detail.Probes[i] = ProbeResult{
			ID: fmt.Sprintf("ports.tcp@%d", target.port), Type: portsTCPProbe,
			Status: "failed", Location: fmt.Sprintf("%s:%d", domain, target.port),
		}
		wg.Add(1)
		go func(index int, target tcpPortTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errs[index] = ctx.Err()
				detail.Probes[index].Message = "Проверка отменена до TCP-подключения."
				return
			}
			probe, finding, err := c.probePort(ctx, domain, target)
			detail.Probes[index] = probe
			findings[index] = finding
			errs[index] = err
		}(i, target)
	}
	wg.Wait()
	for _, finding := range findings {
		if finding != nil {
			detail.Findings = append(detail.Findings, *finding)
		}
	}
	joined := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			joined = append(joined, err)
		}
	}
	return detail, errors.Join(joined...)
}

func (c *PortsCheck) probePort(parent context.Context, domain string, target tcpPortTarget) (ProbeResult, *Finding, error) {
	probe := ProbeResult{
		ID: fmt.Sprintf("ports.tcp@%d", target.port), Type: portsTCPProbe,
		Status: "failed", Location: fmt.Sprintf("%s:%d", domain, target.port),
	}
	ctx, cancel := context.WithTimeout(parent, portTimeout)
	defer cancel()
	conn, err := c.dial()(ctx, "tcp", net.JoinHostPort(domain, fmt.Sprint(target.port)))
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			probe.Status = "completed"
			probe.Message = "TCP-порт закрыт."
			return probe, nil, nil
		}
		probe.Message = "Не удалось надёжно определить доступность TCP-порта."
		return probe, nil, err
	}
	_ = conn.Close()
	probe.Status = "completed"
	probe.Message = "TCP-порт принимает соединения; данные приложению не отправлялись."
	return probe, &Finding{
		CheckName: "ports", ID: fmt.Sprintf("ports.open_%d", target.port), ProbeID: probe.ID,
		Probe: portsTCPProbe, Location: probe.Location, Severity: target.severity,
		Title:       fmt.Sprintf("Открыт TCP-порт %d (часто %s)", target.port, target.name),
		Description: "На этом порту принимаются внешние TCP-соединения; проверка не определяет аутентификацию или доступность данных сервиса.",
		Fix:         "Если служба не должна быть доступна из интернета, ограничьте порт сетевыми правилами; проверьте настройки самой службы.",
		Evidence:    "Установлено TCP-соединение; прикладной протокол и данные не запрашивались.",
	}, nil
}

func (c *PortsCheck) dial() func(context.Context, string, string) (net.Conn, error) {
	if c.dialContext != nil {
		return c.dialContext
	}
	if c.publicTargetsOnly {
		return publicDialContext
	}
	dialer := &net.Dialer{Timeout: portTimeout}
	return dialer.DialContext
}
