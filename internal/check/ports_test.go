package check

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
)

type portsScopeResolver struct{}

func (portsScopeResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (portsScopeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host, nil
}
func (portsScopeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}
func (portsScopeResolver) ResolveTarget(_ context.Context, host string) ([]string, []netip.Addr, error) {
	return []string{host}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func TestPortsCheckUsesFixedAllowlistAndClosesWithoutPayload(t *testing.T) {
	var serverSide net.Conn
	closed := make(chan struct{})
	check := &PortsCheck{dialContext: func(_ context.Context, _, address string) (net.Conn, error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(portText)
		switch port {
		case 21:
			client, server := net.Pipe()
			serverSide = server
			go func() {
				data, _ := io.ReadAll(server)
				if len(data) == 0 {
					close(closed)
				}
			}()
			return client, nil
		case 22:
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		default:
			return nil, errors.New("test-only filtered connection")
		}
	}}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err == nil {
		t.Fatal("filtered ports should make the scan incomplete")
	}
	if len(detail.Probes) != len(tcpPortTargets) || len(detail.Findings) != 1 || detail.Findings[0].ID != "ports.open_21" {
		t.Fatalf("unexpected port results: %+v", detail)
	}
	if serverSide == nil {
		t.Fatal("open test port was not connected")
	}
	defer serverSide.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("open TCP connection was not closed")
	}
	for _, probe := range detail.Probes {
		if probe.Status == "completed" && probe.ID != "ports.tcp@21" && probe.ID != "ports.tcp@22" {
			t.Fatalf("unexpected completed port: %+v", probe)
		}
	}
	for _, finding := range detail.Findings {
		if finding.ID != "ports.open_21" || finding.Probe != portsTCPProbe {
			t.Fatalf("filtered port became a finding: %+v", finding)
		}
	}
}

func TestPortsCheckCapsConcurrentConnections(t *testing.T) {
	var current, peak atomic.Int32
	check := &PortsCheck{dialContext: func(context.Context, string, string) (net.Conn, error) {
		n := current.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return nil, syscall.ECONNREFUSED
	}}
	detail, err := check.RunDetailed(context.Background(), "example.test")
	if err != nil || len(detail.Findings) != 0 {
		t.Fatalf("closed ports should complete without findings: detail=%+v err=%v", detail, err)
	}
	if got := peak.Load(); got < 2 || got > portMaxParallel {
		t.Fatalf("peak concurrent connections = %d, want 2..%d", got, portMaxParallel)
	}
}

func TestPortsCheckTimeoutIsUnknownNotOpen(t *testing.T) {
	check := &PortsCheck{dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	detail, err := check.RunDetailed(ctx, "example.test")
	if err == nil || len(detail.Findings) != 0 {
		t.Fatalf("timeouts must remain inconclusive: detail=%+v err=%v", detail, err)
	}
}

func TestPortTargetListContainsOnlyUniqueFixedPorts(t *testing.T) {
	seen := map[uint16]bool{}
	for _, target := range tcpPortTargets {
		if target.port == 0 || seen[target.port] {
			t.Errorf("invalid or duplicate TCP port %d", target.port)
		}
		seen[target.port] = true
	}
	if len(seen) > 16 {
		t.Fatalf("fixed TCP allowlist unexpectedly grew to %d ports", len(seen))
	}
}

func TestPortsCheckSkipsEveryPortOutsideFrozenPolicy(t *testing.T) {
	dialed := 0
	policy, err := targetscope.FreezeWithDial(context.Background(), portsScopeResolver{}, "example.test", nil, []uint16{443}, func(context.Context, string, string) (net.Conn, error) {
		dialed++
		return nil, errors.New("unexpected dial")
	})
	if err != nil {
		t.Fatal(err)
	}
	detail, err := (&PortsCheck{targetPolicy: policy}).RunDetailed(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("out-of-policy ports should be explicitly skipped: %v", err)
	}
	if dialed != 0 {
		t.Fatalf("made %d TCP dial attempts outside policy", dialed)
	}
	if len(detail.Probes) != len(tcpPortTargets) || len(detail.Findings) != 0 {
		t.Fatalf("unexpected result: %+v", detail)
	}
	for _, probe := range detail.Probes {
		if probe.Status != "skipped" || !strings.Contains(probe.Message, "не вход") {
			t.Errorf("out-of-policy probe was not marked skipped: %+v", probe)
		}
	}
}
