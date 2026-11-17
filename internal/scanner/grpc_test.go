package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/z1kkky/scaner/api/scanner/v1"
	"github.com/z1kkky/scaner/internal/check"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type rpcCheck struct {
	run func(context.Context) ([]check.Finding, error)
}

func (rpcCheck) Name() string                                                 { return "headers" }
func (c rpcCheck) Run(ctx context.Context, _ string) ([]check.Finding, error) { return c.run(ctx) }

func rpcClient(t *testing.T, c check.Check) pb.ScannerServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	pb.RegisterScannerServiceServer(s, NewServer([]check.Check{c}, time.Second))
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(func() { s.Stop(); _ = lis.Close() })
	conn, err := grpc.NewClient("passthrough:///scanner", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewScannerServiceClient(conn)
}

func TestStartScanWireEvents(t *testing.T) {
	client := rpcClient(t, rpcCheck{run: func(context.Context) ([]check.Finding, error) {
		return []check.Finding{{Title: "Нет CSP", Severity: check.SeverityMedium, Description: "description", Fix: "fix"}}, nil
	}})
	for _, explicit := range []bool{false, true} {
		req := &pb.ScanRequest{ScanId: "scan-1", Domain: "example.com"}
		if explicit {
			req.Checks = []pb.CheckType{pb.CheckType_CHECK_TYPE_HEADERS, pb.CheckType_CHECK_TYPE_TLS, pb.CheckType_CHECK_TYPE_HEADERS}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, err := client.StartScan(ctx, req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var events []*pb.ScanEvent
		for {
			e, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			if e.ScanId != req.ScanId || e.Sequence != uint64(len(events)+1) {
				t.Fatalf("bad envelope: %v", e)
			}
			events = append(events, e)
		}
		cancel()
		wantCount := 3
		wantStatus := pb.ScanStatus_SCAN_STATUS_COMPLETED
		if explicit {
			wantCount = 4
			wantStatus = pb.ScanStatus_SCAN_STATUS_PARTIAL
		}
		if len(events) != wantCount || events[0].GetStarted() == nil {
			t.Fatalf("bad events: %v", events)
		}
		if err := events[0].GetStarted().StartedAt.CheckValid(); err != nil {
			t.Fatal(err)
		}
		var headers, skipped bool
		for _, e := range events {
			r := e.GetCheckDone()
			if r == nil {
				continue
			}
			if r.Check == pb.CheckType_CHECK_TYPE_TLS {
				skipped = r.Status == pb.CheckStatus_CHECK_STATUS_SKIPPED
			}
			if r.Check == pb.CheckType_CHECK_TYPE_HEADERS {
				headers = true
				if r.Status != pb.CheckStatus_CHECK_STATUS_COMPLETED || len(r.Findings) != 1 || r.Findings[0].Severity != pb.Severity_SEVERITY_MEDIUM || r.Findings[0].Fix != "fix" {
					t.Fatalf("bad result: %v", r)
				}
			}
		}
		if !headers || explicit && !skipped {
			t.Fatal("missing check results")
		}
		summary := events[len(events)-1].GetFinished()
		if summary == nil || summary.Status != wantStatus || summary.CompletedChecks != 1 || summary.RequestedChecks != int32(wantCount-2) || summary.Score != nil || summary.Grade != pb.Grade_GRADE_UNSPECIFIED {
			t.Fatalf("bad summary: %v", summary)
		}
	}
}

func TestStartScanInvalidRequest(t *testing.T) {
	client := rpcClient(t, rpcCheck{run: func(context.Context) ([]check.Finding, error) {
		t.Error("invalid request ran a check")
		return nil, nil
	}})
	for _, req := range []*pb.ScanRequest{
		{}, {ScanId: "id", Domain: "https://example.com"},
		{ScanId: "id", Domain: "example.com", Checks: []pb.CheckType{999}},
		{ScanId: "id", Domain: "example.com", Checks: []pb.CheckType{0}},
		{ScanId: "id", Domain: "example.com", PagePaths: []string{"//foreign.example/login"}},
		{ScanId: "id", Domain: "example.com", DkimSelectors: []string{"bad selector"}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, err := client.StartScan(ctx, req)
		if err == nil {
			_, err = stream.Recv()
		}
		cancel()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument, got %v", err)
		}
	}
}

func TestStartScanCancellation(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	client := rpcClient(t, rpcCheck{run: func(ctx context.Context) ([]check.Finding, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.StartScan(ctx, &pb.ScanRequest{ScanId: "id", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("check did not start")
	}
	cancel()
	if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
		t.Fatalf("expected Canceled: %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("check was not canceled")
	}
}

func TestStartScanFailedCheck(t *testing.T) {
	client := rpcClient(t, rpcCheck{run: func(context.Context) ([]check.Finding, error) {
		return nil, errors.New("private transport details")
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.StartScan(ctx, &pb.ScanRequest{ScanId: "id", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	e, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	r := e.GetCheckDone()
	if r == nil || r.Status != pb.CheckStatus_CHECK_STATUS_FAILED || r.ErrorCode != "check_failed" || (r.Message == "" || strings.Contains(r.Message, "private transport details")) || len(r.Findings) != 0 {
		t.Fatalf("bad failure: %v", r)
	}
	e, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if s := e.GetFinished(); s == nil || s.Status != pb.ScanStatus_SCAN_STATUS_FAILED || s.CompletedChecks != 0 {
		t.Fatalf("bad summary: %v", e)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected EOF: %v", err)
	}
}

type testTXT func(context.Context, string) ([]string, error)

func (f testTXT) LookupTXT(ctx context.Context, name string) ([]string, error) { return f(ctx, name) }

type testHTTP func(*http.Request) (*http.Response, error)

func (f testHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStartScanDetailedOptions(t *testing.T) {
	for _, kind := range []pb.CheckType{pb.CheckType_CHECK_TYPE_HEADERS, pb.CheckType_CHECK_TYPE_EMAIL} {
		t.Run(kind.String(), func(t *testing.T) {
			var c check.Check
			if kind == pb.CheckType_CHECK_TYPE_HEADERS {
				c = &check.HeadersCheck{Client: &http.Client{Transport: testHTTP(func(r *http.Request) (*http.Response, error) {
					hdr := http.Header{}
					if r.URL.Path == "/login" {
						hdr.Add("Set-Cookie", "sessionid=SECRET; Path=/")
					}
					return &http.Response{StatusCode: 200, Header: hdr, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				})}}
			} else {
				c = &check.EmailCheck{Resolver: testTXT(func(_ context.Context, name string) ([]string, error) {
					switch name {
					case "example.com":
						return []string{"v=spf1 -all"}, nil
					case "_dmarc.example.com":
						return []string{"v=DMARC1; p=reject"}, nil
					case "mail._domainkey.example.com":
						return []string{"v=DKIM1; p="}, nil
					}
					return nil, errors.New("unexpected DNS name")
				})}
			}
			client := rpcClient(t, c)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := client.StartScan(ctx, &pb.ScanRequest{ScanId: "options", Domain: "example.com", Checks: []pb.CheckType{kind}, PagePaths: []string{"/login"}, DkimSelectors: []string{"mail"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Recv(); err != nil {
				t.Fatal(err)
			}
			e, err := stream.Recv()
			if err != nil {
				t.Fatal(err)
			}
			result := e.GetCheckDone()
			wantProbes := 3
			if kind == pb.CheckType_CHECK_TYPE_HEADERS {
				wantProbes = 10
			}
			if result == nil || len(result.Probes) != wantProbes || len(result.Findings) == 0 {
				t.Fatalf("bad detailed result: %v", e)
			}
			probes := map[string]*pb.ProbeResult{}
			for _, p := range result.Probes {
				if p.Id == "" || p.Type == pb.ProbeType_PROBE_TYPE_UNSPECIFIED || p.Status == pb.CheckStatus_CHECK_STATUS_UNSPECIFIED || p.Location == "" {
					t.Fatal(p)
				}
				probes[p.Id] = p
			}
			login := false
			for _, f := range result.Findings {
				p := probes[f.ProbeId]
				if f.Id == "" || p == nil || f.Probe != p.Type || f.Location != p.Location || f.Evidence == "" || strings.Contains(f.Evidence, "SECRET") {
					t.Fatalf("bad finding: %v", f)
				}
				if f.Location == "/login" {
					login = true
				}
			}
			if kind == pb.CheckType_CHECK_TYPE_HEADERS && !login {
				t.Fatal("page_paths was ignored")
			}
			if kind == pb.CheckType_CHECK_TYPE_EMAIL && result.Probes[2].Location != "mail._domainkey.example.com" {
				t.Fatal("selector was ignored")
			}
			if h, ok := c.(*check.HeadersCheck); ok && len(h.PagePaths) != 0 {
				t.Fatal("shared headers check mutated")
			}
			if m, ok := c.(*check.EmailCheck); ok && len(m.DKIMSelectors) != 0 {
				t.Fatal("shared email check mutated")
			}
			if _, err = stream.Recv(); err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Recv(); err != io.EOF {
				t.Fatalf("expected EOF: %v", err)
			}
		})
	}
}
