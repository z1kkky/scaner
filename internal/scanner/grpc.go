package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	pb "github.com/z1kkky/scaner/api/scanner/v1"
	"github.com/z1kkky/scaner/internal/check"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server adapts the scanner event stream to the internal gRPC contract.
// The calling API is responsible for domain ownership verification.
type Server struct {
	pb.UnimplementedScannerServiceServer
	checks    []check.Check
	timeout   time.Duration
	scanSlots chan struct{}
}

const maxConcurrentScans = 8

func NewServer(checks []check.Check, timeout time.Duration) *Server {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Server{
		checks: append([]check.Check(nil), checks...), timeout: timeout,
		scanSlots: make(chan struct{}, maxConcurrentScans),
	}
}

var checkNames = map[pb.CheckType]string{
	pb.CheckType_CHECK_TYPE_TLS:       "tls",
	pb.CheckType_CHECK_TYPE_HEADERS:   "headers",
	pb.CheckType_CHECK_TYPE_EXPOSURES: "exposures",
	pb.CheckType_CHECK_TYPE_EMAIL:     "email",
	pb.CheckType_CHECK_TYPE_PORTS:     "ports",
	pb.CheckType_CHECK_TYPE_CMS:       "cms",
	pb.CheckType_CHECK_TYPE_NUCLEI:    "nuclei",
}

func checkType(name string) pb.CheckType {
	for kind, n := range checkNames {
		if n == name {
			return kind
		}
	}
	return pb.CheckType_CHECK_TYPE_UNSPECIFIED
}

func (s *Server) StartScan(req *pb.ScanRequest, stream grpc.ServerStreamingServer[pb.ScanEvent]) error {
	if req == nil || strings.TrimSpace(req.GetScanId()) == "" || !validDomain(req.GetDomain()) {
		return status.Error(codes.InvalidArgument, "scan_id and a canonical domain are required")
	}
	if len(req.GetScanId()) > 128 {
		return status.Error(codes.InvalidArgument, "scan_id is too long")
	}
	if len(req.GetPagePaths()) > 20 || len(req.GetDkimSelectors()) > 20 {
		return status.Error(codes.InvalidArgument, "too many page paths or DKIM selectors")
	}
	for _, path := range req.GetPagePaths() {
		u, err := url.Parse(path)
		if err != nil || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n") || u.IsAbs() || u.Host != "" || u.Fragment != "" {
			return status.Error(codes.InvalidArgument, "page_paths must contain same-origin absolute paths")
		}
	}
	for _, selector := range req.GetDkimSelectors() {
		if !validDomain(selector) || len(selector)+len("._domainkey.")+len(req.GetDomain()) > 253 {
			return status.Error(codes.InvalidArgument, "invalid DKIM selector")
		}
	}
	names := make([]string, 0, len(req.GetChecks()))
	seen := make(map[pb.CheckType]bool, len(req.GetChecks()))
	if len(req.GetChecks()) > len(checkNames) {
		return status.Error(codes.InvalidArgument, "too many checks")
	}
	for _, kind := range req.GetChecks() {
		name, ok := checkNames[kind]
		if !ok {
			return status.Error(codes.InvalidArgument, "unknown check type")
		}
		if seen[kind] {
			continue
		}
		seen[kind] = true
		names = append(names, name)
	}
	select {
	case s.scanSlots <- struct{}{}:
		defer func() { <-s.scanSlots }()
	default:
		return status.Error(codes.ResourceExhausted, "too many concurrent scans")
	}
	err := Run(stream.Context(), Request{ScanID: req.GetScanId(), Domain: req.GetDomain(), Checks: names, PagePaths: req.GetPagePaths(), DKIMSelectors: req.GetDkimSelectors()}, s.checks, s.timeout, func(event Event) error {
		return stream.Send(protoEvent(event))
	})
	if err == context.Canceled || err == context.DeadlineExceeded {
		return status.FromContextError(err).Err()
	}
	return err
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func protoEvent(event Event) *pb.ScanEvent {
	out := &pb.ScanEvent{ScanId: event.ScanID, Sequence: event.Sequence}
	switch {
	case event.Started != nil:
		started := &pb.ScanStarted{StartedAt: timestamppb.New(event.Started.StartedAt)}
		for _, name := range event.Started.Checks {
			started.Checks = append(started.Checks, checkType(name))
		}
		out.Payload = &pb.ScanEvent_Started{Started: started}
	case event.CheckDone != nil:
		r := event.CheckDone
		result := &pb.CheckResult{Check: checkType(r.Check), DurationMs: r.DurationMs, ErrorCode: r.ErrorCode}
		for _, p := range r.Probes {
			result.Probes = append(result.Probes, &pb.ProbeResult{Id: p.ID, Type: pb.ProbeType(pb.ProbeType_value["PROBE_TYPE_"+strings.ToUpper(p.Type)]), Status: pb.CheckStatus(pb.CheckStatus_value["CHECK_STATUS_"+strings.ToUpper(p.Status)]), Location: p.Location, Message: p.Message})
		}
		result.Status = pb.CheckStatus(pb.CheckStatus_value["CHECK_STATUS_"+strings.ToUpper(string(r.Status))])
		switch r.Status {
		case "skipped":
			result.Message = "Проверка пока не реализована или неприменима."
		case "failed":
			result.Message = "Не удалось получить надёжный результат проверки."
		case "incomplete":
			result.Message = "Проверка выполнена частично; смотрите результаты отдельных подпроб."
		}
		for _, f := range r.Findings {
			result.Findings = append(result.Findings, &pb.Finding{
				Title: f.Title, Description: f.Description, Fix: f.Fix,
				Id: f.ID, ProbeId: f.ProbeID, Probe: pb.ProbeType(pb.ProbeType_value["PROBE_TYPE_"+strings.ToUpper(f.Probe)]), Location: f.Location, Evidence: f.Evidence,
				Severity: pb.Severity(pb.Severity_value["SEVERITY_"+strings.ToUpper(string(f.Severity))]),
			})
		}
		out.Payload = &pb.ScanEvent_CheckDone{CheckDone: result}
	case event.Finished != nil:
		s := event.Finished
		out.Payload = &pb.ScanEvent_Finished{Finished: &pb.ScanSummary{
			Status:          pb.ScanStatus(pb.ScanStatus_value["SCAN_STATUS_"+strings.ToUpper(string(s.Status))]),
			Score:           s.Score,
			Grade:           pb.Grade(pb.Grade_value["GRADE_"+strings.ToUpper(s.Grade)]),
			CompletedChecks: int32(s.CompletedChecks), RequestedChecks: int32(s.RequestedChecks),
			Message:         s.Message,
			FinishedAt: timestamppb.New(s.FinishedAt),
		}}
	}
	return out
}
