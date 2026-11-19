package nucleirunner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
	"github.com/z1kkky/scaner/internal/web"
)

// This opt-in end-to-end test builds the pinned image and sends Nuclei only to
// a loopback fixture, using a test-only frozen policy dialer. It never scans a
// public hostname or address.
func TestDockerNucleiRunnerLoopbackFixture(t *testing.T) {
	requireDocker(t)

	fixture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/server-status" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Apache Server Status"))
			return
		}
		http.NotFound(w, r)
	})
	server := http.Server{Handler: fixture, ReadHeaderTimeout: 2 * time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portN, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(portN)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	policy, err := targetscope.FreezeWithDial(context.Background(), policyResolver{}, "example.com", []string{"example.com"}, []uint16{port}, dial)
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	relayBinary := filepath.Join(work, "scannerweb")
	build := exec.Command("go", "build", "-o", relayBinary, "../../cmd/scannerweb")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build scannerweb relay: %v: %s", err, out)
	}
	nucleiBinary, err := filepath.Abs(filepath.Join("..", "..", "nuclei", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	runner := New(Config{NucleiBinary: nucleiBinary, RelayExecutable: relayBinary, Timeout: 3 * time.Minute})
	ctx, cancelRun := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancelRun()
	result, err := runner.Run(ctx, web.ScanRequest{JobID: "local-fixture-test", OwnerID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Root: "example.com", Hosts: []string{"example.com"}, Ports: []uint16{port}, Policy: policy, Authorized: true})
	if err != nil {
		t.Fatalf("run only against loopback fixture: %v", err)
	}
	var report struct {
		Engine   string `json:"engine"`
		Findings []struct {
			TemplateID string `json:"template_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(result, &report); err != nil {
		t.Fatalf("decode result: %v (%s)", err, result)
	}
	if !strings.Contains(report.Engine, nucleiVersion) || len(report.Findings) != 1 || report.Findings[0].TemplateID != "scaner-apache-server-status" {
		t.Fatalf("unexpected report: %s", result)
	}

	// A second network-none container cannot open a direct TCP connection to
	// even a documentation-only address. The positive request above succeeded
	// exclusively through the mounted Unix socket and scoped host proxy.
	image := runner.image
	probe := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "/bin/bash", image, "-c", "timeout 2 /bin/bash -c 'echo probe >/dev/tcp/192.0.2.1/80'")
	if out, err := probe.CombinedOutput(); err == nil {
		t.Fatalf("network-none container unexpectedly opened direct TCP: %s", out)
	} else if !strings.Contains(strings.ToLower(string(out)), "network is unreachable") && !strings.Contains(strings.ToLower(string(out)), "no route to host") {
		t.Fatalf("direct network probe failed for an unexpected reason: %v: %s", err, out)
	}
}

func TestDockerNucleiRunnerLoopbackHTTPSFixture(t *testing.T) {
	requireDocker(t)
	var requests atomic.Int32
	fixture, roots := newTLSFixture(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Host != "example.com:443" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/server-status" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Apache Server Status"))
			return
		}
		http.NotFound(w, r)
	}))
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Listener.Addr().String())
	}
	policy, err := targetscope.FreezeWithDial(context.Background(), policyResolver{}, "example.com", []string{"example.com"}, []uint16{443}, dial)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	relayBinary := filepath.Join(work, "scannerweb")
	build := exec.Command("go", "build", "-o", relayBinary, "../../cmd/scannerweb")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build scannerweb relay: %v: %s", err, out)
	}
	nucleiBinary, err := filepath.Abs(filepath.Join("..", "..", "nuclei", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	runner := New(Config{NucleiBinary: nucleiBinary, RelayExecutable: relayBinary, Timeout: 3 * time.Minute})
	runner.testRoots = roots
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	const jobID = "local-https-fixture-test"
	result, err := runner.Run(ctx, web.ScanRequest{JobID: jobID, OwnerID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Root: "example.com", Hosts: []string{"example.com"}, Ports: []uint16{443}, Policy: policy, Authorized: true})
	if err != nil {
		t.Fatalf("run HTTPS Nuclei only against loopback fixture: %v", err)
	}
	var report struct {
		Engine   string `json:"engine"`
		Findings []struct {
			TemplateID string `json:"template_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(result, &report); err != nil {
		t.Fatalf("decode result: %v (%s)", err, result)
	}
	if requests.Load() == 0 {
		t.Fatal("HTTPS Nuclei job did not reach the loopback TLS fixture")
	}
	if !strings.Contains(report.Engine, nucleiVersion) || len(report.Findings) != 1 || report.Findings[0].TemplateID != "scaner-apache-server-status" {
		t.Fatalf("unexpected HTTPS report: %s", result)
	}
	name := "scaner-job-" + safeName(jobID)
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--type", "container", name).CombinedOutput()
	if err == nil || !containerMissing(out) {
		t.Fatalf("exact job container remains after completed runner: err=%v output=%s", err, out)
	}
}

func TestDockerNucleiRunnerReachableHTTPAndHTTPSWithoutFindings(t *testing.T) {
	requireDocker(t)
	var requests atomic.Int32
	httpFixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer httpFixture.Close()
	httpPort := uint16(httpFixture.Listener.Addr().(*net.TCPAddr).Port)
	httpsFixture, roots := newTLSFixture(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Host != "example.com:443" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		fixture := httpFixture.Listener.Addr().String()
		if portText == "443" {
			fixture = httpsFixture.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture)
	}
	policy, err := targetscope.FreezeWithDial(context.Background(), policyResolver{}, "example.com", []string{"example.com"}, []uint16{httpPort, 443}, dial)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	relayBinary := filepath.Join(work, "scannerweb")
	build := exec.Command("go", "build", "-o", relayBinary, "../../cmd/scannerweb")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build scannerweb relay: %v: %s", err, out)
	}
	nucleiBinary, err := filepath.Abs(filepath.Join("..", "..", "nuclei", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	runner := New(Config{NucleiBinary: nucleiBinary, RelayExecutable: relayBinary, Timeout: 3 * time.Minute})
	runner.testRoots = roots
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	result, err := runner.Run(ctx, web.ScanRequest{JobID: "local-no-findings-fixture", OwnerID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Root: "example.com", Hosts: []string{"example.com"}, Ports: []uint16{httpPort, 443}, Policy: policy, Authorized: true})
	if err != nil {
		t.Fatalf("reachable HTTP/HTTPS fixtures should complete even with no findings: %v", err)
	}
	var report struct {
		Engine   string `json:"engine"`
		Findings []any  `json:"findings"`
	}
	if err := json.Unmarshal(result, &report); err != nil {
		t.Fatalf("decode empty findings report: %v (%s)", err, result)
	}
	if len(report.Findings) != 0 || !strings.Contains(report.Engine, nucleiVersion) {
		t.Fatalf("unexpected no-findings report: %s", result)
	}
	if got := requests.Load(); got < 4 {
		t.Fatalf("expected both template paths on HTTP and HTTPS fixtures; received %d requests, want at least 4", got)
	}
}

func TestDockerNucleiRunnerCancellationRemovesExactContainer(t *testing.T) {
	requireDocker(t)
	requested := make(chan struct{}, 1)
	fixture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})
	server := http.Server{Handler: fixture, ReadHeaderTimeout: 2 * time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portN, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(portN)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	policy, err := targetscope.FreezeWithDial(context.Background(), policyResolver{}, "example.com", []string{"example.com"}, []uint16{port}, dial)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	relayBinary := filepath.Join(work, "scannerweb")
	build := exec.Command("go", "build", "-o", relayBinary, "../../cmd/scannerweb")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build scannerweb relay: %v: %s", err, out)
	}
	nucleiBinary, err := filepath.Abs(filepath.Join("..", "..", "nuclei", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	runner := New(Config{NucleiBinary: nucleiBinary, RelayExecutable: relayBinary, Timeout: 3 * time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	const jobID = "local-cancel-fixture-test"
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, web.ScanRequest{JobID: jobID, OwnerID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Root: "example.com", Hosts: []string{"example.com"}, Ports: []uint16{port}, Policy: policy, Authorized: true})
		done <- err
	}()
	select {
	case <-requested:
	case <-time.After(45 * time.Second):
		cancel()
		t.Fatal("Nuclei container never reached the local fixture")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled container run unexpectedly succeeded")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("runner did not finish cleanup after cancellation")
	}
	name := "scaner-job-" + safeName(jobID)
	out, err := exec.Command("docker", "inspect", "--type", "container", name).CombinedOutput()
	if err == nil || !containerMissing(out) {
		t.Fatalf("exact cancelled job container remains: err=%v output=%s", err, out)
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SCANER_DOCKER_TESTS") != "1" {
		t.Skip("set SCANER_DOCKER_TESTS=1 to run disposable-container integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI unavailable")
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(probeCtx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, out)
	}
}
