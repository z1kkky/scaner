package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
)

type testResolver struct{ txt []string }

func verifiedTestTarget(t *testing.T) (Target, *testResolver) {
	t.Helper()
	challenge, err := targetscope.NewChallenge("example.com")
	if err != nil {
		t.Fatal(err)
	}
	return Target{ID: "target", Host: challenge.Host, Challenge: challenge, ScopeHosts: []string{challenge.Host}, Ports: []uint16{443}, VerifiedAt: time.Now().UTC(), Verified: true}, &testResolver{txt: []string{challenge.Value}}
}

func (r *testResolver) LookupTXT(context.Context, string) ([]string, error) {
	return append([]string(nil), r.txt...), nil
}
func (*testResolver) LookupCNAME(_ context.Context, h string) (string, error) { return h + ".", nil }
func (*testResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}
func (*testResolver) ResolveTarget(_ context.Context, h string) ([]string, []netip.Addr, error) {
	return []string{h}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type txtSequenceResolver struct {
	testResolver
	mu        sync.Mutex
	responses [][]string
	lookups   int
}

func (r *txtSequenceResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.lookups
	r.lookups++
	if i >= len(r.responses) {
		i = len(r.responses) - 1
	}
	return append([]string(nil), r.responses[i]...), nil
}

type testRunner struct{}

func (testRunner) Run(context.Context, ScanRequest) (json.RawMessage, error) {
	return json.RawMessage(`{"ok":true}`), nil
}

type countingRunner struct{ calls atomic.Int32 }

func (r *countingRunner) Run(context.Context, ScanRequest) (json.RawMessage, error) {
	r.calls.Add(1)
	return json.RawMessage(`{"ok":true}`), nil
}

type partialResultRunner struct{}

func (partialResultRunner) Run(context.Context, ScanRequest) (json.RawMessage, error) {
	return json.RawMessage(`{"status":"incomplete","findings":[{"title":"preserved finding"}]}`), errors.New("container Nuclei failed")
}

type failedRecoveryRunner struct{}

func (failedRecoveryRunner) Run(context.Context, ScanRequest) (json.RawMessage, error) {
	return nil, errors.New("should not run")
}
func (failedRecoveryRunner) Reconcile(context.Context, string) error {
	return errors.New("Docker daemon unavailable")
}
func (failedRecoveryRunner) LiveReady() error {
	return errors.New("Docker daemon unavailable")
}

type countingResolver struct{ calls atomic.Int32 }

func (r *countingResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.calls.Add(1)
	return nil, nil
}
func (r *countingResolver) LookupCNAME(context.Context, string) (string, error) {
	r.calls.Add(1)
	return "", nil
}
func (r *countingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return nil, nil
}
func (r *countingResolver) ResolveTarget(_ context.Context, host string) ([]string, []netip.Addr, error) {
	r.calls.Add(1)
	return []string{host}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type blockingRunner struct{ started chan struct{} }

func (r blockingRunner) Run(ctx context.Context, _ ScanRequest) (json.RawMessage, error) {
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

type gatedRunner struct {
	started   chan struct{}
	release   chan struct{}
	calls     atomic.Int32
	startOnce sync.Once
}

func (r *gatedRunner) Run(ctx context.Context, _ ScanRequest) (json.RawMessage, error) {
	r.calls.Add(1)
	r.startOnce.Do(func() { close(r.started) })
	select {
	case <-r.release:
		return json.RawMessage(`{"ok":true}`), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type blockingTXTResolver struct {
	txt     []string
	started chan struct{}
	release chan struct{}
	ready   chan struct{}
	calls   atomic.Int32
	once    sync.Once
}

func (r *blockingTXTResolver) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	call := r.calls.Add(1)
	r.once.Do(func() { close(r.started) })
	if r.ready != nil && call == 2 {
		close(r.ready)
	}
	select {
	case <-r.release:
		return append([]string(nil), r.txt...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*blockingTXTResolver) LookupCNAME(_ context.Context, h string) (string, error) {
	return h + ".", nil
}
func (*blockingTXTResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}
func (*blockingTXTResolver) ResolveTarget(_ context.Context, host string) ([]string, []netip.Addr, error) {
	return []string{host}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func apiPost(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Host = "127.0.0.1:8787"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func saveState(t *testing.T, dir string, state diskState) {
	t.Helper()
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestListenAddressRequiresLoopback(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:8787", ":8787", "localhost:8787", "192.0.2.1:8787", "127.0.0.1:0", "127.0.0.1:nope"} {
		if _, e := ListenAddress(bad); e == nil {
			t.Errorf("ListenAddress(%q) unexpectedly accepted", bad)
		}
	}
	if got, e := ListenAddress("127.0.0.1:8787"); e != nil || got != "127.0.0.1:8787" {
		t.Fatalf("got %q, %v", got, e)
	}
}

func TestRootServesRussianLocalUIWithLiveActionsGated(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir(), Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.Handler()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "127.0.0.1:8787"
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("root status = %d, body %s", response.Code, response.Body)
	}
	page := response.Body.String()
	for _, want := range []string{"lang=\"ru\"", "Локальный прототип", "id=\"scoreRing\"", "id=\"scoreArc\"", "id=\"overlay\"", "data-action=\"add\"", "id=\"findings\""} {
		if !strings.Contains(page, want) {
			t.Errorf("UI missing gated/local marker %q", want)
		}
	}
	if got := response.Header().Get("Content-Security-Policy"); !strings.Contains(got, "connect-src 'self'") || !strings.Contains(got, "object-src 'none'") {
		t.Fatalf("unexpected UI Content-Security-Policy: %q", got)
	}

	jsRequest := httptest.NewRequest(http.MethodGet, "/ui/app.js", nil)
	jsRequest.Host = "127.0.0.1:8787"
	jsResponse := httptest.NewRecorder()
	h.ServeHTTP(jsResponse, jsRequest)
	if jsResponse.Code != http.StatusOK || !strings.Contains(jsResponse.Body.String(), `if (!target?.verified || !byID("modalAuthorized")?.checked) return;`) {
		t.Fatalf("live UI action gate missing: status=%d", jsResponse.Code)
	}
}

func TestChallengeAPIUsesBrowserJSONContractAndStartsUnverified(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir(), Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := apiPost(s.Handler(), "/api/targets/challenge", `{"host":"Example.com"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("challenge status=%d body=%s", w.Code, w.Body)
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["verified"] != false {
		t.Fatalf("new target verified=%v, want false", payload["verified"])
	}
	challenge, ok := payload["challenge"].(map[string]any)
	if !ok || challenge["record"] == nil || challenge["value"] == nil || challenge["Record"] != nil || challenge["Value"] != nil {
		t.Fatalf("challenge JSON does not match browser contract: %#v", payload["challenge"])
	}
}

func TestDemoIsDeterministicPersistedAndMakesNoTargetOrRunnerCalls(t *testing.T) {
	dir := t.TempDir()
	resolver := &countingResolver{}
	runner := &countingRunner{}
	s, err := New(Config{DataDir: dir, Resolver: resolver, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	withoutOrigin := httptest.NewRequest(http.MethodPost, "/api/demo", strings.NewReader(`{}`))
	withoutOrigin.Header.Set("Content-Type", "application/json")
	withoutOrigin.Host = "127.0.0.1:8787"
	withoutOriginResponse := httptest.NewRecorder()
	h.ServeHTTP(withoutOriginResponse, withoutOrigin)
	if withoutOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin demo request status = %d", withoutOriginResponse.Code)
	}
	firstResponse := apiPost(h, "/api/demo", `{}`)
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("create demo job: %d %s", firstResponse.Code, firstResponse.Body)
	}
	var job Job
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if !job.Simulation || job.Status != "completed" || job.TargetID != "" || job.Authorization != "" {
		t.Fatalf("demo job not clearly separate from a live scan: %+v", job)
	}
	var report demoReport
	if err := json.Unmarshal(job.Result, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Simulation || report.Score != 72 || report.Grade != "C" || len(report.Findings) == 0 || !strings.Contains(report.Disclaimer, "не результат реального сканирования") {
		t.Fatalf("demo report is not labeled as simulated: %+v", report)
	}
	if runner.calls.Load() != 0 || resolver.calls.Load() != 0 {
		t.Fatalf("demo touched scan/network dependencies: runner=%d resolver=%d", runner.calls.Load(), resolver.calls.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The deterministic payload remains byte-for-byte stable, and history survives restart.
	if got := deterministicDemoReport(); string(got) != string(job.Result) {
		t.Fatalf("demo payload is not deterministic: got %s, want %s", got, job.Result)
	}
	s2, err := New(Config{DataDir: dir, Resolver: resolver, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.mu.Lock()
	restored, ok := s2.state.Jobs[job.ID]
	s2.mu.Unlock()
	if !ok {
		t.Fatalf("demo job was not restored: %s", job.ID)
	}
	var restoredReport demoReport
	if err := json.Unmarshal(restored.Result, &restoredReport); err != nil {
		t.Fatal(err)
	}
	if !restored.Simulation || restored.Status != "completed" || !reflect.DeepEqual(restoredReport, report) {
		t.Fatalf("demo history did not persist unchanged: %+v", restored)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/jobs/"+job.ID, nil)
	deleteRequest.Host = "127.0.0.1:8787"
	deleteRequest.Header.Set("Origin", "http://127.0.0.1:8787")
	deleteResponse := httptest.NewRecorder()
	s2.Handler().ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete demo history: %d %s", deleteResponse.Code, deleteResponse.Body)
	}
	if runner.calls.Load() != 0 || resolver.calls.Load() != 0 {
		t.Fatalf("demo/report persistence used live dependencies: runner=%d resolver=%d", runner.calls.Load(), resolver.calls.Load())
	}
}

func TestLocalAPIRequiresSameOriginAndAuthorizationThenPersistsJob(t *testing.T) {
	dir := t.TempDir()
	resolver := &testResolver{}
	s, err := New(Config{DataDir: dir, Resolver: resolver, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/targets/challenge", strings.NewReader(`{"host":"Example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8787"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin-less request code=%d", w.Code)
	}
	badHost := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	badHost.Host = "attacker.example"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, badHost)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host code=%d", w.Code)
	}
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8787")
		r.Host = "127.0.0.1:8787"
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		return out
	}
	w = post("/api/targets/challenge", `{"host":"Example.com"}`)
	if w.Code != 201 {
		t.Fatalf("challenge: %d %s", w.Code, w.Body)
	}
	var target Target
	if err = json.Unmarshal(w.Body.Bytes(), &target); err != nil {
		t.Fatal(err)
	}
	resolver.txt = []string{target.Challenge.Value}
	w = post("/api/targets/verify", `{"target_id":"`+target.ID+`"}`)
	if w.Code != 200 {
		t.Fatalf("verify: %d %s", w.Code, w.Body)
	}
	w = post("/api/jobs", `{"target_id":"`+target.ID+`","hosts":["other.example.com"],"authorized":true,"authorization":"written permission"}`)
	if w.Code != 422 {
		t.Fatalf("unselected subdomain accepted: %d", w.Code)
	}
	w = post("/api/jobs", `{"target_id":"`+target.ID+`","authorized":true}`)
	if w.Code != 400 {
		t.Fatalf("missing attestation: %d", w.Code)
	}
	w = post("/api/jobs", `{"target_id":"`+target.ID+`","authorized":true,"authorization":"I have written permission"}`)
	if w.Code != 202 {
		t.Fatalf("create job: %d %s", w.Code, w.Body)
	}
	var job Job
	if err = json.Unmarshal(w.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second * 2)
	for time.Now().Before(deadline) {
		r := httptest.NewRequest(http.MethodGet, "/api/jobs/"+job.ID, nil)
		r.Host = "127.0.0.1:8787"
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		_ = json.Unmarshal(out.Body.Bytes(), &job)
		if job.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if job.Status != "completed" || string(job.Result) != `{"ok":true}` {
		t.Fatalf("job did not complete: %+v", job)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := New(Config{DataDir: dir, Resolver: resolver, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.mu.Lock()
	got, ok := s2.state.Jobs[job.ID]
	s2.mu.Unlock()
	if !ok {
		t.Fatalf("persisted job missing: %+v", got)
	}
	var result map[string]bool
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatalf("invalid persisted result: %v", err)
	}
	if got.Status != "completed" || !result["ok"] {
		t.Fatalf("persisted job missing: %+v", got)
	}
}

func TestRunningJobCanBeCancelled(t *testing.T) {
	dir := t.TempDir()
	started := make(chan struct{})
	target, resolver := verifiedTestTarget(t)
	s, err := New(Config{DataDir: dir, Resolver: resolver, Runner: blockingRunner{started: started}})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.state.Targets["target"] = target
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	h := s.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8787")
		r.Host = "127.0.0.1:8787"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := post("/api/jobs", `{"target_id":"target","authorized":true,"authorization":"permission recorded"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create job: %d %s", w.Code, w.Body)
	}
	var job Job
	if err = json.Unmarshal(w.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	w = post("/api/jobs/"+job.ID+"/cancel", `{}`)
	if w.Code != 200 {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		job = s.state.Jobs[job.ID]
		s.mu.Unlock()
		if job.Status == "cancelled" {
			break
		}
		time.Sleep(time.Millisecond * 5)
	}
	if job.Status != "cancelled" {
		t.Fatalf("job status after cancellation: %q", job.Status)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRestartMarksRunningJobInterrupted(t *testing.T) {
	dir := t.TempDir()
	state := diskState{Targets: map[string]Target{}, Jobs: map[string]Job{"running": {ID: "running", Status: "running"}}}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "state.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job := s.state.Jobs["running"]
	if job.Status != "interrupted" || job.FinishedAt.IsZero() {
		t.Fatalf("restart state: %+v", job)
	}
}

func TestDataDirectoryLockAndOwnerIdentityPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	ownerID := s.ownerID
	if len(ownerID) != 32 {
		t.Fatalf("owner ID has unexpected form: %q", ownerID)
	}
	if _, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}}); err == nil {
		t.Fatal("second process acquired an in-use data directory")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatalf("reopen released data directory: %v", err)
	}
	defer restarted.Close()
	if restarted.ownerID != ownerID {
		t.Fatalf("owner ID changed across restart: %q != %q", restarted.ownerID, ownerID)
	}
	if req := restarted.requestFor(Job{ID: "job", TargetID: "target"}); req.OwnerID != ownerID {
		t.Fatalf("scan request owner ID = %q, want %q", req.OwnerID, ownerID)
	}
}

func TestDataDirectoryLockReleasedWhenInitializationFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}}); err == nil {
		t.Fatal("invalid persisted state unexpectedly loaded")
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"targets":{},"jobs":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatalf("failed initialization leaked the data lock: %v", err)
	}
	defer s.Close()
}

func TestContainerRecoveryFailureKeepsDemoAvailableAndBlocksLiveJobs(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir(), Resolver: &testResolver{}, Runner: failedRecoveryRunner{}})
	if err != nil {
		t.Fatalf("recovery failure should not prevent local UI startup: %v", err)
	}
	defer s.Close()
	if out := apiPost(s.Handler(), "/api/demo", `{}`); out.Code != http.StatusCreated {
		t.Fatalf("demo unavailable after cleanup failure: %d %s", out.Code, out.Body)
	}
	if out := apiPost(s.Handler(), "/api/jobs", `{"authorized":true,"authorization":"written permission"}`); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("live job accepted after cleanup failure: %d %s", out.Code, out.Body)
	}
}

func TestDeletingTargetRemovesItsLocalHistory(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir(), Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	s.state.Targets["target"] = Target{ID: "target", Host: "example.com"}
	s.state.Jobs["job"] = Job{ID: "job", TargetID: "target", Status: "completed"}
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	r := httptest.NewRequest(http.MethodDelete, "/api/targets/target", nil)
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete target: %d %s", w.Code, w.Body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Targets["target"]; ok {
		t.Fatal("target remains after deletion")
	}
	if _, ok := s.state.Jobs["job"]; ok {
		t.Fatal("target's local job history remains after deletion")
	}
}

func TestRestoreQueuedJobsBeforeStartingWorker(t *testing.T) {
	dir := t.TempDir()
	created := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	target, resolver := verifiedTestTarget(t)
	state := diskState{
		Targets: map[string]Target{"target": target},
		Jobs: map[string]Job{
			"b": {ID: "b", TargetID: "target", Hosts: []string{"example.com"}, Ports: []uint16{443}, Status: "queued", CreatedAt: created},
			"a": {ID: "a", TargetID: "target", Hosts: []string{"example.com"}, Ports: []uint16{443}, Status: "queued", CreatedAt: created},
		},
	}
	saveState(t, dir, state)
	runner := &gatedRunner{started: make(chan struct{}), release: make(chan struct{})}
	s, err := New(Config{DataDir: dir, QueueCapacity: 2, Resolver: resolver, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("restored worker did not start")
	}
	if runner.calls.Load() != 1 {
		t.Fatalf("runner calls after first restored job: %d", runner.calls.Load())
	}
	close(runner.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runner.calls.Load() == 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected two restored jobs to run, got %d", runner.calls.Load())
}

func TestRestoreQueueOverCapacityDoesNotStartRunner(t *testing.T) {
	dir := t.TempDir()
	targets := map[string]Target{"target": {ID: "target", Host: "example.com"}}
	jobs := map[string]Job{}
	for _, id := range []string{"a", "b", "c"} {
		jobs[id] = Job{ID: id, TargetID: "target", Hosts: []string{"example.com"}, Ports: []uint16{443}, Status: "queued"}
	}
	saveState(t, dir, diskState{Targets: targets, Jobs: jobs})
	runner := &gatedRunner{started: make(chan struct{}), release: make(chan struct{})}
	if _, err := New(Config{DataDir: dir, QueueCapacity: 2, Resolver: &testResolver{}, Runner: runner}); err == nil {
		t.Fatal("New accepted restored queue beyond configured capacity")
	}
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("runner invoked during failed initialization: %d", got)
	}
}

func TestJobRechecksTXTAtExecution(t *testing.T) {
	for _, tc := range []struct {
		name      string
		execution []string
	}{
		{name: "record removed"},
		{name: "record changed", execution: []string{"scaner-verification=not-the-challenge"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := targetscope.NewChallenge("example.com")
			if err != nil {
				t.Fatal(err)
			}
			resolver := &txtSequenceResolver{responses: [][]string{{challenge.Value}, tc.execution}}
			runner := &countingRunner{}
			s, err := New(Config{DataDir: t.TempDir(), Resolver: resolver, Runner: runner})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			s.mu.Lock()
			s.state.Targets["target"] = Target{ID: "target", Host: challenge.Host, Challenge: challenge}
			if err := s.persistLocked(); err != nil {
				s.mu.Unlock()
				t.Fatal(err)
			}
			s.mu.Unlock()
			if out := apiPost(s.Handler(), "/api/targets/verify", `{"target_id":"target","ports":[443]}`); out.Code != http.StatusOK {
				t.Fatalf("initial TXT verification: %d %s", out.Code, out.Body)
			}

			out := apiPost(s.Handler(), "/api/jobs", `{"target_id":"target","authorized":true,"authorization":"written permission"}`)
			if out.Code != http.StatusAccepted {
				t.Fatalf("create job: %d %s", out.Code, out.Body)
			}
			var job Job
			if err := json.Unmarshal(out.Body.Bytes(), &job); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				s.mu.Lock()
				got := s.state.Jobs[job.ID]
				s.mu.Unlock()
				if got.Status == "failed" {
					if !strings.Contains(got.Error, "DNS TXT verification failed at job execution") {
						t.Fatalf("unexpected failed-job reason: %+v", got)
					}
					if calls := runner.calls.Load(); calls != 0 {
						t.Fatalf("runner called %d times after TXT proof disappeared", calls)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("job did not fail after the TXT proof disappeared or changed")
		})
	}
}

func TestPartialRunnerResultIsPersistedAsIncomplete(t *testing.T) {
	target, resolver := verifiedTestTarget(t)
	s, err := New(Config{DataDir: t.TempDir(), Resolver: resolver, Runner: partialResultRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	s.state.Targets[target.ID] = target
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	out := apiPost(s.Handler(), "/api/jobs", `{"target_id":"target","authorized":true,"authorization":"written permission"}`)
	if out.Code != http.StatusAccepted {
		t.Fatalf("create job: %d %s", out.Code, out.Body)
	}
	var accepted Job
	if err := json.Unmarshal(out.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		job := s.state.Jobs[accepted.ID]
		s.mu.Unlock()
		if job.Status == "incomplete" {
			if !strings.Contains(job.Error, "container Nuclei failed") || len(job.Result) == 0 || !json.Valid(job.Result) {
				t.Fatalf("incomplete result/error was not preserved: %+v", job)
			}
			var report map[string]any
			if err := json.Unmarshal(job.Result, &report); err != nil || report["status"] != "incomplete" {
				t.Fatalf("invalid partial report: %#v, err=%v", report, err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("partial report was not persisted as incomplete")
}

func TestVerificationCannotResurrectDeletedTarget(t *testing.T) {
	dir := t.TempDir()
	challenge, err := targetscope.NewChallenge("example.com")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &blockingTXTResolver{txt: []string{challenge.Value}, started: make(chan struct{}), release: make(chan struct{})}
	s, err := New(Config{DataDir: dir, Resolver: resolver, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	s.state.Targets["target"] = Target{ID: "target", Host: challenge.Host, Challenge: challenge}
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	h := s.Handler()
	verifyDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		verifyDone <- apiPost(h, "/api/targets/verify", `{"target_id":"target"}`)
	}()
	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		t.Fatal("verification did not reach TXT resolver")
	}
	del := httptest.NewRequest(http.MethodDelete, "/api/targets/target", nil)
	del.Host = "127.0.0.1:8787"
	del.Header.Set("Origin", "http://127.0.0.1:8787")
	delOut := httptest.NewRecorder()
	h.ServeHTTP(delOut, del)
	if delOut.Code != http.StatusNoContent {
		t.Fatalf("delete target: %d %s", delOut.Code, delOut.Body)
	}
	close(resolver.release)
	select {
	case verify := <-verifyDone:
		if verify.Code != http.StatusConflict {
			t.Fatalf("stale verification status: %d %s", verify.Code, verify.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("verification did not finish")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Targets["target"]; ok {
		t.Fatal("verification resurrected deleted target")
	}
}

func TestConcurrentVerificationRejectsStaleScopeUpdate(t *testing.T) {
	dir := t.TempDir()
	challenge, err := targetscope.NewChallenge("example.com")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &blockingTXTResolver{txt: []string{challenge.Value}, started: make(chan struct{}), ready: make(chan struct{}), release: make(chan struct{})}
	s, err := New(Config{DataDir: dir, Resolver: resolver, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	s.state.Targets["target"] = Target{ID: "target", Host: challenge.Host, Challenge: challenge}
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	h := s.Handler()
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, subdomain := range []string{"one.example.com", "two.example.com"} {
		go func(host string) {
			results <- apiPost(h, "/api/targets/verify", `{"target_id":"target","subdomains":["`+host+`"]}`)
		}(subdomain)
	}
	select {
	case <-resolver.ready:
	case <-time.After(time.Second):
		t.Fatal("both verifications did not reach TXT resolution")
	}
	close(resolver.release)
	statuses := map[int]int{}
	for range 2 {
		select {
		case out := <-results:
			statuses[out.Code]++
		case <-time.After(time.Second):
			t.Fatal("verification did not finish")
		}
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusConflict] != 1 {
		t.Fatalf("verification statuses: %v, want one success and one conflict", statuses)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.state.Targets["target"]
	if target.Revision != 1 || len(target.ScopeHosts) != 2 {
		t.Fatalf("stale update overwrote accepted scope: %+v", target)
	}
}

func TestFullQueueDoesNotPersistRejectedJob(t *testing.T) {
	dir := t.TempDir()
	runner := &gatedRunner{started: make(chan struct{}), release: make(chan struct{})}
	target, resolver := verifiedTestTarget(t)
	s, err := New(Config{DataDir: dir, QueueCapacity: 1, Resolver: resolver, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	s.state.Targets["target"] = target
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	request := `{"target_id":"target","authorized":true,"authorization":"written permission"}`
	if out := apiPost(s.Handler(), "/api/jobs", request); out.Code != http.StatusAccepted {
		t.Fatalf("first job: %d %s", out.Code, out.Body)
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("first job did not start")
	}
	if out := apiPost(s.Handler(), "/api/jobs", request); out.Code != http.StatusAccepted {
		t.Fatalf("second queued job: %d %s", out.Code, out.Body)
	}
	if out := apiPost(s.Handler(), "/api/jobs", request); out.Code != http.StatusTooManyRequests {
		t.Fatalf("full-queue job: %d %s", out.Code, out.Body)
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var disk diskState
	if err = json.Unmarshal(b, &disk); err != nil {
		t.Fatal(err)
	}
	if got := len(disk.Jobs); got != 2 {
		t.Fatalf("persisted jobs after queue rejection: %d, want only accepted jobs", got)
	}
	close(runner.release)
}

func TestTerminalPersistenceFailureIsVisibleAndStopsNewJobs(t *testing.T) {
	dir := t.TempDir()
	runner := &gatedRunner{started: make(chan struct{}), release: make(chan struct{})}
	target, resolver := verifiedTestTarget(t)
	s, err := New(Config{DataDir: dir, Resolver: resolver, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.state.Targets["target"] = target
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	out := apiPost(s.Handler(), "/api/jobs", `{"target_id":"target","authorized":true,"authorization":"written permission"}`)
	if out.Code != http.StatusAccepted {
		t.Fatalf("create job: %d %s", out.Code, out.Body)
	}
	var job Job
	if err = json.Unmarshal(out.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}
	s.mu.Lock()
	s.persistFn = func(string, []byte) error { return errors.New("disk full") }
	s.mu.Unlock()
	close(runner.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := s.state.Jobs[job.ID]
		s.mu.Unlock()
		if got.Status == "failed" {
			if !strings.Contains(got.Error, "terminal job state") || !strings.Contains(got.Error, "disk full") {
				t.Fatalf("missing persistence failure detail: %+v", got)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	s.mu.Lock()
	got := s.state.Jobs[job.ID]
	storageErr := s.storageErr
	s.mu.Unlock()
	if got.Status != "failed" || storageErr == "" {
		t.Fatalf("terminal failure not visible: job=%+v storageErr=%q", got, storageErr)
	}
	if out := apiPost(s.Handler(), "/api/jobs", `{"target_id":"target","authorized":true,"authorization":"written permission"}`); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("job accepted after storage failure: %d %s", out.Code, out.Body)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	// The last durable record is still running; startup records the interruption
	// instead of silently claiming the result was saved.
	s2, err := New(Config{DataDir: dir, Resolver: &testResolver{}, Runner: testRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.mu.Lock()
	restored := s2.state.Jobs[job.ID]
	s2.mu.Unlock()
	if restored.Status != "interrupted" {
		t.Fatalf("unsaved result was not visibly interrupted after restart: %+v", restored)
	}
}

func TestTerminalPersistenceFailureStopsAlreadyQueuedJobs(t *testing.T) {
	dir := t.TempDir()
	runner := &gatedRunner{started: make(chan struct{}), release: make(chan struct{})}
	target, resolver := verifiedTestTarget(t)
	s, err := New(Config{DataDir: dir, QueueCapacity: 2, Resolver: resolver, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.state.Targets["target"] = target
	if err = s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	create := func() Job {
		out := apiPost(s.Handler(), "/api/jobs", `{"target_id":"target","authorized":true,"authorization":"written permission"}`)
		if out.Code != http.StatusAccepted {
			t.Fatalf("create job: %d %s", out.Code, out.Body)
		}
		var job Job
		if err := json.Unmarshal(out.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		return job
	}
	first := create()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("first job did not start")
	}
	second := create()
	s.mu.Lock()
	s.persistFn = func(string, []byte) error { return errors.New("disk full") }
	s.mu.Unlock()
	close(runner.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		firstState := s.state.Jobs[first.ID]
		s.mu.Unlock()
		if firstState.Status == "failed" && strings.Contains(firstState.Error, "terminal job state") {
			break
		}
		time.Sleep(time.Millisecond)
	}
	s.mu.Lock()
	firstState := s.state.Jobs[first.ID]
	secondState := s.state.Jobs[second.ID]
	s.mu.Unlock()
	if firstState.Status != "failed" || !strings.Contains(firstState.Error, "disk full") {
		t.Fatalf("terminal persistence failure not recorded: %+v", firstState)
	}
	if secondState.Status != "queued" {
		t.Fatalf("later job did not remain queued: %+v", secondState)
	}
	if got := runner.calls.Load(); got != 1 {
		t.Fatalf("runner calls after terminal persistence failure: %d, want 1", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var disk diskState
	if err := json.Unmarshal(b, &disk); err != nil {
		t.Fatal(err)
	}
	if got := disk.Jobs[second.ID].Status; got != "queued" {
		t.Fatalf("durable later job status = %q, want queued", got)
	}
}
