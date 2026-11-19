// Package web provides the local control plane for the Scaner prototype.
// It deliberately contains no scanner implementation: a Runner is injected
// by the application once the sandboxed execution layer is available.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
)

const maxRequestBytes = 64 << 10

type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type ScanRequest struct {
	JobID      string              `json:"job_id"`
	OwnerID    string              `json:"-"`
	Root       string              `json:"root"`
	Hosts      []string            `json:"hosts"`
	Ports      []uint16            `json:"ports"`
	Policy     *targetscope.Policy `json:"-"`
	Authorized bool                `json:"authorized"`
}

type Runner interface {
	Run(context.Context, ScanRequest) (json.RawMessage, error)
}

// ContainerReconciler removes only containers provably owned by this local
// data store before the service starts accepting live jobs.
type ContainerReconciler interface {
	Reconcile(context.Context, string) error
}

// LiveReadiness reports whether the runner can safely accept another job.
type LiveReadiness interface {
	LiveReady() error
}

type Config struct {
	DataDir       string
	QueueCapacity int
	Resolver      Resolver
	Runner        Runner
}

type Target struct {
	ID         string                `json:"id"`
	Revision   uint64                `json:"revision,omitempty"`
	Host       string                `json:"host"`
	Challenge  targetscope.Challenge `json:"challenge"`
	ScopeHosts []string              `json:"scope_hosts,omitempty"`
	Ports      []uint16              `json:"ports,omitempty"`
	VerifiedAt time.Time             `json:"verified_at,omitempty"`
	Verified   bool                  `json:"verified"`
}

type Job struct {
	ID            string          `json:"id"`
	Simulation    bool            `json:"simulation,omitempty"`
	TargetID      string          `json:"target_id"`
	Hosts         []string        `json:"hosts"`
	Ports         []uint16        `json:"ports"`
	Status        string          `json:"status"`
	Authorization string          `json:"authorization"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     time.Time       `json:"started_at,omitempty"`
	FinishedAt    time.Time       `json:"finished_at,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         string          `json:"error,omitempty"`
}

type diskState struct {
	InstanceID string            `json:"instance_id,omitempty"`
	Targets    map[string]Target `json:"targets"`
	Jobs       map[string]Job    `json:"jobs"`
}
type task struct {
	id  string
	req ScanRequest
}

type Service struct {
	mu          sync.Mutex
	state       diskState
	path        string
	ownerID     string
	dataLock    dataDirLock
	resolver    Resolver
	runner      Runner
	queue       chan task
	ctx         context.Context
	cancel      context.CancelFunc
	jobCancel   map[string]context.CancelFunc
	wg          sync.WaitGroup
	closed      bool
	storageErr  string
	recoveryErr string
	persistFn   func(string, []byte) error
}

func New(cfg Config) (*Service, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("data directory is required")
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 8
	}
	if cfg.Resolver == nil {
		cfg.Resolver = targetscope.SystemResolver()
	}
	if cfg.Runner == nil {
		cfg.Runner = runnerUnavailable{}
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, err
	}
	dataLock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	lockTransferred := false
	defer func() {
		if !lockTransferred {
			_ = dataLock.Close()
		}
	}()
	s := &Service{path: filepath.Join(cfg.DataDir, "state.json"), resolver: cfg.Resolver, runner: cfg.Runner,
		dataLock: dataLock, queue: make(chan task, cfg.QueueCapacity), jobCancel: make(map[string]context.CancelFunc)}
	if err := s.load(); err != nil {
		return nil, err
	}
	if s.state.InstanceID == "" {
		s.state.InstanceID, err = randomID()
		if err != nil {
			return nil, fmt.Errorf("create local container owner id: %w", err)
		}
	} else if id, decodeErr := hex.DecodeString(s.state.InstanceID); decodeErr != nil || len(id) != 16 {
		return nil, errors.New("persisted local container owner ID is invalid")
	}
	s.ownerID = s.state.InstanceID
	// Persist the stable owner identity before inspecting/removing containers.
	// A crash during reconciliation must resume with the same identity.
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	if reconciler, ok := s.runner.(ContainerReconciler); ok {
		reconcileCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := reconciler.Reconcile(reconcileCtx, s.ownerID)
		cancel()
		if err != nil {
			s.recoveryErr = "live scans are disabled until container ownership can be verified: " + err.Error()
		}
	}
	// A process restart cannot resume an in-flight container safely. Preserve
	// its history but mark it interrupted; only queued jobs are re-enqueued.
	for id, j := range s.state.Jobs {
		if j.Status == "running" {
			j.Status = "interrupted"
			j.Error = "service restarted while job was running"
			j.FinishedAt = time.Now().UTC()
			s.state.Jobs[id] = j
		}
	}
	queued := make([]Job, 0)
	for _, j := range s.state.Jobs {
		if j.Status == "queued" {
			queued = append(queued, j)
		}
	}
	sort.Slice(queued, func(i, j int) bool {
		if queued[i].CreatedAt.Equal(queued[j].CreatedAt) {
			return queued[i].ID < queued[j].ID
		}
		return queued[i].CreatedAt.Before(queued[j].CreatedAt)
	})
	if len(queued) > cfg.QueueCapacity {
		return nil, errors.New("persisted queue exceeds configured capacity")
	}
	for _, j := range queued {
		if _, ok := s.state.Targets[j.TargetID]; !ok {
			return nil, fmt.Errorf("queued job %s references missing target", j.ID)
		}
		s.queue <- task{id: j.ID, req: s.requestFor(j)}
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.worker()
	lockTransferred = true
	return s, nil
}

type runnerUnavailable struct{}

func (runnerUnavailable) Run(context.Context, ScanRequest) (json.RawMessage, error) {
	return nil, errors.New("scan runner is not configured")
}

func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for _, cancel := range s.jobCancel {
		cancel()
	}
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
	return s.dataLock.Close()
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.serveIndex)
	mux.HandleFunc("GET /ui/app.js", s.serveAppJS)
	mux.HandleFunc("GET /ui/style.css", s.serveStyleCSS)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /api/targets/challenge", s.createChallenge)
	mux.HandleFunc("POST /api/targets/verify", s.verifyTarget)
	mux.HandleFunc("POST /api/demo", s.createDemoJob)
	mux.HandleFunc("GET /api/targets", s.listTargets)
	mux.HandleFunc("DELETE /api/targets/{id}", s.deleteTarget)
	mux.HandleFunc("POST /api/jobs", s.createJob)
	mux.HandleFunc("GET /api/jobs", s.listJobs)
	mux.HandleFunc("GET /api/jobs/{id}", s.getJob)
	mux.HandleFunc("DELETE /api/jobs/{id}", s.deleteJob)
	mux.HandleFunc("POST /api/jobs/{id}/cancel", s.cancelJob)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedRequestHost(r.Host) {
			http.Error(w, "loopback host required", http.StatusForbidden)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !sameOrigin(r) {
				http.Error(w, "same-origin request required", http.StatusForbidden)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" && strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "DELETE" {
				http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func allowedRequestHost(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

// ListenAddress accepts only loopback literals, preventing accidental exposure.
func ListenAddress(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	n, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || !ip.IsLoopback() || portErr != nil || n == 0 {
		return "", errors.New("web server address must be a loopback IP and explicit port")
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	return allowedRequestHost(r.Host)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

type challengeInput struct {
	Host string `json:"host"`
}

func (s *Service) createChallenge(w http.ResponseWriter, r *http.Request) {
	var in challengeInput
	if decode(w, r, &in) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	c, e := targetscope.NewChallenge(in.Host)
	if e != nil {
		http.Error(w, "invalid hostname", 400)
		return
	}
	id, e := randomID()
	if e != nil {
		http.Error(w, "internal error", 500)
		return
	}
	t := Target{ID: id, Host: c.Host, Challenge: c}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		http.Error(w, "service unavailable", 503)
		return
	}
	if s.storageErr != "" {
		http.Error(w, "local storage is unavailable; restart the service after resolving the storage error", http.StatusServiceUnavailable)
		return
	}
	s.state.Targets[id] = t
	if e = s.persistLocked(); e != nil {
		delete(s.state.Targets, id)
		http.Error(w, "storage error", 500)
		return
	}
	writeJSON(w, 201, t)
}

type verifyInput struct {
	TargetID   string   `json:"target_id"`
	Subdomains []string `json:"subdomains,omitempty"`
	Ports      []uint16 `json:"ports,omitempty"`
}

func (s *Service) verifyTarget(w http.ResponseWriter, r *http.Request) {
	var in verifyInput
	if decode(w, r, &in) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	s.mu.Lock()
	t, ok := s.state.Targets[in.TargetID]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "target not found", 404)
		return
	}
	if e := targetscope.VerifyTXT(r.Context(), s.resolver, t.Challenge); e != nil {
		http.Error(w, "DNS TXT verification failed", 422)
		return
	}
	hosts := make([]string, 0, len(in.Subdomains)+1)
	hosts = append(hosts, t.Host)
	for _, h := range in.Subdomains {
		hosts = append(hosts, normalizeHost(h))
	}
	ports := in.Ports
	if len(ports) == 0 {
		ports = []uint16{80, 443}
	}
	if _, e := targetscope.Freeze(r.Context(), s.resolver, t.Host, hosts, ports); e != nil {
		http.Error(w, "target scope rejected", 422)
		return
	}
	t.VerifiedAt = time.Now().UTC()
	t.Verified = true
	t.ScopeHosts = append([]string(nil), hosts...)
	t.Ports = append([]uint16(nil), ports...)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.state.Targets[t.ID]
	if !ok {
		http.Error(w, "target was deleted during verification", http.StatusConflict)
		return
	}
	if current.Revision != t.Revision || current.Host != t.Host || current.Challenge != t.Challenge {
		http.Error(w, "target changed during verification; retry", http.StatusConflict)
		return
	}
	previous := current
	t.Revision++
	s.state.Targets[t.ID] = t
	if e := s.persistLocked(); e != nil {
		s.state.Targets[t.ID] = previous
		http.Error(w, "storage error", 500)
		return
	}
	writeJSON(w, 200, t)
}
func (s *Service) listTargets(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Target, 0, len(s.state.Targets))
	for _, t := range s.state.Targets {
		t.Verified = !t.VerifiedAt.IsZero()
		out = append(out, t)
	}
	writeJSON(w, 200, out)
}

func (s *Service) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Targets[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	for _, j := range s.state.Jobs {
		if j.TargetID == id && (j.Status == "queued" || j.Status == "running") {
			http.Error(w, "cancel active jobs before deleting target", http.StatusConflict)
			return
		}
	}
	delete(s.state.Targets, id)
	removed := make(map[string]Job)
	for jobID, j := range s.state.Jobs {
		if j.TargetID == id {
			removed[jobID] = j
			delete(s.state.Jobs, jobID)
		}
	}
	if err := s.persistLocked(); err != nil {
		s.state.Targets[id] = t
		for jobID, j := range removed {
			s.state.Jobs[jobID] = j
		}
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createJobInput struct {
	TargetID      string   `json:"target_id"`
	Hosts         []string `json:"hosts,omitempty"`
	Ports         []uint16 `json:"ports,omitempty"`
	Authorized    bool     `json:"authorized"`
	Authorization string   `json:"authorization"`
}

func (s *Service) createJob(w http.ResponseWriter, r *http.Request) {
	var in createJobInput
	if decode(w, r, &in) != nil || !in.Authorized || strings.TrimSpace(in.Authorization) == "" {
		http.Error(w, "explicit written-authorization attestation is required", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		http.Error(w, "service unavailable", 503)
		return
	}
	if s.storageErr != "" {
		http.Error(w, "local storage is unavailable; restart the service after resolving the storage error", http.StatusServiceUnavailable)
		return
	}
	if unavailable := s.liveUnavailable(); unavailable != nil {
		http.Error(w, unavailable.Error(), http.StatusServiceUnavailable)
		return
	}
	t, ok := s.state.Targets[in.TargetID]
	if !ok || t.VerifiedAt.IsZero() {
		http.Error(w, "verified target required", 403)
		return
	}
	hosts := in.Hosts
	if len(hosts) == 0 {
		hosts = append([]string(nil), t.ScopeHosts...)
	}
	for i := range hosts {
		hosts[i] = normalizeHost(hosts[i])
		if !containsString(t.ScopeHosts, hosts[i]) {
			http.Error(w, "host is outside the verified selection", 422)
			return
		}
	}
	ports := in.Ports
	if len(ports) == 0 {
		ports = append([]uint16(nil), t.Ports...)
	}
	for _, port := range ports {
		if !containsPort(t.Ports, port) {
			http.Error(w, "port is outside the verified selection", 422)
			return
		}
	}
	id, e := randomID()
	if e != nil {
		http.Error(w, "internal error", 500)
		return
	}
	j := Job{ID: id, TargetID: t.ID, Hosts: hosts, Ports: ports, Status: "queued", Authorization: strings.TrimSpace(in.Authorization), CreatedAt: time.Now().UTC()}
	s.state.Jobs[id] = j
	req := s.requestFor(j)
	select {
	case s.queue <- task{id: id, req: req}:
	default:
		delete(s.state.Jobs, id)
		http.Error(w, "scan queue is full", 429)
		return
	}
	if e = s.persistLocked(); e != nil {
		delete(s.state.Jobs, id)
		// The worker may already have dequeued this item, but it cannot pass
		// the state lock until the missing job has been removed.
		s.storageErr = e.Error()
		http.Error(w, "storage error; job was not accepted", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 202, j)
}
func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func containsPort(values []uint16, value uint16) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func (s *Service) requestFor(j Job) ScanRequest {
	return ScanRequest{JobID: j.ID, OwnerID: s.ownerID, Root: s.state.Targets[j.TargetID].Host, Hosts: append([]string(nil), j.Hosts...), Ports: append([]uint16(nil), j.Ports...), Authorized: true}
}

func (s *Service) liveUnavailable() error {
	if s.recoveryErr != "" {
		return errors.New(s.recoveryErr)
	}
	if readiness, ok := s.runner.(LiveReadiness); ok {
		return readiness.LiveReady()
	}
	return nil
}
func (s *Service) listJobs(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Job, 0, len(s.state.Jobs))
	for _, j := range s.state.Jobs {
		out = append(out, j)
	}
	writeJSON(w, 200, out)
}
func (s *Service) getJob(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j, ok := s.state.Jobs[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, 200, j)
}
func (s *Service) deleteJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.state.Jobs[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if j.Status == "queued" || j.Status == "running" {
		http.Error(w, "cancel active job before deleting", 409)
		return
	}
	delete(s.state.Jobs, id)
	if e := s.persistLocked(); e != nil {
		s.state.Jobs[id] = j
		http.Error(w, "storage error", 500)
		return
	}
	w.WriteHeader(204)
}
func (s *Service) cancelJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.state.Jobs[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch j.Status {
	case "queued":
		j.Status = "cancelled"
		j.FinishedAt = time.Now().UTC()
	case "running":
		if c := s.jobCancel[id]; c != nil {
			c()
		}
	default:
		writeJSON(w, 200, j)
		return
	}
	s.state.Jobs[id] = j
	if e := s.persistLocked(); e != nil {
		s.storageErr = e.Error()
		http.Error(w, "storage error", 500)
		return
	}
	writeJSON(w, 200, j)
}

func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case t := <-s.queue:
			s.runTask(t)
			s.mu.Lock()
			storageFailed := s.storageErr != ""
			s.mu.Unlock()
			if storageFailed {
				return
			}
		}
	}
}
func (s *Service) runTask(t task) {
	s.mu.Lock()
	if s.storageErr != "" {
		s.mu.Unlock()
		return
	}
	j, ok := s.state.Jobs[t.id]
	if !ok || j.Status != "queued" {
		s.mu.Unlock()
		return
	}
	if unavailable := s.liveUnavailable(); unavailable != nil {
		j.Status = "failed"
		j.Error = unavailable.Error()
		j.FinishedAt = time.Now().UTC()
		s.state.Jobs[t.id] = j
		if err := s.persistLocked(); err != nil {
			s.storageErr = err.Error()
		}
		s.mu.Unlock()
		return
	}
	target, targetOK := s.state.Targets[j.TargetID]
	ctx, cancel := context.WithCancel(s.ctx)
	s.jobCancel[t.id] = cancel
	j.Status = "running"
	j.StartedAt = time.Now().UTC()
	s.state.Jobs[t.id] = j
	if persistErr := s.persistLocked(); persistErr != nil {
		j.Status = "failed"
		j.Error = "could not persist running state: " + persistErr.Error()
		j.FinishedAt = time.Now().UTC()
		s.state.Jobs[t.id] = j
		s.storageErr = persistErr.Error()
		delete(s.jobCancel, t.id)
		s.mu.Unlock()
		cancel()
		return
	}
	s.mu.Unlock()
	var scopeErr error
	if !targetOK || !target.Verified || target.VerifiedAt.IsZero() || target.Host != t.req.Root {
		scopeErr = errors.New("verified target is no longer available")
	} else {
		t.req.Policy, scopeErr = targetscope.Freeze(ctx, s.resolver, t.req.Root, t.req.Hosts, t.req.Ports)
	}
	var res json.RawMessage
	var err error
	if scopeErr != nil {
		err = fmt.Errorf("target scope could not be frozen: %w", scopeErr)
	} else if err = targetscope.VerifyTXT(ctx, s.resolver, target.Challenge); err != nil {
		err = fmt.Errorf("DNS TXT verification failed at job execution: %w", err)
	} else {
		res, err = s.runner.Run(ctx, t.req)
	}
	wasCanceled := ctx.Err() != nil
	cancel()
	s.mu.Lock()
	delete(s.jobCancel, t.id)
	j = s.state.Jobs[t.id]
	if j.Status != "cancelled" {
		if wasCanceled {
			j.Status = "cancelled"
		} else if err != nil {
			if len(res) > 0 && json.Valid(res) {
				j.Status = "incomplete"
				j.Result = res
			} else {
				j.Status = "failed"
			}
			j.Error = err.Error()
		} else {
			j.Status = "completed"
			j.Result = res
		}
		j.FinishedAt = time.Now().UTC()
		s.state.Jobs[t.id] = j
		if persistErr := s.persistLocked(); persistErr != nil {
			j.Status = "failed"
			j.Result = nil
			j.Error = "could not persist terminal job state: " + persistErr.Error()
			s.state.Jobs[t.id] = j
			s.storageErr = persistErr.Error()
		}
	}
	s.mu.Unlock()
}

func (s *Service) load() error {
	b, e := os.ReadFile(s.path)
	if errors.Is(e, os.ErrNotExist) {
		s.state = diskState{Targets: map[string]Target{}, Jobs: map[string]Job{}}
		return nil
	}
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &s.state); e != nil {
		return fmt.Errorf("read local state: %w", e)
	}
	if s.state.Targets == nil {
		s.state.Targets = map[string]Target{}
	}
	if s.state.Jobs == nil {
		s.state.Jobs = map[string]Job{}
	}
	return nil
}
func (s *Service) persistLocked() error {
	b, e := json.MarshalIndent(s.state, "", "  ")
	if e != nil {
		return e
	}
	if s.persistFn != nil {
		return s.persistFn(s.path, b)
	}
	tmp := s.path + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		_ = os.Remove(tmp)
		return e
	}
	if e = os.Rename(tmp, s.path); e != nil {
		_ = os.Remove(tmp)
		return e
	}
	return nil
}
