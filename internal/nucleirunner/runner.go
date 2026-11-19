// Package nucleirunner runs the fixed Nuclei allowlist in a fresh, isolated
// container. The container has no network namespace connectivity; all HTTP
// egress must cross a per-job Unix socket to an exact-target policy proxy.
package nucleirunner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
	"github.com/z1kkky/scaner/internal/web"
)

const (
	nucleiVersion    = "v3.11.1"
	nucleiCommit     = "7604080285c7b5829255c095c0901327affdb6b7"
	nucleiSHA256     = "e6614c9234d135a571f58b2098f7a09cd153bad1676b845e7d75d48b7b42c434"
	baseImage        = "ubuntu@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78"
	proxyPort        = 18080
	maxOutputBytes   = 2 << 20
	maxStderrBytes   = 128 << 10
	maxResponseSize  = 4 << 20
	maxTunnelBytes   = 8 << 20
	maxNucleiTargets = 64
	defaultTimeout   = 2 * time.Minute
	labelApp         = "com.scaner.app"
	labelAppValue    = "scaner"
	labelOwner       = "com.scaner.owner"
	labelJob         = "com.scaner.job"
	labelRun         = "com.scaner.run"
)

//go:embed templates/*.yaml
var templates embed.FS

// Config identifies locally supplied executables. The Nuclei binary must
// match the pinned hash/version. RelayExecutable should be the scannerweb
// executable, which implements the private container relay subcommand.
type Config struct {
	DockerBinary    string
	NucleiBinary    string
	RelayExecutable string
	Timeout         time.Duration
}

type Runner struct {
	cfg       Config
	imageMu   sync.Mutex
	image     string
	imageErr  error
	gate      chan struct{}
	testRoots *x509.CertPool
	runID     string
	runIDErr  error
	readyMu   sync.RWMutex
	blocked   error
}

func New(cfg Config) *Runner {
	if cfg.DockerBinary == "" {
		cfg.DockerBinary = "docker"
	}
	if cfg.NucleiBinary == "" {
		cfg.NucleiBinary = filepath.Join("nuclei", "nuclei")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	r := &Runner{cfg: cfg, gate: make(chan struct{}, 1)}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		r.runIDErr = fmt.Errorf("create container run identity: %w", err)
	} else {
		r.runID = hex.EncodeToString(b)
	}
	return r
}

func (r *Runner) Run(ctx context.Context, req web.ScanRequest) (json.RawMessage, error) {
	if err := r.LiveReady(); err != nil {
		return nil, err
	}
	if r.runIDErr != nil {
		return nil, r.runIDErr
	}
	if !validOwnerID(req.OwnerID) {
		return nil, errors.New("valid local container owner ID required")
	}
	if req.JobID == "" || safeName(req.JobID) != req.JobID {
		return nil, errors.New("valid local job ID required")
	}
	if !req.Authorized {
		return nil, errors.New("written authorization attestation required")
	}
	if req.Policy == nil || req.Policy.Root() == "" || len(req.Policy.Hosts()) == 0 {
		return nil, errors.New("frozen target policy required")
	}
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()
	image, err := r.ensureImage(ctx)
	if err != nil {
		return nil, err
	}
	policy := req.Policy
	targets, err := nucleiTargets(policy)
	if err != nil {
		return nil, err
	}
	return r.runContainer(ctx, image, req, targets)
}

// LiveReady exposes a sticky fail-closed state after a container cannot be
// safely reconciled or removed. Restarting the service retries reconciliation.
func (r *Runner) LiveReady() error {
	r.readyMu.RLock()
	defer r.readyMu.RUnlock()
	if r.runIDErr != nil {
		return r.runIDErr
	}
	return r.blocked
}

func (r *Runner) blockLive(err error) {
	if err == nil {
		return
	}
	r.readyMu.Lock()
	if r.blocked == nil {
		r.blocked = err
	}
	r.readyMu.Unlock()
}

// Reconcile removes stale containers only after their application and owner
// labels match this data directory. Any unknown Scaner-named container blocks
// live scans rather than being removed based on its name.
func (r *Runner) Reconcile(ctx context.Context, ownerID string) error {
	if !validOwnerID(ownerID) {
		err := errors.New("valid container owner ID is required for reconciliation")
		r.blockLive(err)
		return err
	}
	if _, err := exec.LookPath(r.cfg.DockerBinary); err != nil {
		err = fmt.Errorf("Docker CLI unavailable during stale-container reconciliation: %w", err)
		r.blockLive(err)
		return err
	}
	cmd := exec.CommandContext(ctx, r.cfg.DockerBinary, "ps", "-aq", "--filter", "name=scaner-job-")
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("list possible stale Scaner containers: %w: %s", err, strings.TrimSpace(string(out)))
		r.blockLive(err)
		return err
	}
	for _, id := range strings.Fields(string(out)) {
		containerID, labels, err := r.inspectLabels(ctx, id)
		if errors.Is(err, errContainerNotFound) {
			continue
		}
		if err != nil {
			err = fmt.Errorf("inspect possible stale container %q: %w", id, err)
			r.blockLive(err)
			return err
		}
		if labels[labelApp] != labelAppValue || labels[labelOwner] != ownerID || labels[labelJob] == "" || labels[labelRun] == "" {
			err = fmt.Errorf("container %q has unknown ownership labels; live scans are disabled", id)
			r.blockLive(err)
			return err
		}
		if err := removeContainer(ctx, r.cfg.DockerBinary, containerID); err != nil {
			err = fmt.Errorf("remove stale owned container %q: %w", id, err)
			r.blockLive(err)
			return err
		}
	}
	r.readyMu.Lock()
	r.blocked = nil
	r.readyMu.Unlock()
	return nil
}

func validOwnerID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16
}

func nucleiTargets(policy *targetscope.Policy) ([]string, error) {
	var targets []string
	hosts := policy.Hosts()
	ports := policy.AllowedPorts()
	for _, host := range hosts {
		for _, port := range ports {
			if len(targets) >= maxNucleiTargets {
				return nil, fmt.Errorf("Nuclei target limit exceeded (%d)", maxNucleiTargets)
			}
			scheme := "http"
			if port == 443 {
				scheme = "https"
			} else if port == 80 {
				scheme = "http"
			} else {
				// The reviewed profile is HTTP-only. Nonstandard ports are
				// scanned only as cleartext HTTP when explicitly authorized.
				scheme = "http"
			}
			u := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(int(port)))}
			targets = append(targets, u.String())
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("frozen policy contains no host ports for HTTP scanning")
	}
	sort.Strings(targets)
	return targets, nil
}

func (r *Runner) ensureImage(ctx context.Context) (string, error) {
	r.imageMu.Lock()
	defer r.imageMu.Unlock()
	if r.image != "" || r.imageErr != nil {
		return r.image, r.imageErr
	}
	if runtime.GOOS != "linux" {
		r.imageErr = errors.New("the pinned Nuclei container is supported only on Linux")
		return "", r.imageErr
	}
	nucleiPath, err := filepath.Abs(r.cfg.NucleiBinary)
	if err != nil {
		r.imageErr = err
		return "", err
	}
	relayPath := r.cfg.RelayExecutable
	if relayPath == "" {
		relayPath, err = os.Executable()
		if err != nil {
			r.imageErr = fmt.Errorf("locate scannerweb relay executable: %w", err)
			return "", r.imageErr
		}
	}
	relayPath, err = filepath.Abs(relayPath)
	if err != nil {
		r.imageErr = err
		return "", err
	}
	if err = verifyNuclei(nucleiPath); err != nil {
		r.imageErr = err
		return "", err
	}
	image, err := buildImage(ctx, r.cfg.DockerBinary, nucleiPath, relayPath)
	if err != nil {
		r.imageErr = err
		return "", err
	}
	r.image = image
	return image, nil
}

func verifyNuclei(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open pinned Nuclei binary: %w", err)
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != nucleiSHA256 {
		return fmt.Errorf("Nuclei binary SHA-256 mismatch: got %s", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-version")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("Nuclei Engine Version: "+nucleiVersion)) {
		return fmt.Errorf("Nuclei version check failed; require %s", nucleiVersion)
	}
	return nil
}

func buildImage(ctx context.Context, docker, nucleiPath, relayPath string) (string, error) {
	if _, err := exec.LookPath(docker); err != nil {
		return "", fmt.Errorf("Docker CLI unavailable: %w", err)
	}
	root, err := os.MkdirTemp("", "scaner-nuclei-image-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(root)
	if err := os.Mkdir(filepath.Join(root, "templates"), 0700); err != nil {
		return "", err
	}
	if err := copyFile(nucleiPath, filepath.Join(root, "nuclei"), 0500); err != nil {
		return "", err
	}
	if err := copyFile(relayPath, filepath.Join(root, "scannerweb"), 0500); err != nil {
		return "", err
	}
	for _, name := range []string{"apache-status.yaml", "exposed-git.yaml"} {
		data, err := templates.ReadFile("templates/" + name)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(root, "templates", name), data, 0444); err != nil {
			return "", err
		}
	}
	dockerfile := "FROM " + baseImage + "\n" +
		"LABEL org.scaner.nuclei.version=\"" + nucleiVersion + "\"\n" +
		"LABEL org.scaner.nuclei.source-commit=\"" + nucleiCommit + "\"\n" +
		"LABEL org.scaner.nuclei.sha256=\"" + nucleiSHA256 + "\"\n" +
		"LABEL org.scaner.nuclei.base=\"" + baseImage + "\"\n" +
		"COPY --chmod=0555 nuclei /usr/local/bin/nuclei\n" +
		"COPY --chmod=0555 scannerweb /usr/local/bin/scannerweb\n" +
		"RUN mkdir -p /opt/scaner/templates\n" +
		"COPY --chmod=0444 templates/*.yaml /opt/scaner/templates/\n" +
		"USER 65532:65532\n" +
		"ENTRYPOINT [\"/usr/local/bin/scannerweb\"]\n"
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
		return "", err
	}
	checksum := sha256.New()
	for _, p := range []string{filepath.Join(root, "nuclei"), filepath.Join(root, "scannerweb"), filepath.Join(root, "templates", "apache-status.yaml"), filepath.Join(root, "templates", "exposed-git.yaml")} {
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		if _, err = io.Copy(checksum, f); err != nil {
			_ = f.Close()
			return "", err
		}
		_ = f.Close()
	}
	_, _ = io.WriteString(checksum, baseImage)
	tag := "scaner-nuclei:" + hex.EncodeToString(checksum.Sum(nil)[:12])
	cmd := exec.CommandContext(ctx, docker, "build", "--pull=false", "--tag", tag, root)
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = maxStderrBytes, maxStderrBytes
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build pinned Nuclei image: %w: %s", err, stderr.String())
	}
	return tag, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, cpErr := io.Copy(out, in)
	closeErr := out.Close()
	if cpErr != nil {
		return cpErr
	}
	return closeErr
}

func (r *Runner) runContainer(ctx context.Context, image string, req web.ScanRequest, targets []string) (json.RawMessage, error) {
	jobRoot, err := os.MkdirTemp("", "scaner-nuclei-job-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(jobRoot)
	if err := os.Chmod(jobRoot, 0700); err != nil {
		return nil, err
	}
	targetFile := filepath.Join(jobRoot, "targets.txt")
	if err := os.WriteFile(targetFile, []byte(strings.Join(targets, "\n")+"\n"), 0444); err != nil {
		return nil, err
	}
	proxyDir, err := os.MkdirTemp("", "scaner-egress-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(proxyDir)
	socketPath := filepath.Join(proxyDir, "egress.sock")
	proxy, err := newEgressProxyWithRoots(ctx, socketPath, req.Policy, r.testRoots)
	if err != nil {
		return nil, err
	}
	defer proxy.Close()
	caPath := filepath.Join(jobRoot, "scaner-ca.pem")
	if err := proxy.WriteCAPEM(caPath); err != nil {
		return nil, fmt.Errorf("prepare ephemeral proxy trust root: %w", err)
	}
	name := "scaner-job-" + safeName(req.JobID)
	args := []string{"run", "--name", name, "--label", labelApp + "=" + labelAppValue, "--label", labelOwner + "=" + req.OwnerID, "--label", labelJob + "=" + req.JobID, "--label", labelRun + "=" + r.runID, "--network", "none", "--read-only", "--memory", "512m", "--memory-swap", "512m", "--cpus", "0.5", "--pids-limit", "64", "--ulimit", "nofile=64:64", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--mount", "type=bind,src=" + socketPath + ",dst=/run/scaner-egress.sock,readonly", "--mount", "type=bind,src=" + targetFile + ",dst=/run/targets.txt,readonly", "--mount", "type=bind,src=" + caPath + ",dst=/run/scaner-ca.pem,readonly", "--env", "SSL_CERT_FILE=/run/scaner-ca.pem", "--env", "HOME=/tmp", "--env", "XDG_CONFIG_HOME=/tmp/config", "--env", "XDG_CACHE_HOME=/tmp/cache", image, "--scaner-internal-relay", "/run/scaner-egress.sock", strconv.Itoa(proxyPort), "--", "/usr/local/bin/nuclei", "-list", "/run/targets.txt", "-t", "/opt/scaner/templates", "-pt", "http", "-jsonl", "-silent", "-no-color", "-omit-raw", "-duc", "-no-interactsh", "-c", "1", "-bs", "1", "-rl", "1", "-timeout", "5", "-retries", "0", "-proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort)}
	cmd := exec.CommandContext(ctx, r.cfg.DockerBinary, args...)
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = maxOutputBytes, maxStderrBytes
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cleanupErr := r.removeOwnedContainer(cleanupCtx, name, req.OwnerID, req.JobID, r.runID)
	if cleanupErr != nil {
		r.blockLive(fmt.Errorf("container cleanup could not prove ownership: %w", cleanupErr))
	}
	_ = proxy.Close()
	coverageErr := proxy.validateCoverage()
	if runErr := containerCompletionError(stdout.exceeded || stderr.exceeded, err, stderr.String(), cleanupErr); runErr != nil {
		return nil, errors.Join(runErr, coverageErr)
	}
	if coverageErr != nil {
		return nil, coverageErr
	}
	findings, err := parseOutput(stdout.Bytes(), req.Policy)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"engine": "Nuclei " + nucleiVersion, "simulation": false, "findings": findings})
}

func containerCompletionError(outputExceeded bool, runErr error, stderr string, cleanupErr error) error {
	var errs []error
	if outputExceeded {
		errs = append(errs, errors.New("Nuclei container output exceeded safety limits"))
	}
	if runErr != nil {
		errs = append(errs, fmt.Errorf("Nuclei container failed: %w: %s", runErr, stderr))
	}
	if cleanupErr != nil {
		errs = append(errs, fmt.Errorf("container cleanup failed: %w", cleanupErr))
	}
	return errors.Join(errs...)
}

var errContainerNotFound = errors.New("container not found")

func (r *Runner) inspectLabels(ctx context.Context, ref string) (string, map[string]string, error) {
	if ref == "" || strings.ContainsAny(ref, " \t\r\n") {
		return "", nil, errors.New("invalid container reference")
	}
	idCmd := exec.CommandContext(ctx, r.cfg.DockerBinary, "inspect", "--type", "container", "--format", "{{.Id}}", ref)
	idOut, err := idCmd.CombinedOutput()
	if err != nil {
		if containerMissing(idOut) {
			return "", nil, errContainerNotFound
		}
		return "", nil, fmt.Errorf("inspect container ID: %w: %s", err, strings.TrimSpace(string(idOut)))
	}
	id := strings.TrimSpace(string(idOut))
	if !validContainerID(id) {
		return "", nil, errors.New("Docker returned an invalid container ID")
	}
	labelsCmd := exec.CommandContext(ctx, r.cfg.DockerBinary, "inspect", "--type", "container", "--format", "{{json .Config.Labels}}", id)
	labelsOut, err := labelsCmd.CombinedOutput()
	if err != nil {
		if containerMissing(labelsOut) {
			return "", nil, errContainerNotFound
		}
		return "", nil, fmt.Errorf("inspect container ownership labels: %w: %s", err, strings.TrimSpace(string(labelsOut)))
	}
	var labels map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(labelsOut), &labels); err != nil {
		return "", nil, fmt.Errorf("decode container ownership labels: %w", err)
	}
	if labels == nil {
		labels = map[string]string{}
	}
	return id, labels, nil
}

func validContainerID(id string) bool {
	if len(id) < 12 || len(id) > 64 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded)*2 == len(id)
}

func (r *Runner) removeOwnedContainer(ctx context.Context, ref, ownerID, jobID, runID string) error {
	id, labels, err := r.inspectLabels(ctx, ref)
	if errors.Is(err, errContainerNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if labels[labelApp] != labelAppValue || labels[labelOwner] != ownerID || labels[labelJob] != jobID || labels[labelRun] != runID {
		return errors.New("container ownership labels do not match this run")
	}
	return removeContainer(ctx, r.cfg.DockerBinary, id)
}

func removeContainer(ctx context.Context, docker, name string) error {
	cmd := exec.CommandContext(ctx, docker, "rm", "--force", name)
	out, err := cmd.CombinedOutput()
	if err == nil || containerMissing(out) {
		return nil
	}
	inspect := exec.CommandContext(ctx, docker, "inspect", "--type", "container", name)
	inspectOut, inspectErr := inspect.CombinedOutput()
	if inspectErr != nil && containerMissing(inspectOut) {
		return nil
	}
	if inspectErr != nil {
		return fmt.Errorf("docker rm failed (%v): %s; docker inspect failed (%v): %s", err, strings.TrimSpace(string(out)), inspectErr, strings.TrimSpace(string(inspectOut)))
	}
	return fmt.Errorf("docker rm failed (%w): %s; container still exists", err, strings.TrimSpace(string(out)))
}

func containerMissing(output []byte) bool {
	text := strings.ToLower(string(output))
	return strings.Contains(text, "no such container") || strings.Contains(text, "no such object")
}

type event struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

var allowedTemplates = map[string]bool{"scaner-apache-server-status": true, "scaner-exposed-git-head": true}

func parseOutput(raw []byte, policy *targetscope.Policy) ([]map[string]string, error) {
	out := make([]map[string]string, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxOutputBytes)
	for scanner.Scan() {
		var e event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("parse Nuclei output: %w", err)
		}
		if !allowedTemplates[e.TemplateID] || e.Info.Name == "" || e.MatchedAt == "" {
			return nil, errors.New("Nuclei returned an out-of-allowlist or incomplete event")
		}
		severity := strings.ToLower(strings.TrimSpace(e.Info.Severity))
		switch severity {
		case "info", "low", "medium", "high", "critical":
		default:
			return nil, fmt.Errorf("Nuclei returned unsupported severity %q", e.Info.Severity)
		}
		u, err := url.Parse(e.MatchedAt)
		if err != nil || !policyAllowsURL(policy, u) {
			return nil, errors.New("Nuclei returned a match outside the frozen target policy")
		}
		out = append(out, map[string]string{"template_id": e.TemplateID, "title": e.Info.Name, "severity": severity, "matched_at": e.MatchedAt})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func policyAllowsURL(policy *targetscope.Policy, u *url.URL) bool {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return false
		}
		port = uint16(n)
	}
	if !contains(policy.Hosts(), host) || !containsPort(policy.AllowedPorts(), port) {
		return false
	}
	return len(policy.Addresses(host)) > 0
}

func contains(list []string, x string) bool {
	for _, item := range list {
		if item == x {
			return true
		}
	}
	return false
}
func containsPort(list []uint16, x uint16) bool {
	for _, item := range list {
		if item == x {
			return true
		}
	}
	return false
}

func safeName(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	if b.Len() == 0 {
		return "local"
	}
	return b.String()
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return n, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// RunContainerRelay is the private container entrypoint used to expose a
// loopback HTTP proxy to Nuclei while forwarding only through the mounted
// per-job Unix socket. It is not an API and rejects every malformed argument.
func RunContainerRelay(args []string) error {
	if len(args) < 4 || args[2] != "--" {
		return errors.New("invalid internal relay invocation")
	}
	socketPath := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("invalid internal relay port")
	}
	command := args[3:]
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				u, err := net.DialTimeout("unix", socketPath, 5*time.Second)
				if err != nil {
					return
				}
				defer u.Close()
				tunnelBytes(ctx, conn, u)
			}()
		}
	}()
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "XDG_CONFIG_HOME=/tmp/config", "XDG_CACHE_HOME=/tmp/cache", "NO_PROXY=", "no_proxy="}
	if caPath := os.Getenv("SSL_CERT_FILE"); caPath != "" {
		cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+caPath)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err = cmd.Run()
	_ = listener.Close()
	cancel()
	wg.Wait()
	return err
}

func tunnelBytes(ctx context.Context, a, b net.Conn) {
	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.CopyN(dst, src, maxTunnelBytes+1)
		_ = dst.Close()
	}
	wg.Add(2)
	go copyOne(a, b)
	go copyOne(b, a)
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-tunnelCtx.Done():
			_ = a.Close()
			_ = b.Close()
		case <-timer.C:
			_ = a.Close()
			_ = b.Close()
		}
	}()
	wg.Wait()
}

var _ web.Runner = (*Runner)(nil)
