package nucleirunner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testContainerOwnerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestEmptyNucleiOutputSerializesFindingsAsArray(t *testing.T) {
	findings, err := parseOutput(nil, nil)
	if err != nil {
		t.Fatalf("parse empty output: %v", err)
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal empty findings: %v", err)
	}
	if string(data) != "[]" {
		t.Fatalf("empty Nuclei findings JSON = %s, want []", data)
	}
}

func TestContainerCompletionReportsExecutionAndCleanupFailuresTogether(t *testing.T) {
	runErr := errors.New("container exited")
	cleanupErr := errors.New("daemon unavailable")
	got := containerCompletionError(true, runErr, "fixture stderr", cleanupErr)
	if got == nil || !errors.Is(got, runErr) || !errors.Is(got, cleanupErr) || !strings.Contains(got.Error(), "output exceeded") || !strings.Contains(got.Error(), "fixture stderr") {
		t.Fatalf("execution/limit/cleanup failures were hidden: %v", got)
	}
}

func TestRemoveContainerReportsFailureButAcceptsAbsentContainer(t *testing.T) {
	makeDocker := func(t *testing.T, script string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "docker")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	absent := makeDocker(t, `if [ "$1" = "rm" ]; then echo "Error: No such container: $4" >&2; exit 1; fi`)
	if err := removeContainer(ctx, absent, "scaner-job-test"); err != nil {
		t.Fatalf("absent container should be successful cleanup: %v", err)
	}

	failed := makeDocker(t, `if [ "$1" = "rm" ]; then echo "Cannot connect to daemon" >&2; exit 1; fi; echo '{"Id":"still-present"}'`)
	if err := removeContainer(ctx, failed, "scaner-job-test"); err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("failed removal of existing container must be reported, got %v", err)
	}

	daemonUnavailable := makeDocker(t, `echo "Cannot connect to daemon" >&2; exit 1`)
	if err := removeContainer(ctx, daemonUnavailable, "scaner-job-test"); err == nil || !strings.Contains(err.Error(), "inspect failed") {
		t.Fatalf("daemon failure must not be mistaken for absence, got %v", err)
	}
}

func TestReconcileRemovesOnlyContainersWithMatchingOwnershipLabels(t *testing.T) {
	log := filepath.Join(t.TempDir(), "removed")
	docker := filepath.Join(t.TempDir(), "docker")
	script := `case "$1" in
ps) echo ` + testContainerID + ` ;;
inspect)
  if [ "$5" = "{{.Id}}" ]; then echo ` + testContainerID + `; else echo '{"com.scaner.app":"scaner","com.scaner.owner":"` + testContainerOwnerID + `","com.scaner.job":"job-a","com.scaner.run":"old-run"}'; fi ;;
rm) echo "$3" >> "` + log + `" ;;
*) echo "unexpected docker command: $*" >&2; exit 2 ;;
esac`
	if err := os.WriteFile(docker, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := New(Config{DockerBinary: docker})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Reconcile(ctx, testContainerOwnerID); err != nil {
		t.Fatalf("Reconcile owned stale container: %v", err)
	}
	removed, err := os.ReadFile(log)
	if err != nil || strings.TrimSpace(string(removed)) != testContainerID {
		t.Fatalf("did not remove exact inspected ID: %q, %v", removed, err)
	}
	if err := r.LiveReady(); err != nil {
		t.Fatalf("successful reconciliation left runner blocked: %v", err)
	}
}

func TestReconcilePreservesForeignOrUnlabelledContainersAndBlocksLive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels string
	}{
		{name: "foreign", labels: `{"com.scaner.app":"scaner","com.scaner.owner":"other-owner","com.scaner.job":"job-a","com.scaner.run":"run-a"}`},
		{name: "unlabelled", labels: `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			removed := filepath.Join(dir, "removed")
			docker := filepath.Join(dir, "docker")
			script := `case "$1" in
ps) echo ` + testContainerID + ` ;;
inspect)
  if [ "$5" = "{{.Id}}" ]; then echo ` + testContainerID + `; else echo '` + tc.labels + `'; fi ;;
rm) echo "$3" >> "` + removed + `" ;;
*) exit 2 ;;
esac`
			if err := os.WriteFile(docker, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			r := New(Config{DockerBinary: docker})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := r.Reconcile(ctx, testContainerOwnerID); err == nil {
				t.Fatal("unknown container ownership was accepted")
			}
			if _, err := os.Stat(removed); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("foreign container was removed: %v", err)
			}
			if err := r.LiveReady(); err == nil {
				t.Fatal("runner should remain blocked after unproven ownership")
			}
		})
	}
}

func TestReconcileDockerFailureBlocksLive(t *testing.T) {
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho daemon-unavailable >&2; exit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := New(Config{DockerBinary: docker})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Reconcile(ctx, testContainerOwnerID); err == nil {
		t.Fatal("Docker failure was ignored")
	}
	if err := r.LiveReady(); err == nil {
		t.Fatal("Docker failure did not disable live scans")
	}
}

func TestNormalCleanupVerifiesLabelsAndRemovesByExactID(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "removed")
	docker := filepath.Join(dir, "docker")
	r := New(Config{DockerBinary: docker})
	script := `case "$1" in
inspect)
  if [ "$5" = "{{.Id}}" ]; then echo ` + testContainerID + `; else echo '{"com.scaner.app":"scaner","com.scaner.owner":"` + testContainerOwnerID + `","com.scaner.job":"job-a","com.scaner.run":"` + r.runID + `"}'; fi ;;
rm) echo "$3" >> "` + log + `" ;;
*) exit 2 ;;
esac`
	if err := os.WriteFile(docker, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.removeOwnedContainer(ctx, "scaner-job-job-a", testContainerOwnerID, "job-a", r.runID); err != nil {
		t.Fatalf("remove owned container: %v", err)
	}
	removed, err := os.ReadFile(log)
	if err != nil || strings.TrimSpace(string(removed)) != testContainerID {
		t.Fatalf("container was not removed by exact ID: %q, %v", removed, err)
	}
}

func TestNormalCleanupDoesNotRemoveNameCollision(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "removed")
	docker := filepath.Join(dir, "docker")
	script := `case "$1" in
inspect)
  if [ "$5" = "{{.Id}}" ]; then echo ` + testContainerID + `; else echo '{"com.scaner.app":"other","com.scaner.owner":"` + testContainerOwnerID + `","com.scaner.job":"job-a","com.scaner.run":"run-a"}'; fi ;;
rm) echo called >> "` + log + `" ;;
esac`
	if err := os.WriteFile(docker, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := New(Config{DockerBinary: docker})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.removeOwnedContainer(ctx, "scaner-job-job-a", testContainerOwnerID, "job-a", r.runID); err == nil {
		t.Fatal("foreign name collision was accepted")
	}
	if _, err := os.Stat(log); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign container was removed: %v", err)
	}
}
