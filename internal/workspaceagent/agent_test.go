package workspaceagent

import (
	"errors"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{TimeoutSeconds: 60, MaxLogBytes: 1 << 20, RetentionSeconds: 3600,
		MaxRecords: 100, CompletedLogBudgetBytes: 1 << 30}
}

func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	a, err := New(filepath.Join(t.TempDir(), "runs"), t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopRuns(a) })
	return a
}

// stopRuns cancels every live run and waits until their results are
// recorded, so nothing writes to the test's directories during cleanup.
func stopRuns(a *Agent) {
	a.mu.Lock()
	ids := slices.Collect(maps.Keys(a.live))
	a.mu.Unlock()
	for _, id := range ids {
		_, _ = a.Cancel(id)
	}
	a.Wait()
}

func create(t *testing.T, a *Agent, id, command string, options Options) Run {
	t.Helper()
	run, created, err := a.Create(id, command, options)
	if err != nil {
		t.Fatalf("Create(%q): %v", id, err)
	}
	if !created {
		t.Fatalf("Create(%q) returned an existing run", id)
	}
	return run
}

func waitFinished(t *testing.T, a *Agent, id string) Run {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		run, err := a.Get(id)
		if err != nil {
			t.Fatalf("Get(%q): %v", id, err)
		}
		if !live(run.Status) {
			return run
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %q did not finish", id)
	return Run{}
}

func readAll(t *testing.T, a *Agent, id string) string {
	t.Helper()
	offset, _, err := a.openLog(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, _, _, err := a.readLog(id, offset, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != code {
		t.Fatalf("err = %v, want HTTP %d", err, code)
	}
}

func TestRunRecordsResultAndOutput(t *testing.T) {
	a := newTestAgent(t)
	create(t, a, "ok", "echo hello; echo oops >&2", testOptions())
	create(t, a, "fails", "exit 3", testOptions())

	run := waitFinished(t, a, "ok")
	if run.Status != statusSucceeded || run.ExitCode == nil || *run.ExitCode != 0 || run.FinishedAt == "" {
		t.Errorf("ok run = %+v, want Succeeded with exit code 0", run)
	}
	if got := readAll(t, a, "ok"); got != "hello\noops\n" {
		t.Errorf("output = %q, want stdout and stderr combined", got)
	}
	run = waitFinished(t, a, "fails")
	if run.Status != statusFailed || run.ExitCode == nil || *run.ExitCode != 3 {
		t.Errorf("failing run = %+v, want Failed with exit code 3", run)
	}
}

func TestRunRunsInWorkdir(t *testing.T) {
	a := newTestAgent(t)
	create(t, a, "pwd", "pwd", testOptions())
	waitFinished(t, a, "pwd")
	if got := strings.TrimSpace(readAll(t, a, "pwd")); got != a.workdir {
		t.Errorf("working directory = %q, want %q", got, a.workdir)
	}
}

func TestRunTimesOut(t *testing.T) {
	a := newTestAgent(t)
	options := testOptions()
	options.TimeoutSeconds = 1
	create(t, a, "slow", "sleep 30", options)
	run := waitFinished(t, a, "slow")
	if run.Status != statusTimedOut || run.ExitCode == nil || *run.ExitCode != 124 || !strings.Contains(run.Message, "timed out") {
		t.Errorf("run = %+v, want TimedOut with exit code 124", run)
	}
}

func TestCancelStopsTheProcessGroup(t *testing.T) {
	a := newTestAgent(t)
	marker := filepath.Join(t.TempDir(), "survived")
	create(t, a, "group", "(sleep 2; touch "+marker+") & sleep 30", testOptions())
	if _, err := a.Cancel("group"); err != nil {
		t.Fatal(err)
	}
	run := waitFinished(t, a, "group")
	if run.Status != statusCancelled {
		t.Errorf("status = %q, want Cancelled", run.Status)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("a background job in the run's process group kept running after cancel")
	}
}

// A cancel that arrives after the command exited, while its output drains,
// must not turn the result into a cancellation.
func TestCancelAfterExitKeepsTheResult(t *testing.T) {
	a := newTestAgent(t)
	// The detached sleep holds the output open, so the run stays live for the
	// second the supervisor waits for output to drain. The pause lets it leave
	// the process group, which is killed once the command exits.
	create(t, a, "late", "setsid sleep 3 & sleep 0.2; exit 0", testOptions())
	time.Sleep(500 * time.Millisecond)
	if _, err := a.Cancel("late"); err != nil {
		t.Fatal(err)
	}
	run := waitFinished(t, a, "late")
	if run.Status != statusSucceeded || run.ExitCode == nil || *run.ExitCode != 0 {
		t.Errorf("run = %+v, want Succeeded with exit code 0", run)
	}
}

func TestCreateIsIdempotentByID(t *testing.T) {
	a := newTestAgent(t)
	create(t, a, "same", "true", testOptions())
	if _, created, err := a.Create("same", "true", testOptions()); err != nil || created {
		t.Errorf("retry = (created %v, %v), want the existing run", created, err)
	}
	_, _, err := a.Create("same", "false", testOptions())
	wantCode(t, err, http.StatusConflict)
	_, _, err = a.Create("../escape", "true", testOptions())
	wantCode(t, err, http.StatusBadRequest)
}

func TestDeleteRefusesLiveRunsAndBlocksReuse(t *testing.T) {
	a := newTestAgent(t)
	create(t, a, "gone", "sleep 30", testOptions())
	wantCode(t, a.Delete("gone"), http.StatusConflict)
	if _, err := a.Cancel("gone"); err != nil {
		t.Fatal(err)
	}
	waitFinished(t, a, "gone")
	if err := a.Delete("gone"); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete("gone"); err != nil {
		t.Errorf("second delete = %v, want success", err)
	}
	_, err := a.Get("gone")
	wantCode(t, err, http.StatusGone)
	_, _, err = a.Create("gone", "sleep 30", testOptions())
	wantCode(t, err, http.StatusGone)
	_, err = a.Get("never")
	wantCode(t, err, http.StatusNotFound)
}

func TestRestartMarksLiveRunsInterrupted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	dir := filepath.Join(root, "left")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := &record{Version: recordVersion, ID: "left", Command: "make", Status: statusRunning,
		StartedAt: time.Now().UTC(), TimeoutSeconds: 60, MaxLogBytes: 1024}
	if err := saveRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "bad"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad", "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := New(root, t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	run, err := a.Get("left")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != statusInterrupted || run.ExitCode != nil || run.FinishedAt == "" {
		t.Errorf("run = %+v, want Interrupted without an exit code", run)
	}
	if saved, err := loadRecord(dir); err != nil || saved.Status != statusInterrupted {
		t.Errorf("saved record = %+v, %v; want Interrupted on disk", saved, err)
	}
	_, err = a.Get("bad")
	wantCode(t, err, http.StatusUnprocessableEntity)
	if err := a.Delete("bad"); err != nil {
		t.Errorf("deleting an unreadable record: %v", err)
	}
}

func TestLogKeepsNewestBytes(t *testing.T) {
	a := newTestAgent(t)
	options := testOptions()
	options.MaxLogBytes = 10
	create(t, a, "long", "printf 0123456789abcdefghijklmno", options)
	run := waitFinished(t, a, "long")
	if run.LogBytes != 25 || run.LogStartOffset != 15 || !run.LogTruncated {
		t.Errorf("window = [%d, %d) truncated %v, want [15, 25) truncated", run.LogStartOffset, run.LogBytes, run.LogTruncated)
	}
	if got := readAll(t, a, "long"); got != "fghijklmno" {
		t.Errorf("output = %q, want the newest 10 bytes", got)
	}
	window, err := a.windowLocked(a.records["long"])
	if err != nil {
		t.Fatal(err)
	}
	if window.stored() != 10 {
		t.Errorf("stored bytes = %d, want 10 after the leading segment is trimmed", window.stored())
	}
	_, _, err = a.openLog("long", 26)
	wantCode(t, err, http.StatusRequestedRangeNotSatisfiable)
}

func TestListPastTheEndIsEmpty(t *testing.T) {
	a := newTestAgent(t)
	create(t, a, "one", "true", testOptions())
	waitFinished(t, a, "one")
	for _, offset := range []int{1, math.MaxInt} {
		if runs, err := a.List(offset, 100); err != nil || len(runs) != 0 {
			t.Errorf("List(%d, 100) = %v, %v; want no runs", offset, runs, err)
		}
	}
}

func TestPruneLimitsRecordsAndLogBudget(t *testing.T) {
	a := newTestAgent(t)
	options := testOptions()
	options.MaxRecords = 2
	options.MaxLogBytes = 10
	options.CompletedLogBudgetBytes = 15
	for _, id := range []string{"one", "two", "three"} {
		create(t, a, id, "printf 0123456789", options)
		waitFinished(t, a, id)
	}
	_, err := a.Get("one")
	wantCode(t, err, http.StatusGone)
	two, err := a.Get("two")
	if err != nil {
		t.Fatal(err)
	}
	if !two.LogsEvicted || two.LogBytes != 10 || two.LogStartOffset != 10 {
		t.Errorf("oldest kept run = %+v, want its logs evicted with offsets kept", two)
	}
	if three, _ := a.Get("three"); three.LogsEvicted {
		t.Error("newest run's logs were evicted")
	}
}

func TestHandlerFollowsLogsUntilTheRunEnds(t *testing.T) {
	a := newTestAgent(t)
	server := httptest.NewServer(a.Handler("secret", nil))
	defer server.Close()
	create(t, a, "follow", "echo one; sleep 1; echo two", testOptions())

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/runs/follow/logs?follow", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "one\ntwo\n" || resp.Header.Get("X-Log-Offset") != "0" {
		t.Errorf("body = %q offset %q, want both lines from offset 0", body, resp.Header.Get("X-Log-Offset"))
	}
	if resp.Trailer.Get("X-Run-Status") != statusSucceeded || resp.Trailer.Get("X-Run-Exit-Code") != "0" {
		t.Errorf("trailers = %v, want Succeeded and exit code 0", resp.Trailer)
	}
}

func TestHandlerRequiresToken(t *testing.T) {
	server := httptest.NewServer(newTestAgent(t).Handler("secret", nil))
	defer server.Close()
	for _, auth := range []string{"", "Bearer wrong"} {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/runs", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET /runs with %q = %d, want 401", auth, resp.StatusCode)
		}
	}
	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 without a token", resp.StatusCode)
	}
}

func TestExclusiveRunsWaitForTheLiveOne(t *testing.T) {
	a := newTestAgent(t)
	exclusive := testOptions()
	exclusive.Exclusive = "deploy"
	create(t, a, "first", "sleep 30", exclusive)

	// A retry of the live run still returns it.
	if run, created, err := a.Create("first", "sleep 30", exclusive); err != nil || created || run.ID != "first" {
		t.Fatalf("retry of the live run: %+v created=%v err=%v", run, created, err)
	}
	_, _, err := a.Create("second", "true", exclusive)
	wantCode(t, err, http.StatusConflict)
	if err == nil || !strings.Contains(err.Error(), "first") {
		t.Errorf("conflict does not name the live run: %v", err)
	}
	if _, err := a.Get("second"); err == nil {
		t.Error("the refused run was recorded")
	}
	// Other runs, and runs with another key, are not affected.
	create(t, a, "plain", "true", testOptions())
	other := testOptions()
	other.Exclusive = "other"
	create(t, a, "other", "true", other)

	if _, err := a.Cancel("first"); err != nil {
		t.Fatal(err)
	}
	waitFinished(t, a, "first")
	create(t, a, "second", "true", exclusive)
}
