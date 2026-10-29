//go:build linux

package workspacerun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

type runnerResult struct {
	Run    buildcontract.WorkspaceRun   `json:"run"`
	Runs   []buildcontract.WorkspaceRun `json:"runs"`
	Error  string                       `json:"error"`
	Active bool                         `json:"active"`
	Code   int                          `json:"code"`
}

func TestRunnerTimeoutRecordsDistinctResult(t *testing.T) {
	root, call := localRunner(t)
	options := DefaultOptions()
	options.TimeoutSeconds, options.RequestedTimeoutSeconds = 1, 1
	const command = `echo before; sleep 30 & echo $! > child-pid; wait; echo survived > survived`
	call("create", "timeout", command, options.JSON())
	run := awaitRun(t, call, "timeout")
	if run.Status != "TimedOut" || run.ExitCode == nil || *run.ExitCode != 124 || !strings.Contains(run.Message, "1 seconds") {
		t.Fatalf("timeout result: %+v", run)
	}
	if run.TimeoutSeconds != 1 || string(streamRunLog(t, root, "timeout", "0").Bytes) != "before\n" {
		t.Fatalf("timeout lost its policy or output: %+v", run)
	}
	if _, err := os.Stat(filepath.Join(root, "survived")); !os.IsNotExist(err) {
		t.Fatalf("timed out command continued: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "child-pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid child PID: %q, %v", data, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		_, state, ok := strings.Cut(string(data), ") ")
		if !ok {
			t.Fatalf("invalid child process state: %q", data)
		}
		if strings.HasPrefix(state, "Z ") {
			break // Terminated, but the test host's PID 1 may not have reaped it.
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("child %d survived the run timeout: %q", pid, state)
		}
		time.Sleep(20 * time.Millisecond)
	}
	options.RequestedTimeoutSeconds = 2
	if result := call("create", "timeout", command, options.JSON()); result.Code != 409 {
		t.Fatalf("changed timeout reused ID: %+v", result)
	}
}

func TestRunnerKeepsLogTailWithAbsoluteOffsets(t *testing.T) {
	root, call := localRunner(t)
	options := DefaultOptions()
	options.MaxLogBytes = 1000
	command := `python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*40)' ; echo reached > reached; exit 9`
	call("create", "tail", command, options.JSON())
	run := awaitRun(t, call, "tail")
	if run.Status != "Failed" || run.ExitCode == nil || *run.ExitCode != 9 || run.LogBytes != 10240 || run.LogStartOffset != 9240 || !run.LogTruncated {
		t.Fatalf("tail metadata: %+v", run)
	}
	if _, err := os.Stat(filepath.Join(root, "reached")); err != nil {
		t.Fatalf("log cap stopped command: %v", err)
	}
	want := make([]byte, 1000)
	for i := range want {
		want[i] = byte(9240 + i)
	}
	for _, offset := range []string{"0", "9240"} {
		got := streamRunLog(t, root, "tail", offset)
		if got.Offset != 9240 || !bytes.Equal(got.Bytes, want) {
			t.Fatalf("read at %s: offset=%d bytes=%d", offset, got.Offset, len(got.Bytes))
		}
	}
	if got := streamRunLog(t, root, "tail", "10235"); got.Offset != 10235 || !bytes.Equal(got.Bytes, want[995:]) {
		t.Fatalf("absolute resume: %+v", got)
	}
	files, err := filepath.Glob(filepath.Join(root, ".runs", "tail", "logs", "*.log"))
	if err != nil {
		t.Fatal(err)
	}
	var physical int64
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		physical += info.Size()
	}
	if physical != options.MaxLogBytes {
		t.Fatalf("unbounded physical log size: %d", physical)
	}
}

func TestRunnerRetentionAndBudgetPreserveResultsAndLiveRuns(t *testing.T) {
	root, call := localRunner(t)
	call("create", "live", `printf live-output-larger-than-budget; sleep 30`, DefaultOptions().JSON())
	t.Cleanup(func() { call("cancel", "live"); awaitRun(t, call, "live") })
	for id, age := range map[string]time.Duration{"expired": 8 * 24 * time.Hour, "oldest": 24 * time.Hour, "newer": time.Hour} {
		writeTerminalRun(t, root, id, age, []byte("12345678"))
	}
	options := DefaultOptions()
	options.CompletedLogBudgetBytes = 10
	options.MaxLogBytes = 10
	call("create", "trigger", "sleep 30", options.JSON())
	t.Cleanup(func() { call("cancel", "trigger"); awaitRun(t, call, "trigger") })
	if result := call("get", "expired"); result.Code != 410 {
		t.Fatalf("expired result retained: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(root, ".runs", "expired")); !os.IsNotExist(err) {
		t.Fatalf("expired run still occupies disk: %v", err)
	}
	if result := call("create", "expired", "echo duplicate > duplicate", DefaultOptions().JSON()); result.Code != 410 {
		t.Fatalf("expired ID was executable: %+v", result)
	}
	if got := call("get", "oldest").Run; !got.LogsEvicted || got.Status != "Failed" || got.ExitCode == nil || *got.ExitCode != 3 || got.LogBytes != 8 || got.LogStartOffset != 8 || !got.LogTruncated {
		t.Fatalf("budget eviction lost result or offsets: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, ".runs", "oldest", "logs")); !os.IsNotExist(err) {
		t.Fatalf("budget did not reclaim log storage: %v", err)
	}
	if got := streamRunLog(t, root, "oldest", "0"); len(got.Bytes) != 0 || got.Offset != 8 || got.Code != 0 || !got.Run.LogsEvicted {
		t.Fatalf("evicted log resume: %+v", got)
	}
	if got := call("get", "newer").Run; got.LogsEvicted || got.Status != "Failed" || got.LogBytes != 8 {
		t.Fatalf("newer terminal log evicted first: %+v", got)
	}
	if got := call("get", "live").Run; got.Status != "Running" || got.LogBytes <= 10 {
		t.Fatalf("live run was evicted or truncated by completed budget: %+v", got)
	}

	page := call("list", "0", "2").Runs
	if len(page) != 2 || page[0].ID != "trigger" || page[1].ID != "live" {
		t.Fatalf("list order/page: %+v", page)
	}
	if page = call("list", "2", "2").Runs; len(page) != 2 || page[0].ID != "newer" || page[1].ID != "oldest" {
		t.Fatalf("list next page: %+v", page)
	}
}

func TestRunnerDeletionPreservesLiveRunsAndIDs(t *testing.T) {
	root, call := localRunner(t)
	call("create", "live", "sleep 30", DefaultOptions().JSON())
	t.Cleanup(func() { call("cancel", "live"); awaitRun(t, call, "live") })
	writeTerminalRun(t, root, "newer", time.Hour, []byte("12345678"))
	if got := call("delete", "live"); got.Code != 409 {
		t.Fatalf("live deletion accepted: %+v", got)
	}
	for range 2 {
		if got := call("delete", "newer"); got.Code != 0 {
			t.Fatalf("terminal deletion not idempotent: %+v", got)
		}
	}
	if got := call("create", "newer", "echo duplicate > duplicate", DefaultOptions().JSON()); got.Code != 410 {
		t.Fatalf("deleted ID was executable: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "duplicate")); !os.IsNotExist(err) {
		t.Fatalf("retried deleted command ran: %v", err)
	}
}

func writeTerminalRun(t *testing.T, root, id string, age time.Duration, output []byte) string {
	t.Helper()
	directory := filepath.Join(root, ".runs", id)
	if err := os.MkdirAll(filepath.Join(directory, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(map[string]any{
		"version": 1, "id": id, "command": "echo fixture", "status": "Failed", "exitCode": 3,
		"startedAt":   time.Now().Add(-age - time.Second).Format(time.RFC3339),
		"finishedAt":  time.Now().Add(-age).Format(time.RFC3339),
		"maxLogBytes": DefaultOptions().MaxLogBytes, "timeoutSeconds": 7200, "requestedTimeoutSeconds": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"state.json": state, "logs/00000000000000000000.log": output} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(directory, "state.json")
}

func TestActivityWithoutPythonUsesProcAndPTYs(t *testing.T) {
	for _, tc := range []struct {
		name, stat        string
		pty, python, want bool
	}{
		{name: "idle"},
		{name: "exec", stat: "123 (shell command) S 0", want: true},
		{name: "orphan", stat: "123 (background) S 1"},
		{name: "zombie", stat: "123 (dead) Z 0"},
		{name: "terminal", pty: true, want: true},
		{name: "exec skips Python", stat: "123 (shell command) S 0", python: true, want: true},
		{name: "terminal skips Python", pty: true, python: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			proc, pts := filepath.Join(root, "proc"), filepath.Join(root, "pts")
			for _, directory := range []string{filepath.Join(proc, "123"), pts} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.stat != "" {
				if err := os.WriteFile(filepath.Join(proc, "123", "stat"), []byte(tc.stat+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.pty {
				if err := os.WriteFile(filepath.Join(pts, "0"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.python {
				if err := os.WriteFile(filepath.Join(root, "python3"), []byte("#!/bin/sh\nexit 99\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			argv, input := ActivityCommand()
			argv[4], argv[5] = proc, pts
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Stdin = strings.NewReader(input)
			cmd.Env = []string{"PATH=" + root} // No procps; Python must not run when the shell detects activity.
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != fmt.Sprintf("{\"active\":%t}\n", tc.want) {
				t.Fatalf("activity: %q, %v", out, err)
			}
		})
	}
}

func TestWorkspaceInitReapsSupervisorAndBackgroundChildren(t *testing.T) {
	initPath, err := exec.LookPath("catatonit")
	if err != nil {
		t.Skip("catatonit is required for the workspace init integration test (installed in CI)")
	}
	// catatonit becomes a subreaper when tested outside a PID namespace. Keep
	// its direct child alive while the actual runner forks and exits; neither
	// this harness nor the Go test can reap the orphaned supervisor/descendant.
	const harness = `import json, pathlib, subprocess, sys, time
root = pathlib.Path(sys.argv[1])
subprocess.run(json.loads(sys.argv[2]), input=sys.stdin.read(), text=True, check=True, capture_output=True, timeout=5)
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    state = json.loads((root / ".runs/reaping/state.json").read_text())
    child = root / "child-pid"
    if child.exists() and state["status"] == "Succeeded":
        pids = [state["pid"], int(child.read_text())]
        if all(not pathlib.Path(f"/proc/{pid}").exists() for pid in pids):
            print("reaped supervisor and child")
            sys.exit(0)
    time.sleep(0.02)
raise RuntimeError("orphan processes were not reaped: " + str(state))
`
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	root := t.TempDir()
	argv, input := Command("create", "reaping", "sleep 30 & echo $! > child-pid; sleep 0.2", DefaultOptions().JSON())
	encodedArgv, err := json.Marshal(argv)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, initPath, "--", "python3", "-I", "-c", harness, root, string(encodedArgv))
	cmd.Stdin = strings.NewReader(localRunnerInput(root, input))
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "reaped supervisor and child\n" {
		t.Fatalf("init lifecycle: %q, %v", out, err)
	}
}

func TestRunnerDoesNotWaitForPipeHeldOutsideProcessGroup(t *testing.T) {
	root, call := localRunner(t)
	t.Cleanup(func() {
		data, err := os.ReadFile(filepath.Join(root, "escaped-pid"))
		if err == nil {
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Error(err)
				return
			}
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	call("create", "escaped", `python3 -c 'import os, time
from pathlib import Path
pid = os.fork()
if pid == 0:
    os.setsid()
    time.sleep(30)
    os._exit(0)
Path("escaped-pid").write_text(str(pid))
print("parent complete")'`, DefaultOptions().JSON())
	run := awaitRun(t, call, "escaped")
	if run.Status != "Succeeded" || string(streamRunLog(t, root, "escaped", "0").Bytes) != "parent complete\n" {
		t.Fatalf("escaped pipe holder prevented completion: %+v", run)
	}
}

func TestIdleLogFollowerExitsAtItsCapWithoutStoppingRun(t *testing.T) {
	root, call := localRunner(t)
	call("create", "idle", "sleep 30", DefaultOptions().JSON())
	t.Cleanup(func() { call("cancel", "idle"); awaitRun(t, call, "idle") })
	argv, input := Command("stream", "idle", "0", "0", "true", "0.2")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(localRunnerInput(root, input))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var result runnerResult
	decodeErr := json.Unmarshal(stderr.Bytes(), &result)
	if err != nil || decodeErr != nil || len(out) != 0 || result.Run.Status != "Running" || call("get", "idle").Run.Status != "Running" {
		t.Fatalf("idle follower: output=%q stderr=%q err=%v decode=%v", out, stderr.String(), err, decodeErr)
	}
}

func localRunner(t *testing.T) (string, func(string, ...string) runnerResult) {
	t.Helper()
	root := t.TempDir()
	return root, func(action string, args ...string) runnerResult {
		t.Helper()
		argv, input := Command(action, args...)
		out, _ := executeRunner(t, root, argv, input)
		var result runnerResult
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("runner %s: %v: %s", action, err, out)
		}
		return result
	}
}

// executeRunner exercises the embedded protocol in the same untrusted working
// directory as the command, with the container's ordinary umask.
func executeRunner(t *testing.T, root string, argv []string, input string) ([]byte, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", `umask 022; exec "$@"`, "--"}, argv...)...)
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(localRunnerInput(root, input))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("runner: %v: %s", err, stderr.String())
	}
	return out, stderr.Bytes()
}

func localRunnerInput(root, input string) string {
	input = strings.Replace(input, `"/workspace/.runs"`, strconv.Quote(filepath.Join(root, ".runs")), 1)
	return strings.Replace(input, `"/workspace/src"`, strconv.Quote(root), 1)
}

type runnerLog struct {
	runnerResult
	Bytes  []byte
	Offset int64
}

func streamRunLog(t *testing.T, root, id, offset string) runnerLog {
	t.Helper()
	argv, input := Command("get", id)
	out, _ := executeRunner(t, root, argv, input)
	var result runnerLog
	if err := json.Unmarshal(out, &result.runnerResult); err != nil || result.Code != 0 {
		t.Fatalf("get before stream: %s, %v", out, err)
	}
	requested, err := strconv.ParseInt(offset, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	result.Offset = max(requested, result.Run.LogStartOffset)
	argv, input = Command("stream", id, strconv.FormatInt(result.Offset, 10), strconv.FormatInt(result.Run.LogBytes, 10), "false", "1")
	output, metadata := executeRunner(t, root, argv, input)
	if err := json.Unmarshal(metadata, &result.runnerResult); err != nil {
		t.Fatalf("stream metadata: %s, %v", metadata, err)
	}
	result.Bytes = output
	return result
}

func TestRunnerPreservesCommandUmaskAndSignals(t *testing.T) {
	root, call := localRunner(t)
	// Compare the numeric disposition; enum string formatting varies by Python version.
	call("create", "permissions", `echo artifact > artifact; mkdir objects; python3 -c 'import signal; print(int(signal.getsignal(signal.SIGHUP)))'`, DefaultOptions().JSON())
	run := awaitRun(t, call, "permissions")
	if run.Status != "Succeeded" {
		t.Fatalf("run: %+v", run)
	}
	for filename, mode := range map[string]os.FileMode{"artifact": 0o644, "objects": 0o755, ".runs/permissions/state.json": 0o600} {
		info, err := os.Stat(filepath.Join(root, filename))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s permissions: %v, %v; want %o", filename, info, err, mode)
		}
	}
	if output := string(streamRunLog(t, root, "permissions", "0").Bytes); output != "0\n" {
		t.Fatalf("SIGHUP should have its normal disposition: %q", output)
	}
}

func awaitRun(t *testing.T, call func(string, ...string) runnerResult, id string) buildcontract.WorkspaceRun {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		run := call("get", id).Run
		if run.Terminal() {
			return run
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return buildcontract.WorkspaceRun{}
}

func TestRunnerRetainsOutputAndResultAfterLauncherExits(t *testing.T) {
	root, call := localRunner(t)
	command := `printf 'one\000'; while [ ! -f release ]; do sleep 0.05; done; printf '\377two' >&2; exit 23`
	run := call("create", "durable", command, DefaultOptions().JSON()).Run
	if run.ID != "durable" || run.Status != "Running" {
		t.Fatalf("create: %+v", run)
	}
	t.Cleanup(func() { call("cancel", "durable"); awaitRun(t, call, "durable") })
	if !call("active").Active {
		t.Fatal("detached command did not count as activity")
	}
	// Repeating a request after the launch connection was lost must not execute
	// another command, and a different payload must not overwrite its output.
	if got := call("create", "durable", command, DefaultOptions().JSON()).Run; got.StartedAt != run.StartedAt {
		t.Fatalf("duplicate creation: %+v", got)
	}
	if got := call("create", "durable", "echo duplicate", DefaultOptions().JSON()).Code; got != 409 {
		t.Fatalf("conflicting command: %d", got)
	}
	if err := os.WriteFile(filepath.Join(root, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	run = awaitRun(t, call, "durable")
	if run.Status != "Failed" || run.ExitCode == nil || *run.ExitCode != 23 || run.FinishedAt == "" {
		t.Fatalf("result: %+v", run)
	}
	if got := streamRunLog(t, root, "durable", "2").Bytes; !bytes.Equal(got, []byte{'e', 0, 255, 't', 'w', 'o'}) {
		t.Fatalf("resumed bytes: %q", got)
	}
	if got := streamRunLog(t, root, "durable", "8"); len(got.Bytes) != 0 || got.Code != 0 {
		t.Fatalf("EOF: %+v", got)
	}
	if got := streamRunLog(t, root, "durable", "9").Code; got != 416 {
		t.Fatalf("offset beyond EOF: %d", got)
	}
	if call("active").Active {
		t.Fatal("finished run counted as activity")
	}
	if got := call("cancel", "durable").Run; got.Status != "Failed" || *got.ExitCode != 23 {
		t.Fatalf("cancellation changed completed result: %+v", got)
	}
}

func TestRunnerConcurrentCreationExecutesOnce(t *testing.T) {
	root, call := localRunner(t)
	var group sync.WaitGroup
	for range 6 {
		group.Go(func() { call("create", "once", "echo execution >> count; sleep 0.2", DefaultOptions().JSON()) })
	}
	group.Wait()
	awaitRun(t, call, "once")
	data, err := os.ReadFile(filepath.Join(root, "count"))
	if err != nil || string(data) != "execution\n" {
		t.Fatalf("duplicate execution: %q, %v", data, err)
	}
}

func TestRunnerCancellationKillsTERMResistantDescendants(t *testing.T) {
	root, call := localRunner(t)
	call("create", "cancel", `trap '' TERM; sh -c 'trap "" TERM; echo ready > ready; while :; do echo tick >> ticks; sleep 0.05; done' & wait`, DefaultOptions().JSON())
	t.Cleanup(func() { call("cancel", "cancel"); awaitRun(t, call, "cancel") })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command failed to start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := call("cancel", "cancel").Run.Status; got != "Cancelling" {
		t.Fatalf("cancel: %s", got)
	}
	call("cancel", "cancel")
	run := awaitRun(t, call, "cancel")
	if run.Status != "Cancelled" || run.ExitCode == nil || *run.ExitCode != 137 {
		t.Fatalf("cancellation result: %+v", run)
	}
	before, err := os.ReadFile(filepath.Join(root, "ticks"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	after, err := os.ReadFile(filepath.Join(root, "ticks"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("descendant survived cancellation")
	}
}

func TestRunnerRecoversStaleIdentityWithoutInventingExitCode(t *testing.T) {
	root, call := localRunner(t)
	call("create", "stale", "printf retained", DefaultOptions().JSON())
	awaitRun(t, call, "stale")
	filename := filepath.Join(root, ".runs", "stale", "state.json")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state["status"], state["pid"] = "Running", os.Getpid()
	state["identity"] = []string{"old-boot", "old-container", "old-process"}
	delete(state, "exitCode")
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if call("active").Active {
		t.Fatal("stale run prevents auto-pause")
	}
	run := call("cancel", "stale").Run
	if run.Status != "Interrupted" || run.ExitCode != nil || !strings.Contains(run.Message, "exit code") {
		t.Fatalf("stale result: %+v", run)
	}
	if got := string(streamRunLog(t, root, "stale", "0").Bytes); got != "retained" {
		t.Fatalf("lost persisted log: %q", got)
	}
	if got := call("get", "../stale").Code; got != 400 {
		t.Fatalf("invalid ID accepted: %d", got)
	}
	if got := call("get", "missing").Code; got != 404 {
		t.Fatalf("missing run: %d", got)
	}
}
