//go:build linux

package workspacerun

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunnerRecordCapPreservesNewestResultsAndLiveRuns(t *testing.T) {
	root, call := localRunner(t)
	options := DefaultOptions()
	options.MaxRecords = 2
	call("create", "live", "sleep 30", options.JSON())
	t.Cleanup(func() { call("cancel", "live"); awaitRun(t, call, "live") })
	for id, age := range map[string]time.Duration{"oldest": 3 * time.Hour, "newer": 2 * time.Hour, "newest": time.Hour} {
		writeTerminalRun(t, root, id, age, []byte(id))
	}
	call("create", "trigger", "sleep 30", options.JSON())
	t.Cleanup(func() { call("cancel", "trigger"); awaitRun(t, call, "trigger") })
	if got := call("get", "oldest"); got.Code != 410 {
		t.Fatalf("record cap did not evict the oldest result: %+v", got)
	}
	if got := call("create", "oldest", "true", options.JSON()); got.Code != 410 {
		t.Fatalf("record eviction lost retry protection: %+v", got)
	}
	for _, id := range []string{"newer", "newest"} {
		if got := call("get", id); got.Code != 0 || got.Run.ExitCode == nil || *got.Run.ExitCode != 3 {
			t.Fatalf("record cap lost %s: %+v", id, got)
		}
	}
	if got := call("list", "0", "100"); got.Code != 0 || len(got.Runs) != 4 {
		t.Fatalf("record cap counted live runs: %+v", got)
	}
	call("cancel", "trigger")
	awaitRun(t, call, "trigger")
	// Completion also enforces the cap, after the final result is saved.
	deadline := time.Now().Add(3 * time.Second)
	for call("get", "newer").Code != 410 {
		if time.Now().After(deadline) {
			t.Fatal("completion did not evict the oldest remaining result")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := call("get", "live"); got.Code != 0 || got.Run.Status != "Running" {
		t.Fatalf("record cap evicted a live run: %+v", got)
	}
	if got := call("get", "trigger"); got.Code != 0 || got.Run.Status != "Cancelled" {
		t.Fatalf("completion lost its own result: %+v", got)
	}
}

func TestUnreadableRecordsCanBeDeleted(t *testing.T) {
	for _, contents := range []string{`{"id":`, `{}`, "null", "missing"} {
		t.Run(contents, func(t *testing.T) {
			root, call := localRunner(t)
			filename := writeTerminalRun(t, root, "broken", time.Hour, []byte("retained log"))
			wantCode := 422
			if contents == "missing" {
				if err := os.Remove(filename); err != nil {
					t.Fatal(err)
				}
				wantCode = 404
			} else if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := call("get", "broken"); got.Code != wantCode {
				t.Fatalf("record is not unreadable: %+v", got)
			}
			for range 2 {
				if got := call("delete", "broken"); got.Code != 0 {
					t.Fatalf("unreadable record deletion: %+v", got)
				}
			}
			if _, err := os.Stat(filepath.Dir(filename)); !os.IsNotExist(err) {
				t.Fatalf("record and logs still occupy disk: %v", err)
			}
			if got := call("create", "broken", "true", DefaultOptions().JSON()); got.Code != 410 {
				t.Fatalf("corrupt record deletion lost retry protection: %+v", got)
			}
		})
	}
}

func TestInterruptedRecordWriteFailureDoesNotBlockReadsOrLaunch(t *testing.T) {
	root, call := localRunner(t)
	filename := writeTerminalRun(t, root, "stale", time.Hour, []byte("retained output"))
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state["status"], state["pid"], state["identity"] = "Running", os.Getpid(), []string{"old-boot", "old-container", "old-process"}
	delete(state, "exitCode")
	delete(state, "finishedAt")
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate a full volume when persisting the stale record's transition.
	// Other records remain writable so create must still reach its own launch.
	const failRecoveryWrite = `import errno
from pathlib import Path
original_open = Path.open
def fail_recovery_write(path, *args, **kwargs):
    if path.name == "state.tmp" and path.parent.name == "stale":
        raise OSError(errno.ENOSPC, "injected full volume")
    return original_open(path, *args, **kwargs)
Path.open = fail_recovery_write
`
	for _, args := range [][]string{{"get", "stale"}, {"active"}, {"list", "0", "100"}, {"create", "healthy", "printf healthy", DefaultOptions().JSON()}} {
		argv, input := Command(args[0], args[1:]...)
		input = failRecoveryWrite + input
		out, stderr := executeRunner(t, root, argv, input)
		var result runnerResult
		if err := json.Unmarshal(out, &result); err != nil || result.Code != 0 || len(stderr) != 0 {
			t.Fatalf("%s blocked by recovery write: %q, stderr=%q, decode=%v", args[0], out, stderr, err)
		}
		switch args[0] {
		case "get":
			if result.Run.Status != "Interrupted" || result.Run.ExitCode != nil {
				t.Fatalf("stale read: %+v", result)
			}
		case "active":
			if result.Active {
				t.Fatal("failed recovery write prevents auto-pause")
			}
		case "list":
			if len(result.Runs) != 1 || result.Runs[0].Status != "Interrupted" {
				t.Fatalf("stale list: %+v", result)
			}
		}
	}
	if run := awaitRun(t, call, "healthy"); run.Status != "Succeeded" {
		t.Fatalf("healthy launch blocked by stale record: %+v", run)
	}
	data, err = os.ReadFile(filename)
	if err != nil || !strings.Contains(string(data), `"Running"`) {
		t.Fatalf("failure injection did not preserve the stale on-disk record: %s, %v", data, err)
	}
	if got := call("get", "stale"); got.Code != 0 || got.Run.Status != "Interrupted" {
		t.Fatalf("recovery after storage becomes writable: %+v", got)
	}
}

func TestLaunchRetryRecoversFromInitialStateWriteFailure(t *testing.T) {
	root, call := localRunner(t)
	directory := filepath.Join(root, ".runs", "retry")
	// Prevent the initial record from being written after logs/ is created.
	// Removing the obstruction must let the same request launch exactly once.
	if err := os.MkdirAll(filepath.Join(directory, "state.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	const command = `echo execution >> count; printf recovered; exit 3`
	if got := call("create", "retry", command, DefaultOptions().JSON()); got.Code != 500 || !strings.Contains(got.Error, "IsADirectoryError") {
		t.Fatalf("initial state write: %+v", got)
	}
	if info, err := os.Stat(filepath.Join(directory, "logs")); err != nil || !info.IsDir() {
		t.Fatalf("failed launch did not leave a log directory: %v", err)
	}
	for _, name := range []string{filepath.Join(directory, "state.json"), filepath.Join(root, "count")} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("failed launch created %s: %v", name, err)
		}
	}
	if err := os.Remove(filepath.Join(directory, "state.tmp")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := call("create", "retry", command, DefaultOptions().JSON()); got.Code != 0 {
			t.Fatalf("retry after storage recovery: %+v", got)
		}
		run := awaitRun(t, call, "retry")
		if run.Status != "Failed" || run.ExitCode == nil || *run.ExitCode != 3 {
			t.Fatalf("recovered run: %+v", run)
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "count")); err != nil || string(data) != "execution\n" {
		t.Fatalf("retry did not execute exactly once: %q, %v", data, err)
	}
	if got := streamRunLog(t, root, "retry", "0"); got.Code != 0 || string(got.Bytes) != "recovered" {
		t.Fatalf("recovered log: %+v", got)
	}
}

func TestDirectorySyncFailurePreventsCommandLaunch(t *testing.T) {
	root, call := localRunner(t)
	// Inject an I/O error only when syncing a directory. File writes and the
	// rename still succeed, but the command must not start without a durable record.
	const failDirectorySync = `import errno, os, stat
original_fsync = os.fsync
def fail_directory_sync(fd):
    if stat.S_ISDIR(os.fstat(fd).st_mode):
        raise OSError(errno.EIO, "injected directory sync failure")
    original_fsync(fd)
os.fsync = fail_directory_sync
`
	argv, input := Command("create", "sync", "echo started > started", DefaultOptions().JSON())
	input = failDirectorySync + input
	out, stderr := executeRunner(t, root, argv, input)
	var result runnerResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("directory sync response: %q, %v", out, err)
	}
	if result.Code == 0 {
		awaitRun(t, call, "sync")
	}
	if result.Code != 500 || !strings.Contains(result.Error, "injected directory sync failure") || len(stderr) != 0 {
		t.Fatalf("directory sync failure was not reported: %+v, stderr=%q", result, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, ".runs", "sync", "state.json")); err != nil {
		t.Fatalf("failure occurred before replacing the state file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "started")); !os.IsNotExist(err) {
		t.Fatalf("command started before its record was durable: %v", err)
	}
	if got := call("get", "sync"); got.Code != 0 || got.Run.Status != "Interrupted" || got.Run.ExitCode != nil {
		t.Fatalf("unsynced launch must not invent an exit code: %+v", got)
	}
}

func TestSupervisorStartFailureReportsCause(t *testing.T) {
	// Injections are inherited by the forked supervisor. Failing before it
	// acknowledges the launch must be reported as such, not as an interruption.
	for _, tc := range []struct {
		name, inject, cause, persisted string
	}{{
		name: "running record write",
		inject: `import errno, os
from pathlib import Path
launcher, original_open = os.getpid(), Path.open
def fail_supervisor_write(path, *args, **kwargs):
    if path.name == "state.tmp" and os.getpid() != launcher:
        raise OSError(errno.ENOSPC, "injected full volume")
    return original_open(path, *args, **kwargs)
Path.open = fail_supervisor_write
`,
		cause:     "OSError: [Errno 28] injected full volume",
		persisted: "Failed",
	}, {
		name: "killed before acknowledging",
		inject: `import os, signal
os.setsid = lambda: os.kill(os.getpid(), signal.SIGKILL)
`,
		cause:     "it exited before acknowledging",
		persisted: "Failed",
	}, {
		// Only the initial Starting record fits, so the failure cannot be
		// persisted. The create response must still carry its cause.
		name: "failure record write",
		inject: `import errno
from pathlib import Path
original_open, writes = Path.open, [0]
def fill_volume(path, *args, **kwargs):
    if path.name == "state.tmp":
        writes[0] += 1
        if writes[0] > 1:
            raise OSError(errno.ENOSPC, "injected full volume")
    return original_open(path, *args, **kwargs)
Path.open = fill_volume
`,
		cause:     "OSError: [Errno 28] injected full volume",
		persisted: "Interrupted",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			root, call := localRunner(t)
			const command = "echo started > started"
			argv, input := Command("create", "start", command, DefaultOptions().JSON())
			out, stderr := executeRunner(t, root, argv, tc.inject+input)
			var result runnerResult
			if err := json.Unmarshal(out, &result); err != nil || len(stderr) != 0 {
				t.Fatalf("create response: %q, stderr=%q, decode=%v", out, stderr, err)
			}
			run := result.Run
			if result.Code != 0 || run.Status != "Failed" || run.ExitCode == nil || *run.ExitCode != 127 ||
				run.Message != "Run supervisor failed to start: "+tc.cause {
				t.Fatalf("create did not report the start failure: %+v", result)
			}
			// A transient-error retry with the same ID must not relaunch.
			retry := call("create", "start", command, DefaultOptions().JSON())
			if retry.Code != 0 || retry.Run.Status != tc.persisted {
				t.Fatalf("retry: %+v", retry)
			}
			if tc.persisted == "Failed" && (retry.Run.Message != run.Message || *retry.Run.ExitCode != 127) {
				t.Fatalf("retry did not return the recorded failure: %+v", retry)
			}
			if _, err := os.Stat(filepath.Join(root, "started")); !os.IsNotExist(err) {
				t.Fatalf("command started without an acknowledged supervisor: %v", err)
			}
		})
	}
}

func TestUnreadableRecordsDoNotBlockCollectionsOrLaunch(t *testing.T) {
	root, call := localRunner(t)
	for _, field := range []string{"truncated", "version", "finishedAt", "maxLogBytes", "exitCode", "message"} {
		filename := writeTerminalRun(t, root, strings.ToLower(field), time.Hour, nil)
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		if err := json.Unmarshal(data, &state); err != nil {
			t.Fatal(err)
		}
		switch field {
		case "truncated":
			data = []byte(`{"id":`)
		case "finishedAt":
			delete(state, field)
		default:
			state[field] = []string{"wrong type"}
		}
		if field != "truncated" {
			data, err = json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := call("get", strings.ToLower(field)); got.Code != 422 || !strings.Contains(got.Error, "unreadable run record") {
			t.Fatalf("bad %s record: %+v", field, got)
		}
	}
	if got := call("active"); got.Code != 0 || got.Active {
		t.Fatalf("bad records block auto-pause: %+v", got)
	}
	if got := call("list", "0", "100"); got.Code != 0 || len(got.Runs) != 0 {
		t.Fatalf("bad records block list: %+v", got)
	}
	if got := call("create", "healthy", "sleep 30", DefaultOptions().JSON()); got.Code != 0 || got.Run.Status != "Running" {
		t.Fatalf("bad records block launch: %+v", got)
	}
	t.Cleanup(func() { call("cancel", "healthy"); awaitRun(t, call, "healthy") })
	if got := call("active"); got.Code != 0 || !got.Active {
		t.Fatalf("healthy run lost among bad records: %+v", got)
	}
	if got := call("list", "0", "100"); got.Code != 0 || len(got.Runs) != 1 || got.Runs[0].ID != "healthy" {
		t.Fatalf("healthy run missing from list: %+v", got)
	}
}

func TestUnexpectedRunnerFailuresPreserveJSONProtocol(t *testing.T) {
	root, _ := localRunner(t)
	if err := os.WriteFile(filepath.Join(root, ".runs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	argv, input := Command("create", "run", "true", DefaultOptions().JSON())
	out, stderr := executeRunner(t, root, argv, input)
	var result runnerResult
	if err := json.Unmarshal(out, &result); err != nil || result.Code != 500 || !strings.Contains(result.Error, "FileExistsError") || len(stderr) != 0 {
		t.Fatalf("unexpected create error: %q stderr=%q decode=%v", out, stderr, err)
	}
	if err := os.Remove(filepath.Join(root, ".runs")); err != nil {
		t.Fatal(err)
	}
	writeTerminalRun(t, root, "run", time.Hour, nil)
	argv, input = Command("stream", "run", "0", "0", "true", "invalid-duration")
	out, stderr = executeRunner(t, root, argv, input)
	if err := json.Unmarshal(stderr, &result); err != nil || result.Code != 500 || !strings.Contains(result.Error, "ValueError") || len(out) != 0 {
		t.Fatalf("unexpected stream error: %q stderr=%q decode=%v", out, stderr, err)
	}
}

func TestRunnerIsolatedFromWorkspaceAndPythonEnvironment(t *testing.T) {
	root, call := localRunner(t)
	for _, name := range []string{"json.py", "subprocess.py"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(`raise RuntimeError("workspace module hijacked runner")`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PYTHONPATH", root)
	t.Setenv("PYTHONHOME", filepath.Join(root, "invalid-python-home"))
	if got := call("create", "isolated", "printf isolated", DefaultOptions().JSON()); got.Code != 0 {
		t.Fatalf("untrusted Python imports blocked launch: %+v", got)
	}
	if run := awaitRun(t, call, "isolated"); run.Status != "Succeeded" {
		t.Fatalf("isolated run: %+v", run)
	}
	if got := streamRunLog(t, root, "isolated", "0"); string(got.Bytes) != "isolated" || got.Code != 0 {
		t.Fatalf("isolated stream: %+v", got)
	}
	proc, pts := filepath.Join(root, "proc"), filepath.Join(root, "pts")
	for _, directory := range []string{filepath.Join(proc, "123"), pts} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proc, "123", "stat"), []byte("123 (background worker) S 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-matching /proc entry must preserve the Python argv, and activity
	// must use the same isolated interpreter as every other action.
	argv, input := ActivityCommand()
	argv[4], argv[5] = proc, pts
	out, stderr := executeRunner(t, root, argv, input)
	if string(out) != "{\"active\": false}\n" || len(stderr) != 0 {
		t.Fatalf("isolated activity: %q, %q", out, stderr)
	}
}

func TestResolvedBudgetKeepsLatestTailAndExitCode(t *testing.T) {
	root, call := localRunner(t)
	options := DefaultOptions()
	options.CompletedLogBudgetBytes = 1 << 20
	options.MaxLogBytes = 1 << 20 // The API resolves the cap before invoking Python.
	// Cross segment boundaries and finish mid-segment to exercise trimming.
	command := `python3 -c 'import sys; sys.stdout.buffer.write(b"x" * (2*1024*1024+123))'; printf 'last error'; exit 3`
	call("create", "large", command, options.JSON())
	run := awaitRun(t, call, "large")
	if run.Status != "Failed" || run.ExitCode == nil || *run.ExitCode != 3 || run.LogsEvicted || run.LogBytes-run.LogStartOffset != 1<<20 {
		t.Fatalf("budget lost latest result or tail: %+v", run)
	}
	got := streamRunLog(t, root, "large", "0")
	if got.Code != 0 || len(got.Bytes) != 1<<20 || !bytes.HasSuffix(got.Bytes, []byte("last error")) || got.Offset != run.LogStartOffset {
		t.Fatalf("budget tail: offset=%d bytes=%d code=%d", got.Offset, len(got.Bytes), got.Code)
	}
	// Wait for completion's collection cleanup, then repeat an independent
	// cleanup to verify the result and log still survive the budget.
	call("create", "after", "true", options.JSON())
	awaitRun(t, call, "after")
	if got := call("get", "large").Run; got.LogsEvicted || got.ExitCode == nil || *got.ExitCode != 3 {
		t.Fatalf("post-completion pruning lost latest non-empty log: %+v", got)
	}
}

func TestTombstonesExpireAndStayOutsideRunCollections(t *testing.T) {
	root, call := localRunner(t)
	writeTerminalRun(t, root, "old", time.Hour, []byte("old output"))
	if got := call("delete", "old"); got.Code != 0 {
		t.Fatal(got)
	}
	tombstone := filepath.Join(root, ".runs", ".deleted", "old")
	if got := call("create", "old", "true", DefaultOptions().JSON()); got.Code != 410 {
		t.Fatalf("retry window not protected: %+v", got)
	}
	expired := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(tombstone, expired, expired); err != nil {
		t.Fatal(err)
	}
	if got := call("get", "old"); got.Code != 404 {
		t.Fatalf("expired tombstone still visible: %+v", got)
	}
	// Tombstones are separate from run directories and never parsed as records.
	if got := call("list", "0", "100"); got.Code != 0 || len(got.Runs) != 0 {
		t.Fatalf("tombstones listed as runs: %+v", got)
	}
	if got := call("active"); got.Code != 0 || got.Active {
		t.Fatalf("tombstones blocked auto-pause: %+v", got)
	}
	call("create", "trigger", "true", DefaultOptions().JSON())
	awaitRun(t, call, "trigger")
	if _, err := os.Stat(tombstone); !os.IsNotExist(err) {
		t.Fatalf("expired tombstone not collected: %v", err)
	}
	// IDs are documented as single-use. Once their retry window is gone,
	// expired tombstones must not indefinitely reject a new request.
	if got := call("create", "old", "true", DefaultOptions().JSON()); got.Code != 0 {
		t.Fatalf("expired tombstone blocked launch: %+v", got)
	}
	awaitRun(t, call, "old")
}
