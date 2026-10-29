//go:build linux

package workspacerun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRunnerRequestUsesStdinAndPreservesLiteralContents(t *testing.T) {
	root, call := localRunner(t)
	const output = "quoted ' and \"; \\ backslash\n🙂\u2028end\n"
	const command = "cat <<'DATA'\n" + output + "DATA\n"
	argv, input := Command("create", "stdin", command, DefaultOptions().JSON())
	if !slices.Equal(argv, []string{"python3", "-I", "-"}) {
		t.Fatalf("runner or request payload included in exec argv: %d arguments", len(argv))
	}
	if !strings.Contains(input, script) {
		t.Fatal("runner source missing from stdin")
	}
	if got := call("create", "stdin", command, DefaultOptions().JSON()); got.Code != 0 {
		t.Fatalf("stdin launch: %+v", got)
	}
	if run := awaitRun(t, call, "stdin"); run.Status != "Succeeded" || run.Command != command {
		t.Fatalf("request contents changed in transit: %+v", run)
	}
	if got := streamRunLog(t, root, "stdin", "0"); string(got.Bytes) != output {
		t.Fatalf("stdin command output: %q", got.Bytes)
	}
	if got := call("get", "\"]; open('injected', 'w').close(); #\n"); got.Code != 400 {
		t.Fatalf("request data escaped into Python: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "injected")); !os.IsNotExist(err) {
		t.Fatalf("request data executed as Python: %v", err)
	}
}

func TestRunRecordsPersistVersionOne(t *testing.T) {
	root, call := localRunner(t)
	call("create", "versioned", "sleep 30", DefaultOptions().JSON())
	t.Cleanup(func() { call("cancel", "versioned"); awaitRun(t, call, "versioned") })
	for _, phase := range []string{"running", "cancelled"} {
		if phase == "cancelled" {
			call("cancel", "versioned")
			awaitRun(t, call, "versioned")
		}
		data, err := os.ReadFile(filepath.Join(root, ".runs", "versioned", "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		if err := json.Unmarshal(data, &state); err != nil || state["version"] != float64(1) {
			t.Fatalf("%s record lacks format version 1: %s, %v", phase, data, err)
		}
	}
}

func TestUnversionedRecordsRemainReadable(t *testing.T) {
	root, call := localRunner(t)
	filename := writeTerminalRun(t, root, "unversioned", time.Hour, []byte("old output"))
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	delete(state, "version")
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := call("get", "unversioned"); got.Code != 0 || got.Run.ExitCode == nil || *got.Run.ExitCode != 3 {
		t.Fatalf("unversioned result lost during upgrade: %+v", got)
	}
	if got := streamRunLog(t, root, "unversioned", "0"); string(got.Bytes) != "old output" {
		t.Fatalf("unversioned output lost during upgrade: %q", got.Bytes)
	}
}

func TestNewerRunRecordsDoNotBlockWorkspace(t *testing.T) {
	root, call := localRunner(t)
	writeTerminalRun(t, root, "known", time.Hour, []byte("known output"))
	filename, record := writeNewerRun(t, root, newerEnvelope("future", "Failed", 2*time.Hour))
	if got := call("active"); got.Code != 0 || got.Active {
		t.Fatalf("finished newer record prevents auto-pause: %+v", got)
	}
	if got := call("get", "future"); got.Code != 0 || got.Run.Status != "Failed" || got.Run.ExitCode != nil || got.Run.Command != "" || !strings.Contains(got.Run.Message, "newer record format") {
		t.Fatalf("newer record did not expose only lifecycle metadata: %+v", got)
	}
	if got := call("list", "0", "100"); got.Code != 0 || len(got.Runs) != 2 || got.Runs[0].ID != "known" || got.Runs[1].ID != "future" || !strings.Contains(got.Runs[1].Message, "newer record format") {
		t.Fatalf("mixed-version list/order: %+v", got)
	}
	options := DefaultOptions()
	options.CompletedLogBudgetBytes = 1 // Must not interpret or evict opaque newer logs.
	if got := call("create", "healthy", "printf healthy", options.JSON()); got.Code != 0 {
		t.Fatalf("newer record blocked unrelated creation: %+v", got)
	}
	if run := awaitRun(t, call, "healthy"); run.Status != "Succeeded" {
		t.Fatalf("unrelated command failed: %+v", run)
	}
	for _, args := range [][]string{{"cancel", "future"}, {"create", "future", "echo duplicate > duplicate", options.JSON()}} {
		if got := call(args[0], args[1:]...); got.Code != 409 || !strings.Contains(got.Error, "compatible operator") {
			t.Fatalf("%s interpreted an unsupported payload: %+v", args[0], got)
		}
	}
	argv, input := Command("stream", "future", "0", "0", "false", "1")
	out, stderr := executeRunner(t, root, argv, input)
	var result runnerResult
	if err := json.Unmarshal(stderr, &result); err != nil || result.Code != 409 || len(out) != 0 {
		t.Fatalf("stream interpreted unsupported logs: stdout=%q stderr=%q decode=%v", out, stderr, err)
	}
	if _, err := os.Stat(filepath.Join(root, "duplicate")); !os.IsNotExist(err) {
		t.Fatalf("newer run ID executed again: %v", err)
	}
	assertNewerRecordUnchanged(t, filename, record)
	if got := call("delete", "future"); got.Code != 0 {
		t.Fatalf("finished newer record cannot be deleted: %+v", got)
	}
	if got := call("get", "future"); got.Code != 410 {
		t.Fatalf("deleting newer record lost its tombstone: %+v", got)
	}
}

func TestNewerRunLivenessAndAmbiguousEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name, wantStatus string
		active           bool
		change           func(map[string]any)
	}{
		{name: "live", wantStatus: "Running", active: true},
		{name: "reused PID", wantStatus: "Interrupted", change: func(state map[string]any) { state["identity"] = []string{"old-boot", "old-container", "old-process"} }},
		{name: "missing PID", wantStatus: "Unknown", active: true, change: func(state map[string]any) { delete(state, "pid") }},
		{name: "unknown status", wantStatus: "Unknown", active: true, change: func(state map[string]any) { state["status"] = "FutureStatus" }},
		{name: "missing start", wantStatus: "Unknown", active: true, change: func(state map[string]any) { delete(state, "startedAt") }},
		{name: "invalid finish", wantStatus: "Unknown", active: true, change: func(state map[string]any) { state["status"], state["finishedAt"] = "Succeeded", "not-a-date" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, call := localRunner(t)
			state := newerEnvelope("future", "Running", time.Hour)
			state["pid"], state["identity"] = os.Getpid(), currentProcessIdentity(t)
			if tc.change != nil {
				tc.change(state)
			}
			filename, record := writeNewerRun(t, root, state)
			if got := call("active"); got.Code != 0 || got.Active != tc.active {
				t.Fatalf("newer run liveness: %+v", got)
			}
			if got := call("get", "future"); got.Code != 0 || got.Run.Status != tc.wantStatus || got.Run.ExitCode != nil || !strings.Contains(got.Run.Message, "newer record format") {
				t.Fatalf("newer envelope status: %+v", got)
			}
			if got := call("list", "0", "100"); got.Code != 0 || len(got.Runs) != 1 || got.Runs[0].Status != tc.wantStatus {
				t.Fatalf("newer envelope not visible: %+v", got)
			}
			if got := call("create", "healthy", "true", DefaultOptions().JSON()); got.Code != 0 {
				t.Fatalf("uncertain record blocked unrelated command: %+v", got)
			}
			awaitRun(t, call, "healthy")
			assertNewerRecordUnchanged(t, filename, record)
			wantDelete := 0
			if tc.active {
				wantDelete = 409
			}
			if got := call("delete", "future"); got.Code != wantDelete {
				t.Fatalf("unsafe or unavailable deletion: %+v", got)
			}
		})
	}
}

func TestNewerTerminalRecordsRespectRetentionAndCount(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		stale bool
	}{{"retention", false}, {"retention", true}, {"count", false}, {"count", true}} {
		t.Run(fmt.Sprintf("%s/stale=%t", tc.kind, tc.stale), func(t *testing.T) {
			root, call := localRunner(t)
			options := DefaultOptions()
			age := 8 * 24 * time.Hour
			if tc.kind == "count" {
				age, options.MaxRecords = 2*time.Hour, 1
			}
			old := newerEnvelope("old", "Failed", age)
			if tc.stale {
				old["status"], old["pid"], old["identity"] = "Running", os.Getpid(), []string{"old-boot", "old-container", "old-process"}
				delete(old, "finishedAt")
			}
			oldFilename, oldRecord := writeNewerRun(t, root, old)
			if tc.stale {
				modified := time.Now().Add(-age).Truncate(time.Second)
				if err := os.Chtimes(oldFilename, modified, modified); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					got := call("get", "old")
					finished, err := time.Parse(time.RFC3339Nano, got.Run.FinishedAt)
					if err != nil || got.Code != 0 || got.Run.Status != "Interrupted" || got.Run.ExitCode != nil || !finished.Equal(modified) {
						t.Errorf("stale newer run did not retain its modification time %s: %+v, %v", modified, got, err)
					}
				}
				assertNewerRecordUnchanged(t, oldFilename, oldRecord)
				if info, err := os.Stat(oldFilename); err != nil || !info.ModTime().Equal(modified) {
					t.Fatalf("read changed newer record modification time: %v, %v", info, err)
				}
			}
			writeTerminalRun(t, root, "recent", time.Hour, nil)
			live := newerEnvelope("live", "Running", 9*24*time.Hour)
			live["pid"], live["identity"] = os.Getpid(), currentProcessIdentity(t)
			filename, record := writeNewerRun(t, root, live)
			if got := call("create", "trigger", "sleep 30", options.JSON()); got.Code != 0 {
				t.Fatalf("newer record blocked pruning: %+v", got)
			}
			t.Cleanup(func() { call("cancel", "trigger"); awaitRun(t, call, "trigger") })
			if got := call("get", "old"); got.Code != 410 {
				t.Fatalf("%s did not remove old newer record: %+v", tc.kind, got)
			}
			if got := call("get", "recent"); got.Code != 0 || got.Run.ExitCode == nil || *got.Run.ExitCode != 3 {
				t.Fatalf("%s removed recent result: %+v", tc.kind, got)
			}
			assertNewerRecordUnchanged(t, filename, record)
		})
	}
}

func newerEnvelope(id, status string, age time.Duration) map[string]any {
	state := map[string]any{
		"version": 2, "id": id, "status": status,
		"startedAt": time.Now().Add(-age - time.Second).UTC().Format(time.RFC3339),
	}
	if status != "Running" {
		state["finishedAt"] = time.Now().Add(-age).UTC().Format(time.RFC3339)
	}
	return state
}

func currentProcessIdentity(t *testing.T) []string {
	t.Helper()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+1:])
	return []string{strings.TrimSpace(string(boot)), namespace, fields[19]}
}

func writeNewerRun(t *testing.T, root string, state map[string]any) (string, []byte) {
	t.Helper()
	directory := filepath.Join(root, ".runs", state["id"].(string))
	if err := os.MkdirAll(filepath.Join(directory, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Payload fields and log layout deliberately conflict with version 1. Only
	// the envelope is shared, and an older reader must not expose private data.
	state["command"], state["maxLogBytes"] = map[string]string{"private": "new payload"}, "not-an-integer"
	state["exitCode"], state["logsEvicted"] = "new result encoding", "new log encoding"
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "state.json")
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "logs", "opaque.log"), []byte("new log encoding"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filename, data
}

func assertNewerRecordUnchanged(t *testing.T, filename string, want []byte) {
	t.Helper()
	if data, err := os.ReadFile(filename); err != nil || !bytes.Equal(data, want) {
		t.Fatalf("newer record changed: %s, %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "logs", "opaque.log")); err != nil || string(data) != "new log encoding" {
		t.Fatalf("newer logs changed: %q, %v", data, err)
	}
}
