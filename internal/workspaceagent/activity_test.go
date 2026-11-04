package workspaceagent

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeStat(t *testing.T, procDir string, pid int, stat string) {
	t.Helper()
	dir := filepath.Join(procDir, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestActivityCountsRunsTerminalsAndExecProcesses(t *testing.T) {
	a := newTestAgent(t)
	a.procDir, a.ptsDir = t.TempDir(), t.TempDir()
	self := os.Getpid()
	writeStat(t, a.procDir, 1, "1 (catatonit) S 0 1 1 0")
	writeStat(t, a.procDir, self, strconv.Itoa(self)+" (workspace-agent) S 0 1 1 0")
	writeStat(t, a.procDir, 40, "40 (sleep) S 1 1 1 0")
	writeStat(t, a.procDir, 41, "41 (zombie shell) Z 0 41 41 0")

	activity, err := a.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if activity.Active {
		t.Errorf("activity = %+v, want idle: PID 1, the agent, children of PID 1 and zombies don't count", activity)
	}

	writeStat(t, a.procDir, 42, "42 (bash (exec)) S 0 42 42 0")
	for _, name := range []string{"0", "ptmx"} {
		if err := os.WriteFile(filepath.Join(a.ptsDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	create(t, a, "busy", "sleep 30", testOptions())
	t.Cleanup(func() { _, _ = a.Cancel("busy") })

	activity, err = a.Activity()
	if err != nil {
		t.Fatal(err)
	}
	want := ActivityResponse{Active: true, LiveRuns: 1, Terminals: 1, ExecProcesses: 1}
	if activity != want {
		t.Errorf("activity = %+v, want %+v", activity, want)
	}
}

// Syncs run inside the agent, so no exec process stands for them.
func TestActivityCountsSyncs(t *testing.T) {
	a := newTestAgent(t)
	a.procDir, a.ptsDir = t.TempDir(), t.TempDir()
	a.syncing.Add(1)

	activity, err := a.Activity()
	if err != nil {
		t.Fatal(err)
	}
	if want := (ActivityResponse{Active: true, Syncs: 1}); activity != want {
		t.Errorf("activity = %+v, want %+v", activity, want)
	}
}
