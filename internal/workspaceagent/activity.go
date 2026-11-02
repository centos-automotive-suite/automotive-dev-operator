package workspaceagent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ActivityResponse is the body of GET /activity.
type ActivityResponse struct {
	Active        bool `json:"active"`
	LiveRuns      int  `json:"liveRuns"`
	Terminals     int  `json:"terminals"`
	ExecProcesses int  `json:"execProcesses"`
}

// Activity reports what keeps the workspace from auto-pausing: live runs,
// open terminals, and processes started through pod exec, such as shells and
// syncs.
func (a *Agent) Activity() (ActivityResponse, error) {
	a.mu.Lock()
	var result ActivityResponse
	for _, rec := range a.records {
		if live(rec.Status) {
			result.LiveRuns++
		}
	}
	a.mu.Unlock()
	var err error
	if result.Terminals, err = countTerminals(a.ptsDir); err != nil {
		return result, err
	}
	if result.ExecProcesses, err = countExecProcesses(a.procDir, os.Getpid()); err != nil {
		return result, err
	}
	result.Active = result.LiveRuns+result.Terminals+result.ExecProcesses > 0
	return result, nil
}

func countTerminals(ptsDir string) (int, error) {
	entries, err := os.ReadDir(ptsDir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			count++
		}
	}
	return count, nil
}

// countExecProcesses counts live processes whose parent is outside the
// container's PID namespace, which is how processes started by pod exec
// appear. PID 1 and the agent itself are not activity. The agent is not
// counted either way: once start returns, it is reparented inside the
// container.
func countExecProcesses(procDir string, self int) (int, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == 1 || pid == self {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "stat"))
		if err != nil {
			continue // the process exited
		}
		// The command name is in parentheses and may contain spaces or
		// parentheses, so the fields start after the last ") ".
		stat := string(data)
		i := strings.LastIndex(stat, ") ")
		if i < 0 {
			continue
		}
		fields := strings.Fields(stat[i+2:])
		if len(fields) < 2 || fields[0] == "Z" {
			continue
		}
		if fields[1] == "0" {
			count++
		}
	}
	return count, nil
}
