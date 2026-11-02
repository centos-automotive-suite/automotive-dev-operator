// Package workspaceagent runs commands inside a workspace container for the
// build API, and keeps their records and output on the workspace volume.
package workspaceagent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// recordVersion is the state.json format. The agent reads only its own
// version; records from other formats are reported as unreadable.
const recordVersion = 1

const (
	statusRunning     = "Running"
	statusCancelling  = "Cancelling"
	statusSucceeded   = "Succeeded"
	statusFailed      = "Failed"
	statusCancelled   = "Cancelled"
	statusInterrupted = "Interrupted"
	statusTimedOut    = "TimedOut"
)

const interruptedMessage = "The workspace container stopped before the run finished"

var validID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ValidID reports whether id can name a run. It excludes path traversal.
func ValidID(id string) bool { return validID.MatchString(id) }

func live(status string) bool { return status == statusRunning || status == statusCancelling }

// record is a run's state.json. The agent is its only writer, so writes are
// atomic replacements without file locks.
type record struct {
	Version                 int        `json:"version"`
	ID                      string     `json:"id"`
	Command                 string     `json:"command"`
	Status                  string     `json:"status"`
	ExitCode                *int       `json:"exitCode,omitempty"`
	StartedAt               time.Time  `json:"startedAt"`
	FinishedAt              *time.Time `json:"finishedAt,omitempty"`
	Message                 string     `json:"message,omitempty"`
	TimeoutSeconds          int64      `json:"timeoutSeconds"`
	RequestedTimeoutSeconds int64      `json:"requestedTimeoutSeconds"`
	MaxLogBytes             int64      `json:"maxLogBytes"`
	// LogsEvicted means the log budget removed the output. EvictedLogBytes
	// keeps its end offset so offsets stay absolute.
	LogsEvicted     bool  `json:"logsEvicted,omitempty"`
	EvictedLogBytes int64 `json:"evictedLogBytes,omitempty"`
}

func (r *record) finish(status string, code *int, message string, at time.Time) {
	r.Status = status
	r.ExitCode = code
	if message != "" {
		r.Message = message
	}
	r.FinishedAt = &at
}

func loadRecord(dir string) (*record, error) {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, err
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	switch {
	case rec.Version != recordVersion:
		return nil, fmt.Errorf("record format %d is not supported", rec.Version)
	case rec.ID != filepath.Base(dir):
		return nil, fmt.Errorf("record ID %q does not match its directory", rec.ID)
	case rec.MaxLogBytes <= 0 || rec.TimeoutSeconds <= 0:
		return nil, fmt.Errorf("record limits are invalid")
	case !live(rec.Status) && rec.FinishedAt == nil:
		return nil, fmt.Errorf("finished record has no finishedAt")
	}
	switch rec.Status {
	case statusRunning, statusCancelling, statusSucceeded, statusFailed, statusCancelled, statusInterrupted, statusTimedOut:
	default:
		return nil, fmt.Errorf("unknown status %q", rec.Status)
	}
	return &rec, nil
}

// saveRecord replaces state.json and syncs the file and its directory before
// returning, so an acknowledged change survives a crash.
func saveRecord(dir string, rec *record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return writeFileDurably(filepath.Join(dir, "state.json"), data)
}

// writeFileDurably replaces name with data so that a crash leaves either the
// old or the new contents, and the new contents survive once it returns.
func writeFileDurably(name string, data []byte) error {
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	return syncDir(filepath.Dir(name))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
