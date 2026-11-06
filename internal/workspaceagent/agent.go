package workspaceagent

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ProtocolVersion changes only on incompatible API changes.
const ProtocolVersion = 1

const tombstoneTTL = 24 * time.Hour

// Options are the limits the build API resolves for each create.
type Options struct {
	TimeoutSeconds          int64 `json:"timeoutSeconds"`
	RequestedTimeoutSeconds int64 `json:"requestedTimeoutSeconds"`
	MaxLogBytes             int64 `json:"maxLogBytes"`
	RetentionSeconds        int64 `json:"retentionSeconds"`
	MaxRecords              int64 `json:"maxRecords"`
	CompletedLogBudgetBytes int64 `json:"completedLogBudgetBytes"`
	// Exclusive, when set, refuses the run while another run with the same
	// key is live, such as a second deploy sharing the first's tunnel port.
	Exclusive string `json:"exclusive,omitempty"`
}

func (o Options) valid() bool {
	return o.TimeoutSeconds > 0 && o.RequestedTimeoutSeconds >= 0 && o.MaxLogBytes > 0 &&
		o.RetentionSeconds > 0 && o.MaxRecords > 0 && o.CompletedLogBudgetBytes > 0
}

// Run is the public view of a run. Its JSON matches buildcontract.WorkspaceRun.
type Run struct {
	ID             string `json:"id"`
	Command        string `json:"command"`
	Status         string `json:"status"`
	ExitCode       *int   `json:"exitCode,omitempty"`
	StartedAt      string `json:"startedAt,omitempty"`
	FinishedAt     string `json:"finishedAt,omitempty"`
	LogBytes       int64  `json:"logBytes"`
	LogStartOffset int64  `json:"logStartOffset"`
	LogTruncated   bool   `json:"logTruncated"`
	LogsEvicted    bool   `json:"logsEvicted"`
	TimeoutSeconds int64  `json:"timeoutSeconds"`
	Message        string `json:"message,omitempty"`
}

// Error is an API failure with its HTTP status.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Message }

func apiError(code int, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Agent owns every run in one workspace container. mu guards all state,
// including the files under root.
type Agent struct {
	root    string
	workdir string
	log     *slog.Logger
	now     func() time.Time
	procDir string
	ptsDir  string
	// syncing counts sync plans, uploads and deletes in progress, which keep
	// the workspace active.
	syncing atomic.Int32
	// maxUpload bounds the body of a sync upload, and uploadIdle how long it
	// may go without sending anything.
	maxUpload  int64
	uploadIdle time.Duration
	// uploading lets one sync upload use the staging directory at a time.
	uploading sync.Mutex

	mu      sync.Mutex
	records map[string]*record
	broken  map[string]error
	live    map[string]*run
	// changed is closed and replaced on every change, waking log followers.
	changed chan struct{}
	// supervisors counts runs whose results are not yet recorded.
	supervisors sync.WaitGroup
}

type run struct {
	pid       int
	options   Options
	logs      *logWriter
	cancel    chan struct{}
	cancelled bool
	writeErr  error
}

// New loads the records under root. A record still marked live belonged to
// the previous container, whose commands died with it, so it is marked
// Interrupted. The caller must hold the agent lock for root.
func New(root, workdir string, log *slog.Logger) (*Agent, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	a := &Agent{
		root:       root,
		workdir:    workdir,
		log:        log,
		now:        time.Now,
		procDir:    "/proc",
		ptsDir:     "/dev/pts",
		maxUpload:  maxSyncUploadBytes,
		uploadIdle: syncUploadIdle,
		records:    map[string]*record{},
		broken:     map[string]error{},
		live:       map[string]*run{},
		changed:    make(chan struct{}),
	}
	// An agent that died mid-upload left its staging directory behind.
	if err := os.RemoveAll(filepath.Join(workdir, syncStaging)); err != nil {
		log.Warn("Could not remove an interrupted sync upload", "error", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !ValidID(entry.Name()) {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		rec, err := loadRecord(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue // left by a create that failed before saving; Create replaces it
		}
		if err != nil {
			a.broken[entry.Name()] = err
			continue
		}
		if live(rec.Status) {
			rec.finish(statusInterrupted, nil, interruptedMessage, a.now().UTC())
			if err := saveRecord(dir, rec); err != nil {
				log.Error("Failed to record interrupted run", "run", rec.ID, "error", err)
			}
		}
		a.records[rec.ID] = rec
	}
	return a, nil
}

func (a *Agent) notifyLocked() {
	close(a.changed)
	a.changed = make(chan struct{})
}

func (a *Agent) dir(id string) string { return filepath.Join(a.root, id) }

func (a *Agent) tombstone(id string) string { return filepath.Join(a.root, ".deleted", id) }

func (a *Agent) tombstoned(id string) bool {
	info, err := os.Stat(a.tombstone(id))
	return err == nil && info.ModTime().After(a.now().Add(-tombstoneTTL))
}

func (a *Agent) lookupLocked(id string) (*record, error) {
	if err, ok := a.broken[id]; ok {
		return nil, apiError(http.StatusUnprocessableEntity, "unreadable run record %s: %v", id, err)
	}
	if rec, ok := a.records[id]; ok {
		return rec, nil
	}
	if a.tombstoned(id) {
		return nil, apiError(http.StatusGone, "run was deleted or expired; use a new ID for a new command")
	}
	return nil, apiError(http.StatusNotFound, "run not found")
}

func (a *Agent) windowLocked(rec *record) (logWindow, error) {
	if rec.LogsEvicted {
		return logWindow{start: rec.EvictedLogBytes, end: rec.EvictedLogBytes}, nil
	}
	segments, err := listSegments(filepath.Join(a.dir(rec.ID), "logs"))
	if err != nil {
		return logWindow{}, err
	}
	var end int64
	if n := len(segments); n > 0 {
		end = segments[n-1].first + segments[n-1].size
	}
	return logWindow{start: max(0, end-rec.MaxLogBytes), end: end, segments: segments}, nil
}

func (a *Agent) publicLocked(rec *record) (Run, logWindow, error) {
	window, err := a.windowLocked(rec)
	if err != nil {
		return Run{}, window, err
	}
	run := Run{
		ID:             rec.ID,
		Command:        rec.Command,
		Status:         rec.Status,
		ExitCode:       rec.ExitCode,
		StartedAt:      rec.StartedAt.UTC().Format(time.RFC3339Nano),
		LogBytes:       window.end,
		LogStartOffset: window.start,
		LogTruncated:   window.start > 0,
		LogsEvicted:    rec.LogsEvicted,
		TimeoutSeconds: rec.TimeoutSeconds,
		Message:        rec.Message,
	}
	if rec.FinishedAt != nil {
		run.FinishedAt = rec.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	return run, window, nil
}

// Create starts command as run id. Creating an existing ID with the same
// command and requested timeout returns that run, so a client can retry
// after losing the response; created reports whether this call started it.
func (a *Agent) Create(id, command string, options Options) (Run, bool, error) {
	if !ValidID(id) {
		return Run{}, false, apiError(http.StatusBadRequest, "invalid run ID")
	}
	if command == "" || strings.ContainsRune(command, 0) {
		return Run{}, false, apiError(http.StatusBadRequest, "command must be non-empty and contain no NUL")
	}
	if !options.valid() {
		return Run{}, false, apiError(http.StatusBadRequest, "invalid run options")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err, ok := a.broken[id]; ok {
		return Run{}, false, apiError(http.StatusUnprocessableEntity, "unreadable run record %s: %v", id, err)
	}
	if rec, ok := a.records[id]; ok {
		if rec.Command != command || rec.RequestedTimeoutSeconds != options.RequestedTimeoutSeconds {
			return Run{}, false, apiError(http.StatusConflict, "run ID already belongs to a different command or timeout")
		}
		run, _, err := a.publicLocked(rec)
		return run, false, err
	}
	if a.tombstoned(id) {
		return Run{}, false, apiError(http.StatusGone, "run was deleted or expired; use a new ID for a new command")
	}
	// After the retry check, so a retried create still finds its own run.
	if options.Exclusive != "" {
		for liveID, r := range a.live {
			if r.options.Exclusive == options.Exclusive {
				return Run{}, false, apiError(http.StatusConflict, "%s %s is still running; wait for it or cancel it", options.Exclusive, liveID)
			}
		}
	}
	a.pruneLocked(options)

	dir := a.dir(id)
	if err := os.RemoveAll(dir); err != nil {
		return Run{}, false, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Run{}, false, err
	}
	logs, err := newLogWriter(filepath.Join(dir, "logs"), options.MaxLogBytes)
	if err != nil {
		_ = os.RemoveAll(dir)
		return Run{}, false, err
	}
	rec := &record{
		Version:                 recordVersion,
		ID:                      id,
		Command:                 command,
		Status:                  statusRunning,
		StartedAt:               a.now().UTC(),
		TimeoutSeconds:          options.TimeoutSeconds,
		RequestedTimeoutSeconds: options.RequestedTimeoutSeconds,
		MaxLogBytes:             options.MaxLogBytes,
	}
	// Save before starting: a retried create finds the record even if the
	// agent dies mid-start, so the command never runs twice.
	if err := saveRecord(dir, rec); err != nil {
		_ = os.RemoveAll(dir)
		return Run{}, false, err
	}
	a.records[id] = rec
	if err := a.startLocked(rec, logs, options); err != nil {
		code := 127
		rec.finish(statusFailed, &code, "starting command: "+err.Error(), a.now().UTC())
		if err := saveRecord(dir, rec); err != nil {
			a.log.Error("Failed to record run start failure", "run", id, "error", err)
		}
	}
	a.notifyLocked()
	run, _, err := a.publicLocked(rec)
	return run, true, err
}

func (a *Agent) startLocked(rec *record, logs *logWriter, options Options) error {
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer func() { _ = stdin.Close() }()
	output, input, err := os.Pipe()
	if err != nil {
		return err
	}
	pid, exited, err := startCommand(rec.Command, a.workdir, stdin, input)
	_ = input.Close()
	if err != nil {
		_ = output.Close()
		return err
	}
	r := &run{pid: pid, options: options, logs: logs, cancel: make(chan struct{})}
	a.live[rec.ID] = r
	a.supervisors.Add(1)
	go a.supervise(rec, r, output, exited)
	return nil
}

// Wait returns once every run has stopped and its result is recorded.
func (a *Agent) Wait() { a.supervisors.Wait() }

// supervise enforces the run's timeout and cancellation, then records the
// result once the command and everything left in its process group are gone.
func (a *Agent) supervise(rec *record, r *run, output *os.File, exited <-chan syscall.WaitStatus) {
	defer a.supervisors.Done()
	drained := make(chan struct{})
	go a.pump(r, output, drained)

	timeout := time.NewTimer(time.Duration(rec.TimeoutSeconds) * time.Second)
	defer timeout.Stop()
	cancel := (<-chan struct{})(r.cancel)
	var reason string
	var escalate <-chan time.Time
	var status syscall.WaitStatus
wait:
	for {
		select {
		case status = <-exited:
			break wait
		case <-timeout.C:
			if reason == "" {
				reason = statusTimedOut
				a.markTimedOut(rec)
				signalGroup(r.pid, syscall.SIGTERM)
				escalate = time.After(5 * time.Second)
			}
		case <-cancel:
			cancel = nil
			if reason == "" {
				reason = statusCancelled
				signalGroup(r.pid, syscall.SIGTERM)
				escalate = time.After(5 * time.Second)
			}
		case <-escalate:
			escalate = nil
			signalGroup(r.pid, syscall.SIGKILL)
		}
	}
	// Background descendants must stop writing before the result is recorded.
	signalGroup(r.pid, syscall.SIGKILL)
	select {
	case <-drained:
	case <-time.After(time.Second):
		// A descendant that left the group may still hold the pipe open; it
		// must not keep the run live forever.
		_ = output.Close()
		<-drained
	}
	_ = output.Close()

	a.mu.Lock()
	defer a.mu.Unlock()
	code := exitCode(status)
	final, message := statusSucceeded, ""
	switch {
	case r.writeErr != nil:
		final, code, message = statusFailed, 127, "writing output: "+r.writeErr.Error()
	case reason == statusTimedOut:
		final, code = statusTimedOut, 124
	// A cancel that arrived after the command exited changes nothing.
	case reason == statusCancelled:
		final = statusCancelled
	case code != 0:
		final = statusFailed
	}
	if err := r.logs.close(); err != nil {
		a.log.Error("Failed to trim run output", "run", rec.ID, "error", err)
	}
	rec.finish(final, &code, message, a.now().UTC())
	if err := saveRecord(a.dir(rec.ID), rec); err != nil {
		a.log.Error("Failed to record run result", "run", rec.ID, "error", err)
	}
	delete(a.live, rec.ID)
	a.notifyLocked()
	a.pruneLocked(r.options)
}

func (a *Agent) markTimedOut(rec *record) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec.Status = statusCancelling
	rec.Message = fmt.Sprintf("Run timed out after %d seconds", rec.TimeoutSeconds)
	if err := saveRecord(a.dir(rec.ID), rec); err != nil {
		a.log.Error("Failed to record run timeout", "run", rec.ID, "error", err)
	}
	a.notifyLocked()
}

// pump copies the command's output into its log and wakes followers.
func (a *Agent) pump(r *run, output *os.File, drained chan<- struct{}) {
	defer close(drained)
	buf := make([]byte, 64<<10)
	for {
		n, err := output.Read(buf)
		if n > 0 {
			a.mu.Lock()
			if r.writeErr == nil {
				if r.writeErr = r.logs.write(buf[:n]); r.writeErr != nil {
					// Output that cannot be stored must not keep running unrecorded.
					signalGroup(r.pid, syscall.SIGKILL)
				}
			}
			a.notifyLocked()
			a.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// Get returns run id.
func (a *Agent) Get(id string) (Run, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, err := a.lookupLocked(id)
	if err != nil {
		return Run{}, err
	}
	run, _, err := a.publicLocked(rec)
	return run, err
}

// List returns runs newest first.
func (a *Agent) List(offset, limit int) ([]Run, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	recs := make([]*record, 0, len(a.records))
	for _, rec := range a.records {
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool {
		if !recs[i].StartedAt.Equal(recs[j].StartedAt) {
			return recs[i].StartedAt.After(recs[j].StartedAt)
		}
		return recs[i].ID > recs[j].ID
	})
	runs := []Run{}
	// Clamp before adding: offset+limit can overflow.
	start := min(offset, len(recs))
	for _, rec := range recs[start : start+min(limit, len(recs)-start)] {
		run, _, err := a.publicLocked(rec)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, nil
}

// Cancel asks a live run to stop: SIGTERM to its process group, then SIGKILL
// five seconds later. Cancelling a finished run changes nothing.
func (a *Agent) Cancel(id string) (Run, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, err := a.lookupLocked(id)
	if err != nil {
		return Run{}, err
	}
	if r, ok := a.live[id]; ok && rec.Status == statusRunning {
		rec.Status = statusCancelling
		if err := saveRecord(a.dir(id), rec); err != nil {
			rec.Status = statusRunning
			return Run{}, err
		}
		if !r.cancelled {
			r.cancelled = true
			close(r.cancel)
		}
		a.notifyLocked()
	}
	run, _, err := a.publicLocked(rec)
	return run, err
}

// Delete removes a finished run. Its ID cannot be reused for a day, so a
// delayed retry of the original create cannot run the command again.
func (a *Agent) Delete(id string) error {
	if !ValidID(id) {
		return apiError(http.StatusBadRequest, "invalid run ID")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.broken[id]; ok {
		return a.eraseLocked(id)
	}
	rec, ok := a.records[id]
	if !ok {
		if a.tombstoned(id) {
			return nil
		}
		return apiError(http.StatusNotFound, "run not found")
	}
	if live(rec.Status) {
		return apiError(http.StatusConflict, "run is live; cancel it and wait until it finishes before deleting it")
	}
	return a.eraseLocked(id)
}

func (a *Agent) eraseLocked(id string) error {
	tombstone := a.tombstone(id)
	if err := os.MkdirAll(filepath.Dir(tombstone), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tombstone, nil, 0o600); err != nil {
		return err
	}
	now := a.now()
	if err := os.Chtimes(tombstone, now, now); err != nil {
		return err
	}
	if err := os.RemoveAll(a.dir(id)); err != nil {
		return err
	}
	delete(a.records, id)
	delete(a.broken, id)
	return nil
}

// pruneLocked removes finished runs past their retention or beyond the record
// limit, then drops the oldest retained logs until the rest fit the budget.
func (a *Agent) pruneLocked(options Options) {
	now := a.now()
	if entries, err := os.ReadDir(filepath.Join(a.root, ".deleted")); err == nil {
		for _, entry := range entries {
			if info, err := entry.Info(); err == nil && info.ModTime().Before(now.Add(-tombstoneTTL)) {
				_ = os.Remove(filepath.Join(a.root, ".deleted", entry.Name()))
			}
		}
	}
	var finished []*record
	for _, rec := range a.records {
		if !live(rec.Status) {
			finished = append(finished, rec)
		}
	}
	sort.Slice(finished, func(i, j int) bool {
		if !finished[i].FinishedAt.Equal(*finished[j].FinishedAt) {
			return finished[i].FinishedAt.Before(*finished[j].FinishedAt)
		}
		return finished[i].ID < finished[j].ID
	})
	cutoff := now.Add(-time.Duration(options.RetentionSeconds) * time.Second)
	excess := len(finished) - int(options.MaxRecords)
	type retained struct {
		rec  *record
		size int64
	}
	var kept []retained
	var total int64
	for i, rec := range finished {
		if rec.FinishedAt.Before(cutoff) || i < excess {
			if err := a.eraseLocked(rec.ID); err != nil {
				a.log.Error("Failed to remove expired run", "run", rec.ID, "error", err)
			}
			continue
		}
		window, err := a.windowLocked(rec)
		if err != nil {
			a.log.Error("Failed to size run output", "run", rec.ID, "error", err)
			continue
		}
		kept = append(kept, retained{rec, window.stored()})
		total += window.stored()
	}
	for _, k := range kept {
		if total <= options.CompletedLogBudgetBytes {
			break
		}
		if k.size == 0 {
			continue
		}
		if err := a.evictLocked(k.rec); err != nil {
			a.log.Error("Failed to evict run output", "run", k.rec.ID, "error", err)
			continue
		}
		total -= k.size
	}
}

// evictLocked removes a finished run's output and keeps its result. The end
// offset is saved first, so a crash mid-removal still leaves a truthful,
// empty window.
func (a *Agent) evictLocked(rec *record) error {
	window, err := a.windowLocked(rec)
	if err != nil {
		return err
	}
	rec.LogsEvicted, rec.EvictedLogBytes = true, window.end
	if err := saveRecord(a.dir(rec.ID), rec); err != nil {
		rec.LogsEvicted, rec.EvictedLogBytes = false, 0
		return err
	}
	return os.RemoveAll(filepath.Join(a.dir(rec.ID), "logs"))
}

// openLog checks offset against run id's output and moves it up to the
// first retained byte.
func (a *Agent) openLog(id string, offset int64) (int64, Run, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, err := a.lookupLocked(id)
	if err != nil {
		return 0, Run{}, err
	}
	run, _, err := a.publicLocked(rec)
	if err != nil {
		return 0, Run{}, err
	}
	if offset > run.LogBytes {
		return 0, Run{}, apiError(http.StatusRequestedRangeNotSatisfiable, "offset exceeds available log bytes")
	}
	return max(offset, run.LogStartOffset), run, nil
}

// readLog returns up to limit bytes of run id's output at offset, the run as
// of that read, and a channel closed at the next change.
func (a *Agent) readLog(id string, offset, limit int64) ([]byte, Run, <-chan struct{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, err := a.lookupLocked(id)
	if err != nil {
		return nil, Run{}, nil, err
	}
	run, window, err := a.publicLocked(rec)
	if err != nil {
		return nil, Run{}, nil, err
	}
	// Never skip bytes mid-response; the client reconnects from its offset.
	if offset < window.start {
		return nil, Run{}, nil, apiError(http.StatusConflict, "log tail advanced; reconnect to resume")
	}
	data, err := window.read(offset, limit)
	return data, run, a.changed, err
}
