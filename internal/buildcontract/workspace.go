package buildcontract

import (
	"fmt"
	"io/fs"
	"os"
)

// WorkspaceRequest is the payload to create a workspace.
type WorkspaceRequest struct {
	Name                    string `json:"name"`
	FromBuild               string `json:"fromBuild,omitempty"` // ImageBuild name to extract lease from
	Lease                   string `json:"lease,omitempty"`     // Direct lease ID
	Arch                    string `json:"architecture,omitempty"`
	Image                   string `json:"toolchainImage,omitempty"`
	ClientConfig            string `json:"clientConfig,omitempty"`            // Base64-encoded Jumpstarter client config
	CPU                     string `json:"cpu,omitempty"`                     // CPU request (e.g., "1", "500m")
	Memory                  string `json:"memory,omitempty"`                  // Memory request (e.g., "2Gi", "512Mi")
	TmpfsBuildDir           bool   `json:"tmpfsBuildDir,omitempty"`           // Mount tmpfs at /tmp/build for fast compilation
	AutoPauseTimeoutMinutes *int32 `json:"autoPauseTimeoutMinutes,omitempty"` // nil = use global default, 0 = disable
}

// WorkspaceResponse is returned by workspace operations.
type WorkspaceResponse struct {
	Name             string `json:"name"`
	Phase            string `json:"phase"`
	Reason           string `json:"reason,omitempty"`
	Message          string `json:"message,omitempty"`
	Lease            string `json:"lease,omitempty"`
	Arch             string `json:"architecture"`
	PodName          string `json:"podName,omitempty"`
	Age              string `json:"age,omitempty"`
	AutoPauseTimeout string `json:"autoPauseTimeout,omitempty"` // e.g., "30m", "disabled"
	LastActivity     string `json:"lastActivity,omitempty"`     // e.g., "2m ago", "just now"
}

// MaxWorkspaceRunCommandBytes bounds the encoded shell command accepted by runs.
const MaxWorkspaceRunCommandBytes = 64 << 10

// WorkspaceRunRequest creates a durable command. Reusing ID with the same
// command and requested timeout is idempotent, including after an ambiguous
// network failure. Use a fresh ID for every new command; deleted IDs are retained
// for a 24-hour retry window, after which idempotency is no longer guaranteed.
type WorkspaceRunRequest struct {
	ID             string `json:"id,omitempty"`
	Command        string `json:"command"`
	TimeoutSeconds int64  `json:"timeoutSeconds,omitempty"`
}

// WorkspaceRun records a command and its result on the workspace volume.
// ExitCode is absent when the command is live or was interrupted without a result.
type WorkspaceRun struct {
	ID             string `json:"id"`
	Command        string `json:"command"`
	Status         string `json:"status"`
	ExitCode       *int   `json:"exitCode,omitempty"`
	StartedAt      string `json:"startedAt"`
	FinishedAt     string `json:"finishedAt,omitempty"`
	LogBytes       int64  `json:"logBytes"`       // Absolute end offset, including discarded output.
	LogStartOffset int64  `json:"logStartOffset"` // Absolute offset of the first retained byte.
	LogTruncated   bool   `json:"logTruncated"`
	LogsEvicted    bool   `json:"logsEvicted"` // The log budget removed output; the result is retained.
	TimeoutSeconds int64  `json:"timeoutSeconds"`
	Message        string `json:"message,omitempty"`
}

// Terminal reports whether the run has stopped producing output.
func (r WorkspaceRun) Terminal() bool {
	switch r.Status {
	case "Succeeded", "Failed", "Cancelled", "Interrupted", "TimedOut":
		return true
	default:
		return false
	}
}

// SyncPlanRequest is the manifest sent by the client to compute a sync diff.
type SyncPlanRequest struct {
	Files          map[string]string `json:"files"`                    // relative path -> SyncFileVersion
	IncludeDeleted bool              `json:"includeDeleted,omitempty"` // when true, report remote-only files in Deleted
}

// SyncFileVersion is what a sync plan compares of the file at path, without
// following a symlink: a symlink's target, or a regular file's size and
// modification time, as rsync's quick check compares them, so nothing is
// read. Anything else has no version. The CLI and the workspace find versions
// the same way, and an upload keeps a file's modification time, so a file
// synced and left alone has the same version on both sides.
func SyncFileVersion(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	switch mode := info.Mode(); {
	case mode.IsRegular():
		return fmt.Sprintf("file %d %d", info.Size(), info.ModTime().UnixNano()), nil
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		return "link " + target, nil
	default:
		return "", nil
	}
}

// SyncPlanResponse tells the client which files need uploading.
type SyncPlanResponse struct {
	Changed        []string `json:"changed"`                  // files to upload (new or modified)
	Unchanged      int      `json:"unchanged"`                // count of files already up to date
	Deleted        []string `json:"deleted,omitempty"`        // files on remote not in local manifest (only when IncludeDeleted)
	IncludeDeleted bool     `json:"includeDeleted,omitempty"` // echoed so clients can detect servers that ignore IncludeDeleted
}

// SyncUploadRequest starts the body of a sync upload, and the tar stream of
// files to upload follows it.
type SyncUploadRequest struct {
	Delete []string `json:"delete,omitempty"` // relative paths under /workspace/src/ to remove as the upload applies
}

// ArtifactMapping maps a source path inside the workspace to a destination on the board.
type ArtifactMapping struct {
	Src  string `json:"src"`  // Path inside workspace (file or directory)
	Dest string `json:"dest"` // Path on the board
}

// WorkspaceDeployRequest is the payload to deploy artifacts to a board. The
// deploy runs as a workspace run with ID, so retrying a lost response with the
// same ID returns that run instead of deploying again.
type WorkspaceDeployRequest struct {
	ID        string            `json:"id,omitempty"`
	Artifacts []ArtifactMapping `json:"artifacts"`
}

// WorkspaceShellSize sets the size of a workspace shell's terminal. On the
// shell's websocket the client sends it as a text message and keystrokes as
// binary messages; the shell's output arrives as binary messages, and its exit
// code as the text of a normal close.
type WorkspaceShellSize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// MaxWorkspaceShellMessageBytes bounds each message on a shell's websocket.
const MaxWorkspaceShellMessageBytes = 64 << 10
