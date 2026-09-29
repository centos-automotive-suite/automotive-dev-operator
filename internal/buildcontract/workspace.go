package buildcontract

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

// WorkspaceExecRequest is the payload to execute a command in a workspace.
type WorkspaceExecRequest struct {
	Command string `json:"command"`
}

// SyncPlanRequest is the manifest sent by the client to compute a sync diff.
type SyncPlanRequest struct {
	Files          map[string]string `json:"files"`                    // relative path -> hex-encoded sha256
	IncludeDeleted bool              `json:"includeDeleted,omitempty"` // when true, report remote-only files in Deleted
}

// SyncPlanResponse tells the client which files need uploading.
type SyncPlanResponse struct {
	Changed        []string `json:"changed"`                  // files to upload (new or modified)
	Unchanged      int      `json:"unchanged"`                // count of files already up to date
	Deleted        []string `json:"deleted,omitempty"`        // files on remote not in local manifest (only when IncludeDeleted)
	IncludeDeleted bool     `json:"includeDeleted,omitempty"` // echoed so clients can detect servers that ignore IncludeDeleted
}

// SyncDeleteRequest is the payload to delete files from a workspace.
type SyncDeleteRequest struct {
	Files []string `json:"files"` // relative paths under /workspace/src/ to remove
}

// ArtifactMapping maps a source path inside the workspace to a destination on the board.
type ArtifactMapping struct {
	Src  string `json:"src"`  // Path inside workspace (file or directory)
	Dest string `json:"dest"` // Path on the board
}

// WorkspaceDeployRequest is the payload to deploy artifacts to a board.
type WorkspaceDeployRequest struct {
	Artifacts []ArtifactMapping `json:"artifacts"`
	Password  string            `json:"password,omitempty"` // SSH password for key injection (default: "password")
}
