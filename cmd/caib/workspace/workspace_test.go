package workspace

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"gopkg.in/yaml.v3"
)

func TestNewWorkspaceCmdDerivesServerURL(t *testing.T) {
	origServer := os.Getenv("CAIB_SERVER")
	defer func() {
		if origServer != "" {
			_ = os.Setenv("CAIB_SERVER", origServer)
		} else {
			_ = os.Unsetenv("CAIB_SERVER")
		}
	}()

	t.Run("PersistentPreRunE populates serverURL from CAIB_SERVER env", func(t *testing.T) {
		_ = os.Setenv("CAIB_SERVER", "https://env-server.example.com")
		serverURL = ""

		outputFmt := "table"
		cmd := NewWorkspaceCmd(&outputFmt)

		if cmd.PersistentPreRunE == nil {
			t.Fatal("workspace command must have PersistentPreRunE set for server URL derivation")
		}

		if err := cmd.PersistentPreRunE(cmd, nil); err != nil {
			t.Fatalf("PersistentPreRunE returned error: %v", err)
		}

		if serverURL != "https://env-server.example.com" {
			t.Errorf("expected serverURL to be derived from CAIB_SERVER, got %q", serverURL)
		}
	})

	t.Run("PersistentPreRunE preserves explicit --server flag value", func(t *testing.T) {
		_ = os.Unsetenv("CAIB_SERVER")

		outputFmt := "table"
		cmd := NewWorkspaceCmd(&outputFmt)

		// Simulate --server flag being set after flag parsing
		serverURL = "https://explicit.example.com"

		if err := cmd.PersistentPreRunE(cmd, nil); err != nil {
			t.Fatalf("PersistentPreRunE returned error: %v", err)
		}

		if serverURL != "https://explicit.example.com" {
			t.Errorf("expected explicit server URL to be preserved, got %q", serverURL)
		}
	})
}

func TestRenderFormattedWorkspaceList(t *testing.T) {
	workspaces := []buildapitypes.WorkspaceResponse{
		{Name: "ws-1", Arch: "amd64", Phase: "Running", Lease: "lease-abc", Age: "5m"},
		{Name: "ws-2", Arch: "arm64", Phase: "Stopped", Age: "1h"},
	}

	var gotErr error
	handleErr := func(err error) { gotErr = err }

	t.Run("json output contains all workspaces", func(t *testing.T) {
		gotErr = nil
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		caibcommon.RenderFormatted("json", workspaces, nil, handleErr)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if gotErr != nil {
			t.Fatalf("unexpected error: %v", gotErr)
		}

		var parsed []buildapitypes.WorkspaceResponse
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse JSON output: %v\noutput: %s", err, buf.String())
		}
		if len(parsed) != 2 {
			t.Errorf("expected 2 workspaces, got %d", len(parsed))
		}
		if parsed[0].Name != "ws-1" {
			t.Errorf("expected first workspace name 'ws-1', got %q", parsed[0].Name)
		}
	})

	t.Run("yaml output contains all workspaces", func(t *testing.T) {
		gotErr = nil
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		caibcommon.RenderFormatted("yaml", workspaces, nil, handleErr)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if gotErr != nil {
			t.Fatalf("unexpected error: %v", gotErr)
		}

		var parsed []map[string]any
		if err := yaml.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse YAML output: %v\noutput: %s", err, buf.String())
		}
		if len(parsed) != 2 {
			t.Errorf("expected 2 workspaces, got %d", len(parsed))
		}
	})

	t.Run("empty list renders as empty JSON array", func(t *testing.T) {
		gotErr = nil
		empty := []buildapitypes.WorkspaceResponse{}
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		caibcommon.RenderFormatted("json", empty, func() error {
			return nil
		}, handleErr)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if gotErr != nil {
			t.Fatalf("unexpected error: %v", gotErr)
		}

		trimmed := strings.TrimSpace(buf.String())
		if trimmed != "[]" {
			t.Errorf("expected empty JSON array '[]', got %q", trimmed)
		}
	})
}

func TestRenderFormattedWorkspaceShow(t *testing.T) {
	ws := &buildapitypes.WorkspaceResponse{
		Name:             "test-ws",
		Arch:             "amd64",
		Phase:            "Running",
		PodName:          "test-ws-pod",
		Lease:            "lease-123",
		Age:              "10m",
		AutoPauseTimeout: "30m",
		LastActivity:     "2m ago",
	}

	var gotErr error
	handleErr := func(err error) { gotErr = err }

	t.Run("json output contains all fields", func(t *testing.T) {
		gotErr = nil
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		caibcommon.RenderFormatted("json", ws, nil, handleErr)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if gotErr != nil {
			t.Fatalf("unexpected error: %v", gotErr)
		}

		var parsed map[string]any
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse JSON: %v\noutput: %s", err, buf.String())
		}
		if parsed["name"] != "test-ws" {
			t.Errorf("expected name 'test-ws', got %q", parsed["name"])
		}
		if parsed["architecture"] != "amd64" {
			t.Errorf("expected architecture 'amd64', got %q", parsed["architecture"])
		}
		if parsed["lease"] != "lease-123" {
			t.Errorf("expected lease 'lease-123', got %q", parsed["lease"])
		}
	})
}

func TestPrintWorkspaceList(t *testing.T) {
	workspaces := []buildapitypes.WorkspaceResponse{
		{Name: "ws-1", Arch: "amd64", Phase: "Running", Lease: "lease-abc", Age: "5m"},
		{Name: "ws-2", Arch: "arm64", Phase: "Stopped", Age: "1h"},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printWorkspaceList(workspaces)

	_ = w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "NAME") || !strings.Contains(output, "ARCH") {
		t.Error("expected table header with NAME and ARCH columns")
	}
	if !strings.Contains(output, "ws-1") {
		t.Error("expected ws-1 in output")
	}
	if !strings.Contains(output, "ws-2") {
		t.Error("expected ws-2 in output")
	}
	// ws-2 has no lease, should show "-"
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines (header + 2 rows), got %d", len(lines))
	}
	if !strings.Contains(lines[2], "-") {
		t.Error("expected '-' placeholder for empty lease in ws-2 row")
	}
}

func TestPrintWorkspaceDetails(t *testing.T) {
	ws := &buildapitypes.WorkspaceResponse{
		Name:             "test-ws",
		Arch:             "amd64",
		Phase:            "Running",
		PodName:          "test-ws-pod",
		AutoPauseTimeout: "30m",
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printWorkspaceDetails(ws)

	_ = w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Name:         test-ws") {
		t.Error("expected Name field in output")
	}
	if !strings.Contains(output, "Architecture: amd64") {
		t.Error("expected Architecture field in output")
	}
	if !strings.Contains(output, "Auto-pause:   30m") {
		t.Error("expected Auto-pause field in output")
	}
	// Lease and Age are empty, should not appear
	if strings.Contains(output, "Lease:") {
		t.Error("empty Lease should not appear in output")
	}
	if strings.Contains(output, "Age:") {
		t.Error("empty Age should not appear in output")
	}
}

func TestProgressReaderQuietMode(t *testing.T) {
	t.Run("render suppressed in quiet mode", func(t *testing.T) {
		clilog.SetQuiet(true)
		defer clilog.SetQuiet(false)

		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		pr := &progressReader{
			total: 100,
			read:  50,
			isTTY: false,
		}
		pr.render(50)

		_ = w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if buf.Len() > 0 {
			t.Errorf("expected no output in quiet mode, got: %s", buf.String())
		}
	})

	t.Run("render writes to stderr in non-quiet mode", func(t *testing.T) {
		clilog.SetQuiet(false)

		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		pr := &progressReader{
			total: 100,
			read:  25,
			isTTY: false,
		}
		pr.render(25)

		_ = w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if buf.Len() == 0 {
			t.Error("expected output at 25% boundary on non-TTY stderr")
		}
		if !strings.Contains(buf.String(), "Upload:") {
			t.Errorf("expected 'Upload:' in progress output, got: %s", buf.String())
		}
	})

	t.Run("non-TTY render skips non-boundary percentages", func(t *testing.T) {
		clilog.SetQuiet(false)

		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		pr := &progressReader{
			total: 100,
			read:  33,
			isTTY: false,
		}
		pr.render(33)

		_ = w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if buf.Len() > 0 {
			t.Errorf("expected no output at 33%% (only prints at 25%% intervals and 100%%), got: %s", buf.String())
		}
	})

	t.Run("finish suppressed in quiet mode", func(t *testing.T) {
		clilog.SetQuiet(true)
		defer clilog.SetQuiet(false)

		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		pr := &progressReader{
			total: 100,
			isTTY: true,
		}
		pr.finish()

		_ = w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)

		if buf.Len() > 0 {
			t.Errorf("expected no output from finish() in quiet mode, got: %s", buf.String())
		}
	})
}

// initTestGitRepo creates a temporary git repo with committed, untracked, and
// gitignored files, returning the repo directory path.
func initTestGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v failed: %v\n%s", args, err, out)
		}
	}

	run("git", "init")
	run("git", "checkout", "-b", "main")

	// committed file
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("tracked"), 0644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "tracked.txt")
	run("git", "commit", "-m", "initial")

	// untracked file (not git-added, not in .gitignore)
	if err := os.WriteFile(filepath.Join(dir, "untracked.rpm"), []byte("rpm-data"), 0644); err != nil {
		t.Fatal(err)
	}

	// gitignored file
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.log\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.log"), []byte("log"), 0644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", ".gitignore")
	run("git", "commit", "-m", "add gitignore")

	return dir
}

func TestGitListFiles(t *testing.T) {
	dir := initTestGitRepo(t)

	t.Run("default mode includes untracked non-ignored files", func(t *testing.T) {
		files, err := gitListFiles(dir, false)
		if err != nil {
			t.Fatalf("gitListFiles failed: %v", err)
		}
		sort.Strings(files)

		hasTracked := false
		hasUntracked := false
		hasIgnored := false
		for _, f := range files {
			switch f {
			case "tracked.txt":
				hasTracked = true
			case "untracked.rpm":
				hasUntracked = true
			case "ignored.log":
				hasIgnored = true
			}
		}

		if !hasTracked {
			t.Error("expected tracked.txt in file list")
		}
		if !hasUntracked {
			t.Error("expected untracked.rpm in file list (untracked but not ignored)")
		}
		if hasIgnored {
			t.Error("ignored.log should be excluded by .gitignore")
		}
	})

	t.Run("tracked-only mode excludes untracked files", func(t *testing.T) {
		files, err := gitListFiles(dir, true)
		if err != nil {
			t.Fatalf("gitListFiles failed: %v", err)
		}

		hasTracked := false
		hasUntracked := false
		for _, f := range files {
			switch f {
			case "tracked.txt":
				hasTracked = true
			case "untracked.rpm":
				hasUntracked = true
			}
		}

		if !hasTracked {
			t.Error("expected tracked.txt in file list")
		}
		if hasUntracked {
			t.Error("untracked.rpm should be excluded in tracked-only mode")
		}
	})
}

func TestComputeManifestWarnsOnSkippedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	manifest := computeManifest(dir, []string{"good.txt", "nonexistent.txt"})

	_ = w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if _, ok := manifest["good.txt"]; !ok {
		t.Error("expected good.txt in manifest")
	}
	if _, ok := manifest["nonexistent.txt"]; ok {
		t.Error("nonexistent.txt should not be in manifest")
	}
	if !strings.Contains(buf.String(), "Warning: skipping nonexistent.txt") {
		t.Errorf("expected warning for nonexistent file, got: %s", buf.String())
	}
}

func TestNewSyncCmdHasDeleteFlag(t *testing.T) {
	cmd := newSyncCmd()

	f := cmd.Flags().Lookup("delete")
	if f == nil {
		t.Fatal("expected --delete flag on sync command")
	}
	if f.DefValue != "false" {
		t.Errorf("expected --delete default to be false, got %q", f.DefValue)
	}

	gt := cmd.Flags().Lookup("git-tracked-only")
	if gt == nil {
		t.Fatal("expected --git-tracked-only flag on sync command")
	}
}

func TestSyncPlanRequestIncludeDeleted(t *testing.T) {
	manifest := map[string]string{"a.go": "abc123"}

	t.Run("IncludeDeleted false by default", func(t *testing.T) {
		req := buildapitypes.SyncPlanRequest{Files: manifest}
		if req.IncludeDeleted {
			t.Error("expected IncludeDeleted to be false by default")
		}
	})

	t.Run("IncludeDeleted true when set", func(t *testing.T) {
		req := buildapitypes.SyncPlanRequest{Files: manifest, IncludeDeleted: true}
		if !req.IncludeDeleted {
			t.Error("expected IncludeDeleted to be true")
		}
	})
}

func TestSyncPlanResponseDeletedField(t *testing.T) {
	t.Run("Deleted field present in response", func(t *testing.T) {
		resp := buildapitypes.SyncPlanResponse{
			Changed:   []string{"new.go"},
			Unchanged: 2,
			Deleted:   []string{"old.go", "removed.go"},
		}
		if len(resp.Deleted) != 2 {
			t.Errorf("expected 2 deleted files, got %d", len(resp.Deleted))
		}
		if resp.Deleted[0] != "old.go" {
			t.Errorf("expected first deleted file 'old.go', got %q", resp.Deleted[0])
		}
	})

	t.Run("Deleted field nil when omitted", func(t *testing.T) {
		resp := buildapitypes.SyncPlanResponse{
			Changed:   []string{"a.go"},
			Unchanged: 1,
		}
		if resp.Deleted != nil {
			t.Errorf("expected Deleted to be nil when not set, got %v", resp.Deleted)
		}
	})
}

func TestSyncDeleteRequestValidation(t *testing.T) {
	t.Run("valid relative paths", func(t *testing.T) {
		req := buildapitypes.SyncDeleteRequest{
			Files: []string{"src/main.go", "pkg/util.go"},
		}
		if len(req.Files) != 2 {
			t.Errorf("expected 2 files, got %d", len(req.Files))
		}
	})

	t.Run("JSON round-trip preserves fields", func(t *testing.T) {
		req := buildapitypes.SyncDeleteRequest{
			Files: []string{"a.go", "b/c.go"},
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		var decoded buildapitypes.SyncDeleteRequest
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if len(decoded.Files) != 2 {
			t.Errorf("expected 2 files after round-trip, got %d", len(decoded.Files))
		}
	})
}

func TestSyncPlanRequestJSONIncludeDeleted(t *testing.T) {
	t.Run("IncludeDeleted omitted when false", func(t *testing.T) {
		req := buildapitypes.SyncPlanRequest{
			Files: map[string]string{"a.go": "hash1"},
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if strings.Contains(string(data), "includeDeleted") {
			t.Error("expected includeDeleted to be omitted from JSON when false")
		}
	})

	t.Run("IncludeDeleted present when true", func(t *testing.T) {
		req := buildapitypes.SyncPlanRequest{
			Files:          map[string]string{"a.go": "hash1"},
			IncludeDeleted: true,
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if !strings.Contains(string(data), `"includeDeleted":true`) {
			t.Errorf("expected includeDeleted:true in JSON, got: %s", string(data))
		}
	})
}

func TestTarTrackedFilesWarnsOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exists.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	var buf bytes.Buffer
	err := tarTrackedFiles(dir, []string{"exists.txt", "gone.txt"}, &buf)

	_ = w.Close()
	os.Stderr = old

	if err != nil {
		t.Fatalf("tarTrackedFiles failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected tar archive to contain data")
	}

	var stderrBuf bytes.Buffer
	_, _ = stderrBuf.ReadFrom(r)
	if !strings.Contains(stderrBuf.String(), "Warning: skipping gone.txt") {
		t.Errorf("expected warning for missing file, got: %s", stderrBuf.String())
	}
}
