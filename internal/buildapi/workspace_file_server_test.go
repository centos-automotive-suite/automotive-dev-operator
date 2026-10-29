package buildapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// stubWorkspaceFileServerExec replaces the pod-exec entry point used to start
// the workspace file server with a recorder that returns execErr.
func stubWorkspaceFileServerExec(t *testing.T, execErr error) *[]execCall {
	t.Helper()
	orig := podExecForWorkspaceFileServer
	calls := &[]execCall{}
	podExecForWorkspaceFileServer = func(_ context.Context, _ *rest.Config, _, podName, _ string, cmd []string, _ io.Writer) error {
		*calls = append(*calls, execCall{podName: podName, cmd: cmd})
		return execErr
	}
	t.Cleanup(func() { podExecForWorkspaceFileServer = orig })
	return calls
}

func newWorkspaceBuildTestServer() *APIServer {
	return &APIServer{
		log: logr.Discard(),
		deps: apiDependencies{
			loadOperatorConfig: func(context.Context, client.Client, string) (*automotivev1alpha1.OperatorConfig, error) {
				return nil, nil
			},
		},
	}
}

// The file server started for workspace builds must serve /workspace/export
// only, never the whole workspace (SSH keys, Jumpstarter config, sources).
func TestResolveWorkspaceForBuild_ServesOnlyExportDir(t *testing.T) {
	ws, pod := runningWorkspace("dev-ws", "alice")
	calls := stubWorkspaceFileServerExec(t, nil)
	a := newWorkspaceBuildTestServer()
	req := &buildcontract.BuildRequest{}

	res, err := a.resolveWorkspaceForBuild(context.Background(), newFakeClient(ws, pod), &rest.Config{}, "default", "dev-ws", "alice", req)
	if err != nil {
		t.Fatalf("resolveWorkspaceForBuild: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("exec calls = %d, want 1", len(*calls))
	}
	call := (*calls)[0]
	if call.podName != pod.Name {
		t.Errorf("exec pod = %q, want %q", call.podName, pod.Name)
	}
	// -I keeps modules in the exec's working directory from shadowing the
	// standard library.
	if len(call.cmd) < 5 || !slices.Equal(call.cmd[:3], []string{"python3", "-I", "-c"}) {
		t.Fatalf("cmd = %q, want python3 -I -c <server> ...", call.cmd)
	}
	if got := call.cmd[len(call.cmd)-2:]; !slices.Equal(got, []string{"9090", "/workspace/export"}) {
		t.Errorf("cmd port/root = %q, want [9090 /workspace/export]", got)
	}
	if slices.Contains(call.cmd, "/workspace") {
		t.Errorf("cmd %q must not serve /workspace", call.cmd)
	}

	const wantURL = "http://10.0.0.1:9090"
	if res.FileURL != wantURL {
		t.Errorf("FileURL = %q, want %q", res.FileURL, wantURL)
	}
	if !slices.Contains(req.CustomDefs, "workspace_url="+wantURL) {
		t.Errorf("CustomDefs = %q, want workspace_url=%s", req.CustomDefs, wantURL)
	}
	if !res.Running {
		t.Error("Running = false, want true")
	}
}

// If the server cannot be started, no URL is advertised, so manifests that
// reference file:///workspace/export fail with a clear error instead of 404s.
func TestResolveWorkspaceForBuild_FileServerFailureOmitsURL(t *testing.T) {
	ws, pod := runningWorkspace("dev-ws", "alice")
	stubWorkspaceFileServerExec(t, errors.New("command terminated with exit code 1"))
	a := newWorkspaceBuildTestServer()
	req := &buildcontract.BuildRequest{}

	res, err := a.resolveWorkspaceForBuild(context.Background(), newFakeClient(ws, pod), &rest.Config{}, "default", "dev-ws", "alice", req)
	if err != nil {
		t.Fatalf("resolveWorkspaceForBuild: %v", err)
	}
	if res.FileURL != "" {
		t.Errorf("FileURL = %q, want empty", res.FileURL)
	}
	if len(req.CustomDefs) != 0 {
		t.Errorf("CustomDefs = %q, want none", req.CustomDefs)
	}
	if !res.Running {
		t.Error("Running = false, want true")
	}
}

func requireFileServerHost(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("/proc not available")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// runWorkspaceFileServerLauncher runs the launcher the way the build API does,
// against a temp root and port, from working directory dir.
func runWorkspaceFileServerLauncher(t *testing.T, dir string, port int, root string) ([]byte, error) {
	t.Helper()
	args := workspaceFileServerArgs(port, root)
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // fixed script, test-only args
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

func launchWorkspaceFileServer(t *testing.T, port int, root string) {
	t.Helper()
	if out, err := runWorkspaceFileServerLauncher(t, t.TempDir(), port, root); err != nil {
		t.Fatalf("launcher failed: %v\n%s", err, out)
	}
}

// fileServerPIDs returns the PIDs of launched file servers serving root.
func fileServerPIDs(t *testing.T, root string) []int {
	t.Helper()
	matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	var pids []int
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		args := bytes.Split(data, []byte{0})
		if slices.ContainsFunc(args, func(a []byte) bool { return string(a) == workspaceFileServerPython }) &&
			slices.ContainsFunc(args, func(a []byte) bool { return string(a) == root }) {
			pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(m)))
			pids = append(pids, pid)
		}
	}
	return pids
}

func killFileServersOnCleanup(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		for _, pid := range fileServerPIDs(t, root) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
}

func httpGet(t *testing.T, port int, path string) (int, string) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestWorkspaceFileServerPython_ConfinedToExportRoot runs the embedded server
// and checks that it creates the export root and refuses symlinks that
// resolve outside it.
func TestWorkspaceFileServerPython_ConfinedToExportRoot(t *testing.T) {
	requireFileServerHost(t)
	ws := t.TempDir()
	export := filepath.Join(ws, "export")
	port := freeTCPPort(t)
	killFileServersOnCleanup(t, export)

	launchWorkspaceFileServer(t, port, export)

	if fi, err := os.Stat(export); err != nil || !fi.IsDir() {
		t.Fatalf("export root not created: %v", err)
	}
	mustWrite := func(p, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustLink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(ws, "secret"), "top-secret")
	mustWrite(filepath.Join(export, "ok.txt"), "ok")
	mustLink("ok.txt", filepath.Join(export, "inner"))
	mustLink("../secret", filepath.Join(export, "escape"))
	mustLink("..", filepath.Join(export, "up"))
	mustWrite(filepath.Join(export, "site", "page.txt"), "page")
	mustLink("../../secret", filepath.Join(export, "site", "index.html"))

	for _, tc := range []struct {
		path     string
		wantCode int
		wantBody string
	}{
		{"/ok.txt", http.StatusOK, "ok"},
		{"/inner", http.StatusOK, "ok"},
		{"/site/page.txt", http.StatusOK, "page"},
		{"/escape", http.StatusNotFound, ""},
		{"/up/secret", http.StatusNotFound, ""},
		{"/site/", http.StatusNotFound, ""},
	} {
		code, body := httpGet(t, port, tc.path)
		if code != tc.wantCode {
			t.Errorf("GET %s = %d, want %d", tc.path, code, tc.wantCode)
		}
		if tc.wantBody != "" && body != tc.wantBody {
			t.Errorf("GET %s body = %q, want %q", tc.path, body, tc.wantBody)
		}
	}
}

// TestWorkspaceFileServerPython_RelaunchKeepsRunningServer checks that a
// second build's launch leaves the running server alone, so concurrent builds
// keep their downloads.
func TestWorkspaceFileServerPython_RelaunchKeepsRunningServer(t *testing.T) {
	requireFileServerHost(t)
	export := filepath.Join(t.TempDir(), "export")
	if err := os.MkdirAll(export, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(export, "ok.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	killFileServersOnCleanup(t, export)

	launchWorkspaceFileServer(t, port, export)
	before := fileServerPIDs(t, export)
	if len(before) != 1 {
		t.Fatalf("file server PIDs = %v, want exactly one", before)
	}
	launchWorkspaceFileServer(t, port, export)
	if after := fileServerPIDs(t, export); !slices.Equal(after, before) {
		t.Errorf("relaunch replaced the running server: PIDs %v -> %v", before, after)
	}
	if code, body := httpGet(t, port, "/ok.txt"); code != http.StatusOK || body != "ok" {
		t.Errorf("GET /ok.txt after relaunch = %d %q, want 200 \"ok\"", code, body)
	}
}

// TestWorkspaceFileServerPython_IgnoresModulesInWorkingDir checks that a
// module in the exec's working directory cannot replace the standard library.
func TestWorkspaceFileServerPython_IgnoresModulesInWorkingDir(t *testing.T) {
	requireFileServerHost(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "http.py"), []byte("raise SystemExit('shadowed')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(t.TempDir(), "export")
	port := freeTCPPort(t)
	killFileServersOnCleanup(t, export)

	if out, err := runWorkspaceFileServerLauncher(t, dir, port, export); err != nil {
		t.Fatalf("launcher failed with http.py in its working directory: %v\n%s", err, out)
	}
}
