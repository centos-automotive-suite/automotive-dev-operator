//go:build linux

package buildapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// fakeDeployTools puts jmp, ssh and rsync stand-ins first on PATH, which the
// agent passes to runs. jmp records its PID and arguments and stays up like a
// tunnel; rsync prints each argument in brackets and exits with rsyncExit.
func fakeDeployTools(t *testing.T, rsyncExit int) string {
	t.Helper()
	dir := t.TempDir()
	tools := map[string]string{
		"jmp":   "#!/bin/sh\necho $$ > " + filepath.Join(dir, "jmp.pid") + "\necho \"$*\" > " + filepath.Join(dir, "jmp.args") + "\nexec sleep 60\n",
		"ssh":   "#!/bin/sh\nexit 0\n",
		"rsync": "#!/bin/sh\nprintf '[%s]' \"$@\"; echo\nexit " + strconv.Itoa(rsyncExit) + "\n",
	}
	for name, script := range tools {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func deployTestClient(t *testing.T, leaseID string) (*buildapiclient.Client, func() int32) {
	t.Helper()
	agent, requests := startRunAgent(t, t.TempDir())
	a, router := runTestServer(t, agent.URL, "alice", false)
	if leaseID != "" {
		kube, err := a.deps.getClientFromRequest(nil)
		if err != nil {
			t.Fatal(err)
		}
		var ws automotivev1alpha1.Workspace
		if err := kube.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "dev"}, &ws); err != nil {
			t.Fatal(err)
		}
		ws.Spec.LeaseID = leaseID
		if err := kube.Update(context.Background(), &ws); err != nil {
			t.Fatal(err)
		}
	}
	return newRunClient(t, router), requests.Load
}

func followDeploy(t *testing.T, api *buildapiclient.Client, id string) (string, *buildapiclient.WorkspaceRunLogStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := api.WorkspaceRunLogs(ctx, "dev", id, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data), stream
}

// gone reports whether pid has exited, counting a zombie as exited.
func gone(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

func TestWorkspaceDeployRunsTheTunnelAndRsyncInARun(t *testing.T) {
	tools := fakeDeployTools(t, 0)
	api, _ := deployTestClient(t, "lease-1")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	run, err := api.DeployWorkspace(ctx, "dev", buildcontract.WorkspaceDeployRequest{ID: "deploy-1", Artifacts: []buildcontract.ArtifactMapping{
		{Src: "/workspace/src/my app", Dest: "/usr/local/bin/$(x)"},
	}})
	if err != nil || run.ID != "deploy-1" {
		t.Fatalf("deploy: %+v, %v", run, err)
	}
	output, stream := followDeploy(t, api, "deploy-1")
	if stream.Trailers.Get("X-Run-Status") != "Succeeded" {
		t.Fatalf("deploy run: %v\n%s", stream.Trailers, output)
	}
	for _, want := range []string{"[/workspace/src/my app][root@127.0.0.1:/usr/local/bin/$(x)]", "Deploy complete: 1 artifact(s)"} {
		if !strings.Contains(output, want) {
			t.Errorf("output lacks %q:\n%s", want, output)
		}
	}
	// Each rsync is traced as it runs, but not the wait for SSH or the cleanup.
	var traced []string
	for line := range strings.Lines(output) {
		if strings.HasPrefix(line, "+") {
			traced = append(traced, line)
		}
	}
	if len(traced) != 1 || !strings.Contains(traced[0], "rsync -avz") || !strings.Contains(traced[0], "/workspace/src/my app") {
		t.Errorf("traced commands = %q, want only the rsync\n%s", traced, output)
	}
	if args, err := os.ReadFile(filepath.Join(tools, "jmp.args")); err != nil || !strings.Contains(string(args), "--lease lease-1") {
		t.Errorf("tunnel args: %q, %v", args, err)
	}
	pidText, err := os.ReadFile(filepath.Join(tools, "jmp.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(pidText)))
	deadline := time.Now().Add(5 * time.Second)
	for !gone(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the tunnel outlived its deploy run")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestWorkspaceDeployFailsWithTheRsyncExitCode(t *testing.T) {
	fakeDeployTools(t, 23)
	api, _ := deployTestClient(t, "lease-1")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := api.DeployWorkspace(ctx, "dev", buildcontract.WorkspaceDeployRequest{ID: "deploy-1", Artifacts: []buildcontract.ArtifactMapping{
		{Src: "/workspace/src/a", Dest: "/a"}, {Src: "/workspace/src/b", Dest: "/b"},
	}}); err != nil {
		t.Fatal(err)
	}
	output, stream := followDeploy(t, api, "deploy-1")
	if stream.Trailers.Get("X-Run-Status") != "Failed" || stream.Trailers.Get("X-Run-Exit-Code") != "23" {
		t.Errorf("trailers = %v, want Failed with exit code 23", stream.Trailers)
	}
	if strings.Contains(output, "/workspace/src/b") || strings.Contains(output, "Deploy complete") {
		t.Errorf("deploy went on after a failed rsync:\n%s", output)
	}
}

func TestWorkspaceDeployWithoutALeaseStartsNothing(t *testing.T) {
	api, agentRequests := deployTestClient(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := api.DeployWorkspace(ctx, "dev", buildcontract.WorkspaceDeployRequest{ID: "deploy-1", Artifacts: []buildcontract.ArtifactMapping{{Src: "/a", Dest: "/a"}}})
	var response buildapiclient.HTTPError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusBadRequest {
		t.Fatalf("deploy without a lease: %v", err)
	}
	if n := agentRequests(); n != 0 {
		t.Errorf("the agent got %d requests", n)
	}
}

func TestWorkspaceDeployRejectsAnInvalidRunID(t *testing.T) {
	api, agentRequests := deployTestClient(t, "lease-1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := api.DeployWorkspace(ctx, "dev", buildcontract.WorkspaceDeployRequest{ID: "../x", Artifacts: []buildcontract.ArtifactMapping{{Src: "/a", Dest: "/a"}}})
	var response buildapiclient.HTTPError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusBadRequest {
		t.Fatalf("deploy with an invalid ID: %v", err)
	}
	if n := agentRequests(); n != 0 {
		t.Errorf("the agent got %d requests", n)
	}
}

// A workspace deploys one run at a time: overlapping deploys would share the
// tunnel's port and SSH connection.
func TestWorkspaceDeployRefusesASecondDeployWhileOneRuns(t *testing.T) {
	tools := fakeDeployTools(t, 0)
	// ssh never connects, so the first deploy waits for the tunnel.
	if err := os.WriteFile(filepath.Join(tools, "ssh"), []byte("#!/bin/sh\nexit 255\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	api, _ := deployTestClient(t, "lease-1")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	artifacts := []buildcontract.ArtifactMapping{{Src: "/a", Dest: "/a"}}

	if _, err := api.DeployWorkspace(ctx, "dev", buildcontract.WorkspaceDeployRequest{ID: "deploy-1", Artifacts: artifacts}); err != nil {
		t.Fatal(err)
	}
	_, err := api.DeployWorkspace(ctx, "dev", buildcontract.WorkspaceDeployRequest{ID: "deploy-2", Artifacts: artifacts})
	var response buildapiclient.HTTPError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusConflict || !strings.Contains(err.Error(), "deploy-1") {
		t.Fatalf("second deploy: %v, want a 409 naming deploy-1", err)
	}
	// Other runs still start.
	if _, err := api.CreateWorkspaceRun(ctx, "dev", buildcontract.WorkspaceRunRequest{ID: "exec-1", Command: "true"}); err != nil {
		t.Fatalf("exec during a deploy: %v", err)
	}
	if _, err := api.CancelWorkspaceRun(ctx, "dev", "deploy-1"); err != nil {
		t.Fatal(err)
	}
}
