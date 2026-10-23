package buildapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	kexec "k8s.io/client-go/util/exec"
)

func workspaceExecTestClient(t *testing.T, newExecutor func(*rest.Config, string, string, string, []string) (remotecommand.Executor, error)) *buildapiclient.Client {
	t.Helper()
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ws", Namespace: "test-ns"},
		Spec:       automotivev1alpha1.WorkspaceSpec{Owner: "test-user"},
		Status:     automotivev1alpha1.WorkspaceStatus{Phase: phaseRunning, PodName: "test-pod"},
	}
	fixture := setupUploadTest(t, ws)
	fixture.server.exec.newExecutor = newExecutor
	router := gin.New()
	router.POST("/v1/workspaces/:name/exec", func(c *gin.Context) {
		c.Set("requester", "test-user")
		fixture.server.execWorkspace(c, c.Param("name"))
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestWorkspaceExecExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{name: "success"},
		{name: "command failure", err: fmt.Errorf("wrapped: %w", kexec.CodeExitError{Err: errors.New("command failed"), Code: 42}), code: 42},
		{name: "signal", err: kexec.CodeExitError{Err: errors.New("killed"), Code: 137}, code: 137},
		{name: "executor failure", err: errors.New("connection lost"), code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := workspaceExecTestClient(t, func(_ *rest.Config, namespace, pod, container string, cmd []string) (remotecommand.Executor, error) {
				if namespace != "test-ns" || pod != "test-pod" || container != workspaceContainerName {
					t.Errorf("unexpected exec target: %s/%s/%s", namespace, pod, container)
				}
				if !reflect.DeepEqual(cmd, []string{"/bin/sh", "-c", "cd /workspace/src && false"}) {
					t.Errorf("command = %q", cmd)
				}
				return &fakeRemoteExecutor{streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
					_, _ = io.WriteString(opts.Stdout, "stdout without newline")
					_, _ = io.WriteString(opts.Stderr, "\nstderr\n")
					return tc.err
				}}, nil
			})
			output, err := readWorkspaceExec(t, api, buildcontract.WorkspaceExecRequest{Command: "false"})
			if !strings.Contains(output, "stdout without newline\nstderr\n") {
				t.Fatalf("missing output: %q", output)
			}
			assertWorkspaceExitCode(t, err, tc.code)
		})
	}
}

func TestWorkspaceExecScriptStrictMode(t *testing.T) {
	for _, script := range []string{
		"exit 37\necho must-not-run\n",
		"false\necho must-not-run\n",
		"false | true\necho must-not-run\n",
		"cat >/dev/null\nfalse\necho must-not-run\n",
		"echo \"${CAIB_TEST_UNSET_VARIABLE}\"\necho must-not-run\n",
		"printf 'script-ok\\n'\n",
	} {
		t.Run(strings.SplitN(script, "\n", 2)[0], func(t *testing.T) {
			workDir := t.TempDir()
			scriptDir := t.TempDir()
			api := workspaceExecTestClient(t, func(_ *rest.Config, _, _, _ string, cmd []string) (remotecommand.Executor, error) {
				// Map the pod's working directory into the test's temporary directory.
				cmd[2] = strings.ReplaceAll(cmd[2], "/workspace/src", shellQuote(workDir))
				return &fakeRemoteExecutor{streamWithContextFn: func(ctx context.Context, opts remotecommand.StreamOptions) error {
					command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
					command.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + scriptDir}
					command.Stdin, command.Stdout, command.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
					err := command.Run()
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						return kexec.CodeExitError{Err: err, Code: exitErr.ExitCode()}
					}
					return err
				}}, nil
			})
			output, err := readWorkspaceExec(t, api, buildcontract.WorkspaceExecRequest{Script: script})
			files, readErr := os.ReadDir(scriptDir)
			if readErr != nil || len(files) != 0 {
				t.Fatalf("script temporary files were not cleaned up: %v, %v", files, readErr)
			}
			if strings.Contains(output, "must-not-run") {
				t.Fatalf("script continued after failure: %s", output)
			}
			code := 1
			if strings.HasPrefix(script, "exit 37") {
				code = 37
			} else if strings.HasPrefix(script, "printf") {
				code = 0
				if !strings.Contains(output, "script-ok\n") {
					t.Fatalf("missing script output: %q", output)
				}
			}
			assertWorkspaceExitCode(t, err, code)
		})
	}
}

func readWorkspaceExec(t *testing.T, api *buildapiclient.Client, req buildcontract.WorkspaceExecRequest) (string, error) {
	t.Helper()
	body, err := api.ExecWorkspace(context.Background(), "test-ws", req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	output, err := io.ReadAll(body)
	return string(output), err
}

func assertWorkspaceExitCode(t *testing.T, err error, code int) {
	t.Helper()
	if code == 0 {
		if err != nil {
			t.Fatalf("unexpected exec error: %v", err)
		}
		return
	}
	var exitErr *buildapiclient.WorkspaceExecError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("exec error = %v; want exit status %d", err, code)
	}
}
