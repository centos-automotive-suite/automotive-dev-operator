//go:build linux

package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	kexec "k8s.io/client-go/util/exec"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func runTestServer(t *testing.T, root, owner string, stopped bool) (*APIServer, *gin.Engine, *atomic.Int32) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("NAMESPACE", "default")
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: "dev", Namespace: "default"},
		Spec:       automotivev1alpha1.WorkspaceSpec{Owner: owner, Stopped: stopped},
		Status:     automotivev1alpha1.WorkspaceStatus{Phase: phaseRunning, PodName: "workspace-dev"},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ws).WithStatusSubresource(ws).Build()
	a := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return kube, nil }
		deps.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) { return &rest.Config{}, nil }
		deps.loadOperatorConfig = loadOperatorConfig
	})
	calls := &atomic.Int32{}
	a.exec.newExecutor = func(_ *rest.Config, namespace, pod, container string, argv []string) (remotecommand.Executor, error) {
		calls.Add(1)
		if namespace != "default" || pod != "workspace-dev" || container != workspaceContainerName {
			t.Errorf("wrong exec target: %s/%s/%s", namespace, pod, container)
		}
		if !slices.Equal(argv, []string{"python3", "-I", "-"}) {
			t.Errorf("runner payload leaked into exec argv: %d arguments", len(argv))
		}
		return &fakeRemoteExecutor{streamWithContextFn: func(ctx context.Context, opts remotecommand.StreamOptions) error {
			if opts.Stdin == nil {
				return fmt.Errorf("runner stdin is missing")
			}
			input, err := io.ReadAll(opts.Stdin)
			if err != nil {
				return err
			}
			program := strings.Replace(string(input), `"/workspace/.runs"`, strconv.Quote(filepath.Join(root, ".runs")), 1)
			program = strings.Replace(program, `"/workspace/src"`, strconv.Quote(root), 1)
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			cmd.Stdin = strings.NewReader(program)
			cmd.Stdout, cmd.Stderr = opts.Stdout, opts.Stderr
			return cmd.Run()
		}}, nil
	}
	// Authentication itself is covered through registerWorkspaceRoutes in the
	// Workspace API suite. Keep a fixed identity here to exercise owner checks.
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("requester", "alice"); c.Next() })
	router.POST("/v1/workspaces/:name/runs", a.wrapNamedHandler("create run", a.createWorkspaceRun))
	router.GET("/v1/workspaces/:name/runs", a.wrapNamedHandler("list runs", a.listWorkspaceRuns))
	router.DELETE("/v1/workspaces/:name/runs/:run", a.wrapNamedHandler("delete run", a.deleteWorkspaceRun))
	router.GET("/v1/workspaces/:name/runs/:run", a.wrapNamedHandler("get run", a.getWorkspaceRun))
	router.GET("/v1/workspaces/:name/runs/:run/logs", a.wrapNamedHandler("run logs", a.workspaceRunLogs))
	router.POST("/v1/workspaces/:name/runs/:run/cancel", a.wrapNamedHandler("cancel run", a.cancelWorkspaceRun))
	return a, router, calls
}

// runnerInputArgs inspects the transmitted request while preserving its stdin
// for the actual helper invocation. Request arguments must never be in exec argv.
func runnerInputArgs(t *testing.T, opts *remotecommand.StreamOptions) []string {
	t.Helper()
	if opts.Stdin == nil {
		t.Fatal("runner stdin is missing")
	}
	input, err := io.ReadAll(opts.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	opts.Stdin = bytes.NewReader(input)
	_, request, ok := strings.Cut(string(input), "sys.argv = ")
	if !ok {
		t.Fatal("runner request missing from stdin")
	}
	line, _, _ := strings.Cut(request, "\n")
	var args []string
	if err := json.Unmarshal([]byte(line), &args); err != nil {
		t.Fatal(err)
	}
	return args
}

func TestWorkspaceRunExecFailuresPreserveTheirActualCause(t *testing.T) {
	for _, tc := range []struct {
		name, stdout, stderr string
		exit, status         int
		python               bool
	}{
		{name: "missing interpreter", stderr: `exec: "python3": executable file not found in $PATH`, exit: 127, status: 422, python: true},
		{name: "interpreter not executable", stderr: "python3: permission denied", exit: 126, status: 422, python: true},
		{name: "traceback", stderr: "Traceback (most recent call last):\n" + strings.Repeat("frame\n", 300) + "PermissionError: volume is read-only", exit: 1, status: 502},
		{name: "helper killed", stderr: "Killed", exit: 137, status: 502},
		{name: "exec permission error", stderr: "permission denied by exec transport", exit: -1, status: 502},
		{name: "runner exception", stdout: `{"code":500,"error":"OSError: no space left on device"}`, status: 500},
		{name: "corrupt record", stdout: `{"code":422,"error":"unreadable run record: finishedAt"}`, status: 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, router, _ := runTestServer(t, t.TempDir(), "alice", false)
			a.exec.newExecutor = func(*rest.Config, string, string, string, []string) (remotecommand.Executor, error) {
				return &fakeRemoteExecutor{streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
					_, _ = io.WriteString(opts.Stdout, tc.stdout)
					_, _ = io.WriteString(opts.Stderr, tc.stderr)
					if tc.exit == -1 {
						return errors.New(tc.stderr)
					}
					if tc.exit != 0 {
						return kexec.CodeExitError{Err: fmt.Errorf("command terminated with exit code %d", tc.exit), Code: tc.exit}
					}
					return nil
				}}, nil
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"run","command":"true"}`)))
			var response struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			want := tc.stderr
			if len(want) > 1024 {
				want = want[strings.LastIndex(want, "\n")+1:]
			}
			if tc.stdout != "" {
				var protocol struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal([]byte(tc.stdout), &protocol); err != nil {
					t.Fatal(err)
				}
				want = protocol.Error
			}
			if rec.Code != tc.status || strings.Contains(response.Error, "Python 3.12") != tc.python || !strings.Contains(response.Error, want) {
				t.Fatalf("exec failure: %d %s; want %d with %q", rec.Code, response.Error, tc.status, want)
			}
		})
	}
}

func TestWorkspaceRunNewerFormatsRejectLogsBeforeStreaming(t *testing.T) {
	for _, tc := range []struct {
		name, record, status string
	}{
		{"terminal", `{"version":2,"id":"future","status":"Failed","startedAt":"2026-01-01T00:00:00Z","finishedAt":"2026-01-01T00:01:00Z","command":{"private":"payload"}}`, "Failed"},
		{"ambiguous", `{"version":2,"id":"future","status":"FutureStatus"}`, "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, ".runs", "future")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			_, router, calls := runTestServer(t, root, "alice", false)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/future", nil))
			var run buildcontract.WorkspaceRun
			if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil || rec.Code != http.StatusOK || run.Status != tc.status || run.ExitCode != nil || !strings.Contains(run.Message, "newer record format") {
				t.Fatalf("newer run inspection: %d %s, %v", rec.Code, rec.Body.String(), err)
			}
			for _, query := range []string{"", "?follow&offset=100"} {
				before := calls.Load()
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/future/logs"+query, nil))
				if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "compatible operator") || rec.Header().Get("X-Log-Offset") != "" || calls.Load()-before != 1 {
					t.Fatalf("unsupported logs reached offset validation or streaming: %d %s headers=%v calls=%d", rec.Code, rec.Body.String(), rec.Header(), calls.Load()-before)
				}
			}
		})
	}
}

func TestWorkspaceRunFollowUsesPersistentExecAndStatusTrailers(t *testing.T) {
	a, router, calls := runTestServer(t, t.TempDir(), "alice", false)
	newExecutor := a.exec.newExecutor
	a.exec.newExecutor = func(cfg *rest.Config, ns, pod, container string, argv []string) (remotecommand.Executor, error) {
		executor, err := newExecutor(cfg, ns, pod, container, argv)
		if err != nil {
			return nil, err
		}
		return &fakeRemoteExecutor{streamWithContextFn: func(ctx context.Context, opts remotecommand.StreamOptions) error {
			args := runnerInputArgs(t, &opts)
			if args[3] == "stream" && args[len(args)-1] != "40" {
				t.Errorf("follower can outlive the CLI reconnect cycle: %s seconds", args[len(args)-1])
			}
			return executor.StreamWithContext(ctx, opts)
		}}, nil
	}
	server := httptest.NewServer(router)
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = api.CreateWorkspaceRun(ctx, "dev", buildcontract.WorkspaceRunRequest{ID: "stream", Command: "printf first; sleep 1.2; printf second; sleep 1.2; printf last; exit 7"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := api.WorkspaceRunLogs(ctx, "dev", "stream", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || string(data) != "firstsecondlast" || calls.Load() != 3 || stream.Offset != 0 || stream.StreamDuration != 40*time.Second || stream.Trailers.Get("X-Run-Status") != "Failed" || stream.Trailers.Get("X-Run-Exit-Code") != "7" {
		t.Fatalf("stream: %q err=%v execs=%d offset=%d trailers=%v", data, err, calls.Load(), stream.Offset, stream.Trailers)
	}
}

func TestWorkspaceRunClientReceivesTracebackCause(t *testing.T) {
	a, router, _ := runTestServer(t, t.TempDir(), "alice", false)
	const cause = "PermissionError: workspace volume is read-only"
	a.exec.newExecutor = func(*rest.Config, string, string, string, []string) (remotecommand.Executor, error) {
		return &fakeRemoteExecutor{streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
			_, _ = io.WriteString(opts.Stderr, "Traceback (most recent call last):\n"+strings.Repeat("  stack frame\n", 300)+cause)
			return kexec.CodeExitError{Err: errors.New("command exited"), Code: 1}
		}}, nil
	}
	server := httptest.NewServer(router)
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.CreateWorkspaceRun(context.Background(), "dev", buildcontract.WorkspaceRunRequest{ID: "run", Command: "true"})
	var response buildapiclient.HTTPError
	if !errors.As(err, &response) || response.HTTPStatusCode() != 502 || !strings.Contains(err.Error(), cause) {
		t.Fatalf("client lost actual cause: %v", err)
	}
}

func TestWorkspaceRunListDeleteAndTruncatedHTTPLog(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, ".runs", "tail")
	if err := os.MkdirAll(filepath.Join(directory, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string]string{
		"state.json":                    `{"id":"tail","command":"make","status":"Failed","exitCode":7,"maxLogBytes":10,"timeoutSeconds":7200,"requestedTimeoutSeconds":0,"startedAt":"2026-01-01T00:00:00+00:00","finishedAt":"2026-01-01T00:01:00+00:00"}`,
		"logs/00000000000000000000.log": "discarded last error",
	} {
		if err := os.WriteFile(filepath.Join(directory, file), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, router, _ := runTestServer(t, root, "alice", false)
	server := httptest.NewServer(router)
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runs, err := api.ListWorkspaceRuns(ctx, "dev", 0, 10)
	if err != nil || len(runs) != 1 || runs[0].ID != "tail" || runs[0].LogStartOffset != 10 || !runs[0].LogTruncated {
		t.Fatalf("list: %+v %v", runs, err)
	}
	stream, err := api.WorkspaceRunLogs(ctx, "dev", "tail", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || stream.Offset != 10 || string(data) != "last error" {
		t.Fatalf("tail: %q offset=%d err=%v", data, stream.Offset, err)
	}
	checkWorkspaceLogRotation(t, a, api, ctx, directory)
	for range 2 {
		if err := api.DeleteWorkspaceRun(ctx, "dev", "tail"); err != nil {
			t.Fatal(err)
		}
	}
	if runs, err = api.ListWorkspaceRuns(ctx, "dev", 0, 10); err != nil || len(runs) != 0 {
		t.Fatalf("deleted run still listed: %+v %v", runs, err)
	}
	_, err = api.CreateWorkspaceRun(ctx, "dev", buildcontract.WorkspaceRunRequest{ID: "tail", Command: "true"})
	var response buildapiclient.HTTPError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusGone {
		t.Fatalf("deleted ID can run again: %v", err)
	}
}

func TestWorkspaceRunPolicyFlowsFromOperatorConfig(t *testing.T) {
	a, router, _ := runTestServer(t, t.TempDir(), "alice", false)
	a.deps.loadOperatorConfig = func(_ context.Context, _ client.Client, namespace string) (*automotivev1alpha1.OperatorConfig, error) {
		if namespace != "default" {
			t.Errorf("wrong config namespace: %s", namespace)
		}
		return &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{Workspaces: &automotivev1alpha1.WorkspacesConfig{
			RunDefaultTimeoutMinutes: 10, RunMaxTimeoutMinutes: 20, RunMaxLogSizeMiB: 5, RunRetentionDays: 3, RunMaxRecords: 50, RunCompletedLogBudgetMiB: 200,
		}}}, nil
	}
	a.exec.newExecutor = func(_ *rest.Config, _, _, _ string, argv []string) (remotecommand.Executor, error) {
		return &fakeRemoteExecutor{streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
			args := runnerInputArgs(t, &opts)
			var options map[string]int64
			if err := json.Unmarshal([]byte(args[len(args)-1]), &options); err != nil {
				return err
			}
			for key, want := range map[string]int64{"timeoutSeconds": 90, "requestedTimeoutSeconds": 90, "maxLogBytes": 5 << 20, "retentionSeconds": 3 * 86400, "maxRecords": 50, "completedLogBudgetBytes": 200 << 20} {
				if options[key] != want {
					t.Errorf("%s: got %d, want %d", key, options[key], want)
				}
			}
			_, err := fmt.Fprint(opts.Stdout, `{"run":{"id":"policy","status":"Running","timeoutSeconds":90}}`)
			return err
		}}, nil
	}
	rec := httptest.NewRecorder()
	// Only timeout is user-controlled; unknown retention/log fields cannot
	// override the operator policy even if a hand-written client supplies them.
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"policy","command":"true","timeoutSeconds":90,"maxLogBytes":99999999,"retentionSeconds":99999999,"maxRecords":99999999}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("policy create: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWorkspaceRunHTTPDisconnectAndAPIRecreation(t *testing.T) {
	root := t.TempDir()
	_, router, _ := runTestServer(t, root, "alice", false)
	server := httptest.NewServer(router)
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run, err := api.CreateWorkspaceRun(ctx, "dev", buildcontract.WorkspaceRunRequest{
		ID: "reconnect", Command: `printf first; while [ ! -f release ]; do sleep 0.05; done; printf '\000last'; exit 17`,
	})
	if err != nil || run.ID != "reconnect" {
		t.Fatalf("create: %+v, %v", run, err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = api.CancelWorkspaceRun(cleanupCtx, "dev", "reconnect")
	}()
	streamCtx, disconnect := context.WithCancel(ctx)
	stream, err := api.WorkspaceRunLogs(streamCtx, "dev", run.ID, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 5)
	if _, err := io.ReadFull(stream, first); err != nil || string(first) != "first" {
		t.Fatalf("first output: %q, %v", first, err)
	}
	disconnect()
	_ = stream.Close()
	server.Close()
	// A new API instance has no in-memory knowledge of the run.
	_, router, _ = runTestServer(t, root, "alice", false)
	server2 := httptest.NewServer(router)
	t.Cleanup(server2.Close)
	api, err = buildapiclient.New(server2.URL)
	if err != nil {
		t.Fatal(err)
	}
	run, err = api.GetWorkspaceRun(ctx, "dev", run.ID)
	if err != nil || run.Status != "Running" {
		t.Fatalf("run lost after disconnect: %+v, %v", run, err)
	}
	if err := os.WriteFile(filepath.Join(root, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err = api.WorkspaceRunLogs(ctx, "dev", run.ID, true, 5)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || !bytes.Equal(remaining, []byte{0, 'l', 'a', 's', 't'}) {
		t.Fatalf("reattach output: %q, %v", remaining, err)
	}
	run, err = api.GetWorkspaceRun(ctx, "dev", run.ID)
	if err != nil || run.ExitCode == nil || *run.ExitCode != 17 || run.Status != "Failed" {
		t.Fatalf("retained result: %+v, %v", run, err)
	}
}

func TestWorkspaceRunAuthorizationAndValidation(t *testing.T) {
	requests := []struct{ method, path, body string }{
		{http.MethodPost, "/v1/workspaces/dev/runs", `{"id":"run","command":"echo hello"}`},
		{http.MethodGet, "/v1/workspaces/dev/runs", ""},
		{http.MethodDelete, "/v1/workspaces/dev/runs/run", ""},
		{http.MethodGet, "/v1/workspaces/dev/runs/run", ""},
		{http.MethodGet, "/v1/workspaces/dev/runs/run/logs?follow&offset=0", ""},
		{http.MethodPost, "/v1/workspaces/dev/runs/run/cancel", ""},
	}
	for _, tc := range []struct {
		name, owner string
		stopped     bool
		status      int
	}{{"other owner", "bob", false, 404}, {"stopped", "alice", true, 409}} {
		t.Run(tc.name, func(t *testing.T) {
			_, router, calls := runTestServer(t, t.TempDir(), tc.owner, tc.stopped)
			for _, request := range requests {
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(request.method, request.path, strings.NewReader(request.body)))
				if rec.Code != tc.status {
					t.Errorf("%s %s: %d %s", request.method, request.path, rec.Code, rec.Body.String())
				}
			}
			if calls.Load() != 0 {
				t.Fatal("unauthorized or stopped workspace reached pod exec")
			}
		})
	}
	_, router, calls := runTestServer(t, t.TempDir(), "alice", false)
	for _, request := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/workspaces/dev/runs", `{"command":" "}`},
		{http.MethodPost, "/v1/workspaces/dev/runs", `{"id":"../escape","command":"true"}`},
		{http.MethodGet, "/v1/workspaces/dev/runs/run/logs?offset=-1", ""},
		{http.MethodGet, "/v1/workspaces/dev/runs/run/logs?offset=no", ""},
		{http.MethodGet, "/v1/workspaces/dev/runs/run/logs?follow=nope", ""},
		{http.MethodGet, "/v1/workspaces/dev/runs?limit=101", ""},
		{http.MethodGet, "/v1/workspaces/dev/runs?offset=-1", ""},
		{http.MethodPost, "/v1/workspaces/dev/runs", `{"command":"true","timeoutSeconds":86401}`},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(request.method, request.path, strings.NewReader(request.body)))
		if rec.Code != 400 {
			t.Errorf("invalid request: %d %s", rec.Code, rec.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached pod exec")
	}
}

func TestWorkspaceRunLaunchIgnoresRequestCancellation(t *testing.T) {
	a, router, _ := runTestServer(t, t.TempDir(), "alice", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newExecutor := a.exec.newExecutor
	a.exec.newExecutor = func(cfg *rest.Config, ns, pod, container string, argv []string) (remotecommand.Executor, error) {
		cancel()
		return newExecutor(cfg, ns, pod, container, argv)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"detached","command":"true"}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("launch tied to HTTP context: %d %s", rec.Code, rec.Body.String())
	}
	var run buildcontract.WorkspaceRun
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil || run.ID != "detached" {
		t.Fatalf("launch result: %+v %v", run, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !run.Terminal() {
		if time.Now().After(deadline) {
			t.Fatal("detached run did not finish")
		}
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/detached", nil))
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWorkspaceRunRequiresActivityReservation(t *testing.T) {
	a, router, calls := runTestServer(t, t.TempDir(), "alice", false)
	getClient := a.deps.getClientFromRequest
	requests := 0
	a.deps.getClientFromRequest = func(c *gin.Context) (client.Client, error) {
		requests++
		if requests == 3 {
			return nil, errors.New("API unavailable while recording activity")
		}
		return getClient(c)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"run","command":"true"}`)))
	if rec.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("launched without recording activity: HTTP %d, exec calls %d", rec.Code, calls.Load())
	}
}

func TestWorkspaceRunLogSnapshotAndOffsets(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, ".runs", "large")
	if err := os.MkdirAll(filepath.Join(directory, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{'a', 0, 255, '\n'}, 40000)
	for name, content := range map[string][]byte{
		"state.json":                    []byte(`{"id":"large","command":"make","status":"Succeeded","exitCode":0,"maxLogBytes":104857600,"timeoutSeconds":7200,"requestedTimeoutSeconds":0,"startedAt":"2026-01-01T00:00:00+00:00","finishedAt":"2026-01-01T00:01:00+00:00"}`),
		"logs/00000000000000000000.log": data,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, router, _ := runTestServer(t, root, "alice", false)
	for _, suffix := range []string{"?offset=3", "?follow&offset=3"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/large/logs"+suffix, nil))
		if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), data[3:]) || rec.Header().Get("X-Log-Offset") != "3" {
			t.Fatalf("log bytes or offset corrupted: %d, %d bytes", rec.Code, rec.Body.Len())
		}
	}
	for path, status := range map[string]int{
		"large/logs?offset=160001": 416,
		"missing/logs":             404,
		"missing":                  404,
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/"+path, nil))
		if rec.Code != status {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func checkWorkspaceLogRotation(t *testing.T, a *APIServer, api *buildapiclient.Client, ctx context.Context, directory string) {
	t.Helper()
	// Force retention to advance between the API's preflight and the streaming
	// exec. The first response must stop rather than silently skipping bytes.
	newExecutor := a.exec.newExecutor
	rotated := false
	a.exec.newExecutor = func(cfg *rest.Config, ns, pod, container string, argv []string) (remotecommand.Executor, error) {
		executor, err := newExecutor(cfg, ns, pod, container, argv)
		if err != nil {
			return nil, err
		}
		return &fakeRemoteExecutor{streamWithContextFn: func(ctx context.Context, opts remotecommand.StreamOptions) error {
			args := runnerInputArgs(t, &opts)
			if args[3] == "stream" && !rotated {
				rotated = true
				if err := os.WriteFile(filepath.Join(directory, "logs", "00000000000000000000.log"), []byte("discarded last errorFINAL TAIL"), 0o600); err != nil {
					return err
				}
			}
			return executor.StreamWithContext(ctx, opts)
		}}, nil
	}
	stream, err := api.WorkspaceRunLogs(ctx, "dev", "tail", true, 10)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || len(data) != 0 || stream.Offset != 10 || !strings.Contains(stream.Trailers.Get("X-Log-Error"), "tail advanced") {
		t.Fatalf("rotation gap was hidden: %q offset=%d trailers=%v err=%v", data, stream.Offset, stream.Trailers, err)
	}
	stream, err = api.WorkspaceRunLogs(ctx, "dev", "tail", true, 10)
	if err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || stream.Offset != 20 || string(data) != "FINAL TAIL" {
		t.Fatalf("rotation resume: %q offset=%d err=%v", data, stream.Offset, err)
	}
}
