//go:build linux

package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// startRunAgent runs a real workspace agent over root, as a workspace pod
// would, and counts the requests that reach it.
func startRunAgent(t *testing.T, root string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	agent, err := workspaceagent.New(filepath.Join(root, "runs"), root, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Stop runs before the temp dir goes, so none writes during cleanup.
		runs, _ := agent.List(0, 100)
		for _, run := range runs {
			_, _ = agent.Cancel(run.ID)
		}
		agent.Wait()
	})
	handler := agent.Handler("secret", nil)
	requests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func runTestServer(t *testing.T, agentURL, owner string, stopped bool) (*APIServer, *gin.Engine) {
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
		deps.loadOperatorConfig = loadOperatorConfig
		deps.workspaceAgent = func(_ context.Context, _ client.Client, target *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
			if target.Namespace != "default" || target.Name != "dev" {
				t.Errorf("wrong agent target: %s/%s", target.Namespace, target.Name)
			}
			return workspaceagent.NewClient(agentURL, "secret", nil), nil
		}
	})
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
	router.POST("/v1/workspaces/:name/deploy", a.wrapNamedHandler("deploy", a.deployWorkspace))
	return a, router
}

func newRunClient(t *testing.T, router *gin.Engine) *buildapiclient.Client {
	t.Helper()
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

// seedRun writes a finished run record and its output the way the agent
// stores them, before the agent starts.
func seedRun(t *testing.T, root, id string, maxLogBytes int, output []byte) {
	t.Helper()
	dir := filepath.Join(root, "runs", id)
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := fmt.Sprintf(`{"version":1,"id":%q,"command":"make","status":"Failed","exitCode":7,"maxLogBytes":%d,`+
		`"timeoutSeconds":7200,"requestedTimeoutSeconds":0,"startedAt":"2026-01-01T00:00:00Z","finishedAt":"2026-01-01T00:01:00Z"}`, id, maxLogBytes)
	for name, data := range map[string][]byte{"state.json": []byte(state), "logs/00000000000000000000.log": output} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkspaceRunFollowRelaysOutputAndStatusTrailers(t *testing.T) {
	agent, _ := startRunAgent(t, t.TempDir())
	a, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	run, err := api.CreateWorkspaceRun(ctx, "dev", buildcontract.WorkspaceRunRequest{ID: "follow", Command: "echo one; sleep 1; echo two; exit 3"})
	if err != nil || run.ID != "follow" || run.Status != "Running" {
		t.Fatalf("create: %+v, %v", run, err)
	}
	stream, err := api.WorkspaceRunLogs(ctx, "dev", "follow", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	_ = stream.Close()
	if err != nil || string(data) != "one\ntwo\n" {
		t.Fatalf("followed output: %q, %v", data, err)
	}
	if stream.Trailers.Get("X-Run-Status") != "Failed" || stream.Trailers.Get("X-Run-Exit-Code") != "3" {
		t.Errorf("trailers = %v, want Failed with exit code 3", stream.Trailers)
	}
	if limit := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute; stream.StreamDuration != limit {
		t.Errorf("stream duration = %v, want the API's whole stream limit", stream.StreamDuration)
	}
}

func TestWorkspaceRunListDeleteAndTruncatedHTTPLog(t *testing.T) {
	root := t.TempDir()
	seedRun(t, root, "tail", 10, []byte("discarded last error"))
	agent, _ := startRunAgent(t, root)
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
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

// JSON escapes '<' to six bytes, so the largest command must still fit both
// hops' body limits once encoded.
func TestWorkspaceRunAcceptsTheLargestEscapedCommand(t *testing.T) {
	agent, _ := startRunAgent(t, t.TempDir())
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	command := "true #" + strings.Repeat("<", buildcontract.MaxWorkspaceRunCommandBytes-len("true #"))
	if _, err := api.CreateWorkspaceRun(ctx, "dev", buildcontract.WorkspaceRunRequest{ID: "large", Command: command}); err != nil {
		t.Fatalf("create: %v", err)
	}
	for {
		run, err := api.GetWorkspaceRun(ctx, "dev", "large")
		if err != nil {
			t.Fatal(err)
		}
		if run.Terminal() {
			if run.Status != "Succeeded" {
				t.Fatalf("run = %+v, want Succeeded", run)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWorkspaceRunPolicyFlowsFromOperatorConfig(t *testing.T) {
	var got workspaceagent.CreateRequest
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"policy","status":"Running","timeoutSeconds":90}`))
	}))
	defer agent.Close()
	a, router := runTestServer(t, agent.URL, "alice", false)
	a.deps.loadOperatorConfig = func(_ context.Context, _ client.Client, namespace string) (*automotivev1alpha1.OperatorConfig, error) {
		if namespace != "default" {
			t.Errorf("wrong config namespace: %s", namespace)
		}
		return &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{Workspaces: &automotivev1alpha1.WorkspacesConfig{
			RunDefaultTimeoutMinutes: 10, RunMaxTimeoutMinutes: 20, RunMaxLogSizeMiB: 5, RunRetentionDays: 3, RunMaxRecords: 50, RunCompletedLogBudgetMiB: 200,
		}}}, nil
	}
	rec := httptest.NewRecorder()
	// Only timeout is user-controlled; unknown retention/log fields cannot
	// override the operator policy even if a hand-written client supplies them.
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"policy","command":"true","timeoutSeconds":90,"maxLogBytes":99999999,"retentionSeconds":99999999,"maxRecords":99999999}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("policy create: %d %s", rec.Code, rec.Body.String())
	}
	want := workspaceagent.Options{TimeoutSeconds: 90, RequestedTimeoutSeconds: 90, MaxLogBytes: 5 << 20,
		RetentionSeconds: 3 * 86400, MaxRecords: 50, CompletedLogBudgetBytes: 200 << 20}
	if got.ID != "policy" || got.Command != "true" || got.Options != want {
		t.Errorf("agent create = %+v, want options %+v", got, want)
	}
}

func TestWorkspaceRunSurvivesDisconnectAndAPIRecreation(t *testing.T) {
	root := t.TempDir()
	agent, _ := startRunAgent(t, root)
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
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

	// A new API instance has no in-memory knowledge of the run.
	_, router = runTestServer(t, agent.URL, "alice", false)
	api = newRunClient(t, router)
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
			agent, calls := startRunAgent(t, t.TempDir())
			_, router := runTestServer(t, agent.URL, tc.owner, tc.stopped)
			for _, request := range requests {
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(request.method, request.path, strings.NewReader(request.body)))
				if rec.Code != tc.status {
					t.Errorf("%s %s: %d %s", request.method, request.path, rec.Code, rec.Body.String())
				}
			}
			if calls.Load() != 0 {
				t.Fatal("unauthorized or stopped workspace reached its agent")
			}
		})
	}
	agent, calls := startRunAgent(t, t.TempDir())
	_, router := runTestServer(t, agent.URL, "alice", false)
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
		t.Fatal("invalid request reached the agent")
	}
}

func TestWorkspaceRunLaunchIgnoresRequestCancellation(t *testing.T) {
	agent, _ := startRunAgent(t, t.TempDir())
	a, router := runTestServer(t, agent.URL, "alice", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connect := a.deps.workspaceAgent
	a.deps.workspaceAgent = func(c context.Context, kube client.Client, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		cancel()
		return connect(c, kube, ws)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"detached","command":"true"}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("launch tied to HTTP context: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWorkspaceRunRequiresActivityReservation(t *testing.T) {
	agent, calls := startRunAgent(t, t.TempDir())
	a, router := runTestServer(t, agent.URL, "alice", false)
	getClient := a.deps.getClientFromRequest
	requests := 0
	a.deps.getClientFromRequest = func(c *gin.Context) (client.Client, error) {
		requests++
		// Workspace lookup, agent connection and run limits come first.
		if requests == 4 {
			return nil, errors.New("API unavailable while recording activity")
		}
		return getClient(c)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"run","command":"true"}`)))
	if rec.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("launched without recording activity: HTTP %d, agent requests %d", rec.Code, calls.Load())
	}
}

func TestWorkspaceRunLogSnapshotAndOffsets(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte{'a', 0, 255, '\n'}, 40000)
	seedRun(t, root, "large", 104857600, data)
	agent, _ := startRunAgent(t, root)
	_, router := runTestServer(t, agent.URL, "alice", false)
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

func TestWorkspaceRunAgentFailures(t *testing.T) {
	agent, _ := startRunAgent(t, t.TempDir())
	a, router := runTestServer(t, agent.URL, "alice", false)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"same","command":"true"}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	// The agent's own failures keep their status and message.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/runs", strings.NewReader(`{"id":"same","command":"false"}`)))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "different command") {
		t.Errorf("conflicting create: %d %s, want the agent's 409", rec.Code, rec.Body.String())
	}

	agent.Close()
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/same", nil))
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), strings.TrimPrefix(agent.URL, "http://")) {
		t.Errorf("unreachable agent: %d %s, want 502 without the agent's address", rec.Code, rec.Body.String())
	}

	a.deps.workspaceAgent = func(context.Context, client.Client, *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		return nil, errors.New("reading the workspace agent token: not found")
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/workspaces/dev/runs/same", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "token") {
		t.Errorf("missing agent token: %d %s, want 503 without cluster details", rec.Code, rec.Body.String())
	}
}
