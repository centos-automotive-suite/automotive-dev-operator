package buildapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestAppendWorkspaceRepoCustomDefs(t *testing.T) {
	req := &buildcontract.BuildRequest{CustomDefs: []string{"existing=value"}}
	reposJSON := []byte(`[{"id":"workspace-kernel-build","baseurl":"http://10.0.0.1:8080"}]`)

	appendWorkspaceRepoCustomDefs(req, reposJSON)

	want := []string{
		"existing=value",
		`extra_repos=[{"id":"workspace-kernel-build","baseurl":"http://10.0.0.1:8080"}]`,
		`extra_build_repos=[{"id":"workspace-kernel-build","baseurl":"http://10.0.0.1:8080"}]`,
	}
	if !reflect.DeepEqual(req.CustomDefs, want) {
		t.Fatalf("CustomDefs = %#v, want %#v", req.CustomDefs, want)
	}
}

func runningWorkspace(name, owner string) (*automotivev1alpha1.Workspace, *corev1.Pod) {
	podName := name + "-pod"
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       automotivev1alpha1.WorkspaceSpec{Owner: owner},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseRunning,
			PodName: podName,
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: "default"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
	}
	return ws, pod
}

// stubWorkspaceGrants points the API at a fake agent per workspace that mints
// numbered grants, and records which workspace each grant came from, so tests
// can count grants without a cluster.
func stubWorkspaceGrants(t *testing.T) (*APIServer, *[]string) {
	t.Helper()
	// Pin the namespace so fixtures and the lookup target the same namespace
	// regardless of BUILD_API_NAMESPACE or an in-pod service-account file.
	t.Setenv("BUILD_API_NAMESPACE", "default")
	var mu sync.Mutex
	var grants []string
	a := &APIServer{log: logr.Discard()}
	a.deps.loadOperatorConfig = func(context.Context, client.Client, string) (*automotivev1alpha1.OperatorConfig, error) {
		return nil, nil
	}
	a.deps.workspaceAgent = func(_ context.Context, _ client.Client, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/file-grants" || r.Header.Get("Authorization") != "Bearer secret" {
				http.Error(w, `{"error":"unexpected request"}`, http.StatusBadRequest)
				return
			}
			mu.Lock()
			grants = append(grants, ws.Name)
			n := len(grants)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"token":"tok%d","expiresAt":"2030-01-01T00:00:00Z"}`, n)
		}))
		t.Cleanup(server.Close)
		return workspaceagent.NewClient(server.URL, "secret", nil), nil
	}
	return a, &grants
}

// A build submitted by one user must not reach into another user's workspace
// via --extra-repo. The request is rejected and no grant is minted.
func TestResolveExtraRepos_RejectsUnownedWorkspace(t *testing.T) {
	ws, pod := runningWorkspace("alice-ws", "alice")
	k8sClient := newFakeClient(ws, pod)
	a, grants := stubWorkspaceGrants(t)
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"alice-ws:/workspace/export/rpms"}}

	err := a.resolveExtraRepos(context.Background(), k8sClient, "bob", req)
	if err == nil {
		t.Fatal("expected ownership error, got nil")
	}
	if len(*grants) != 0 {
		t.Fatalf("expected no grants on rejection, got %v", *grants)
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("expected no CustomDefs mutation on rejection, got %#v", req.CustomDefs)
	}
}

// The response must not reveal whether a workspace exists: an unowned workspace
// and a missing one must produce byte-identical errors.
func TestResolveExtraRepos_UnownedIndistinguishableFromMissing(t *testing.T) {
	a, _ := stubWorkspaceGrants(t)
	const name = "shadow-ws"
	newReq := func() *buildcontract.BuildRequest {
		return &buildcontract.BuildRequest{ExtraRepos: []string{name + ":/workspace/export/rpms"}}
	}

	// Case 1: workspace does not exist.
	errMissing := a.resolveExtraRepos(context.Background(), newFakeClient(), "bob", newReq())
	if errMissing == nil {
		t.Fatal("expected error for missing workspace, got nil")
	}

	// Case 2: workspace exists but is owned by someone else.
	ws, pod := runningWorkspace(name, "alice")
	errUnowned := a.resolveExtraRepos(context.Background(), newFakeClient(ws, pod), "bob", newReq())
	if errUnowned == nil {
		t.Fatal("expected error for unowned workspace, got nil")
	}

	if errMissing.Error() != errUnowned.Error() {
		t.Fatalf("missing vs unowned errors differ and leak existence:\n missing:  %q\n unowned:  %q",
			errMissing.Error(), errUnowned.Error())
	}
}

// A non-NotFound lookup failure (API-server/RBAC) must return the sentinel
// error so applyExtraRepos maps it to a 500
func TestResolveExtraRepos_LookupFailureIsSentinel(t *testing.T) {
	a, _ := stubWorkspaceGrants(t)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	const rawErr = "connection refused to apiserver 10.0.0.5:6443"
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			return errors.New(rawErr)
		},
	}).Build()
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"any-ws:/workspace/export/rpms"}}

	err := a.resolveExtraRepos(context.Background(), k8sClient, "bob", req)
	if err == nil {
		t.Fatal("expected lookup error, got nil")
	}
	if !errors.Is(err, errWorkspaceLookup) {
		t.Fatalf("expected errWorkspaceLookup sentinel, got %v", err)
	}
	if strings.Contains(err.Error(), rawErr) {
		t.Fatalf("error leaks raw cluster detail to client: %q", err.Error())
	}
}

// Validation is all-or-nothing: if a later entry is unauthorized, no grant is
// minted for earlier authorized entries.
func TestResolveExtraRepos_AllOrNothing(t *testing.T) {
	bobWS, bobPod := runningWorkspace("bob-ws", "bob")
	aliceWS, alicePod := runningWorkspace("alice-ws", "alice")
	k8sClient := newFakeClient(bobWS, bobPod, aliceWS, alicePod)
	a, grants := stubWorkspaceGrants(t)
	req := &buildcontract.BuildRequest{
		ExtraRepos: []string{"bob-ws:/workspace/export/rpms", "alice-ws:/workspace/export/rpms"},
	}

	err := a.resolveExtraRepos(context.Background(), k8sClient, "bob", req)
	if err == nil {
		t.Fatal("expected ownership error on second entry, got nil")
	}
	if len(*grants) != 0 {
		t.Fatalf("expected no grants (pass 1 must reject before pass 2), got %v", *grants)
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("expected no CustomDefs mutation on rejection, got %#v", req.CustomDefs)
	}
}

// The owner's own running workspace is accepted: the build gets one grant on
// its agent, and the repo URL carries it.
func TestResolveExtraRepos_AllowsOwnedRunningWorkspace(t *testing.T) {
	ws, pod := runningWorkspace("bob-ws", "bob")
	a, grants := stubWorkspaceGrants(t)
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"bob-ws:/workspace/export/rpms"}}

	if err := a.resolveExtraRepos(context.Background(), newFakeClient(ws, pod), "bob", req); err != nil {
		t.Fatalf("expected owned workspace to be accepted, got %v", err)
	}
	if !reflect.DeepEqual(*grants, []string{"bob-ws"}) {
		t.Fatalf("grants = %v, want one from bob-ws", *grants)
	}
	want := `extra_repos=[{"id":"workspace-bob-ws","baseurl":"http://10.0.0.1:9091/f/tok1/rpms"}]`
	if !slices.Contains(req.CustomDefs, want) {
		t.Fatalf("CustomDefs missing %q, got %#v", want, req.CustomDefs)
	}
}

// The agent serves only /workspace/export, so other paths are rejected before
// any grant is minted.
func TestResolveExtraRepos_RejectsPathOutsideExport(t *testing.T) {
	ws, pod := runningWorkspace("bob-ws", "bob")
	a, grants := stubWorkspaceGrants(t)
	for _, p := range []string{"/workspace/rpms", "/workspace/export/../.ssh", "/workspace/exported", "rpms", "/tmp/rpms"} {
		req := &buildcontract.BuildRequest{ExtraRepos: []string{"bob-ws:" + p}}
		err := a.resolveExtraRepos(context.Background(), newFakeClient(ws, pod), "bob", req)
		if err == nil || !strings.Contains(err.Error(), "under /workspace/export") {
			t.Errorf("%s: err = %v, want an error asking to move the repo under /workspace/export", p, err)
		}
		if len(req.CustomDefs) != 0 {
			t.Errorf("%s: CustomDefs = %#v, want none", p, req.CustomDefs)
		}
	}
	if len(*grants) != 0 {
		t.Fatalf("expected no grants on rejection, got %v", *grants)
	}
}

// Repos in one workspace share one grant, and each repo gets its own path and
// a distinct repo ID.
func TestResolveExtraRepos_SharesGrantPerWorkspace(t *testing.T) {
	ws, pod := runningWorkspace("bob-ws", "bob")
	a, grants := stubWorkspaceGrants(t)
	req := &buildcontract.BuildRequest{ExtraRepos: []string{
		"bob-ws:/workspace/export/kernel",
		"bob-ws:/workspace/export/my tools/",
		"bob-ws:/workspace/export",
	}}

	if err := a.resolveExtraRepos(context.Background(), newFakeClient(ws, pod), "bob", req); err != nil {
		t.Fatalf("resolveExtraRepos: %v", err)
	}
	if len(*grants) != 1 {
		t.Fatalf("grants = %v, want 1 per workspace", *grants)
	}
	want := `extra_repos=[` +
		`{"id":"workspace-bob-ws","baseurl":"http://10.0.0.1:9091/f/tok1/kernel"},` +
		`{"id":"workspace-bob-ws-2","baseurl":"http://10.0.0.1:9091/f/tok1/my%20tools"},` +
		`{"id":"workspace-bob-ws-3","baseurl":"http://10.0.0.1:9091/f/tok1/"}]`
	if len(req.CustomDefs) == 0 || req.CustomDefs[0] != want {
		t.Fatalf("CustomDefs = %#v, want first entry %s", req.CustomDefs, want)
	}
}

// If the agent cannot grant access, the build is rejected with its reason
// instead of pointing DNF at a URL that won't open.
func TestResolveExtraRepos_GrantFailureRejectsBuild(t *testing.T) {
	ws, pod := runningWorkspace("bob-ws", "bob")
	a, _ := stubWorkspaceGrants(t)
	a.deps.workspaceAgent = func(context.Context, client.Client, *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		return nil, errors.New("reading the workspace agent token: secret not found")
	}
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"bob-ws:/workspace/export/rpms"}}

	err := a.resolveExtraRepos(context.Background(), newFakeClient(ws, pod), "bob", req)
	if err == nil || !strings.Contains(err.Error(), "secret not found") {
		t.Fatalf("err = %v, want the agent's reason", err)
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("CustomDefs = %#v, want none", req.CustomDefs)
	}
}

// A build in a running workspace gets workspace_url with its own grant.
func TestResolveWorkspaceForBuild_GrantsExportToBuild(t *testing.T) {
	ws, pod := runningWorkspace("bob-ws", "bob")
	a, grants := stubWorkspaceGrants(t)
	req := &buildcontract.BuildRequest{}

	res, err := a.resolveWorkspaceForBuild(context.Background(), newFakeClient(ws, pod), "default", "bob-ws", "bob", req)
	if err != nil {
		t.Fatal(err)
	}
	const wantURL = "http://10.0.0.1:9091/f/tok1"
	if !res.Running || res.FileURL != wantURL || !slices.Contains(req.CustomDefs, "workspace_url="+wantURL) {
		t.Fatalf("resolution = %+v, CustomDefs = %#v; want workspace_url %s", res, req.CustomDefs, wantURL)
	}
	if len(*grants) != 1 {
		t.Fatalf("grants = %v, want one per build", *grants)
	}
}

// Build pods must be able to parse the grant URL on IPv6 clusters too.
func TestGrantWorkspaceFilesBracketsIPv6PodIP(t *testing.T) {
	ws, _ := runningWorkspace("bob-ws", "bob")
	a, _ := stubWorkspaceGrants(t)
	for _, tc := range []struct{ podIP, want string }{
		{"10.0.0.1", "http://10.0.0.1:9091/f/tok1"},
		{"fd00::5", "http://[fd00::5]:9091/f/tok2"},
	} {
		url, err := a.grantWorkspaceFiles(context.Background(), nil, ws, tc.podIP, time.Hour)
		if err != nil || url != tc.want {
			t.Errorf("grant URL for %s = %q, %v; want %q", tc.podIP, url, err, tc.want)
		}
	}
}
