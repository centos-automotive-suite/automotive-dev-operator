package buildapi

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
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

type execCall struct {
	podName string
	cmd     []string
}

// stubExtraRepoExec replaces the pod-exec entry point used by resolveExtraRepos
// with a recorder, so tests can assert exactly how many servers were started
// (and that none were started on a rejected request) without a live cluster.
func stubExtraRepoExec(t *testing.T) *[]execCall {
	t.Helper()
	// Pin the namespace so fixtures and the lookup target the same namespace
	// regardless of BUILD_API_NAMESPACE or an in-pod service-account file.
	t.Setenv("BUILD_API_NAMESPACE", "default")
	orig := podExecForExtraRepos
	calls := &[]execCall{}
	podExecForExtraRepos = func(_ context.Context, _ *rest.Config, _, podName, _ string, cmd []string, _ io.Writer) error {
		*calls = append(*calls, execCall{podName: podName, cmd: cmd})
		return nil
	}
	t.Cleanup(func() { podExecForExtraRepos = orig })
	return calls
}

// A build submitted by one user must not reach into another user's workspace
// via --extra-repo. The request is rejected and no server is started.
func TestResolveExtraRepos_RejectsUnownedWorkspace(t *testing.T) {
	ws, pod := runningWorkspace("alice-ws", "alice")
	k8sClient := newFakeClient(ws, pod)
	calls := stubExtraRepoExec(t)
	a := &APIServer{}
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"alice-ws:/workspace/rpms"}}

	err := a.resolveExtraRepos(context.Background(), k8sClient, nil, "bob", req)
	if err == nil {
		t.Fatal("expected ownership error, got nil")
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no exec calls on rejection, got %d", len(*calls))
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("expected no CustomDefs mutation on rejection, got %#v", req.CustomDefs)
	}
}

// The response must not reveal whether a workspace exists: an unowned workspace
// and a missing one must produce byte-identical errors.
func TestResolveExtraRepos_UnownedIndistinguishableFromMissing(t *testing.T) {
	stubExtraRepoExec(t)
	a := &APIServer{}
	const name = "shadow-ws"
	newReq := func() *buildcontract.BuildRequest {
		return &buildcontract.BuildRequest{ExtraRepos: []string{name + ":/workspace/rpms"}}
	}

	// Case 1: workspace does not exist.
	errMissing := a.resolveExtraRepos(context.Background(), newFakeClient(), nil, "bob", newReq())
	if errMissing == nil {
		t.Fatal("expected error for missing workspace, got nil")
	}

	// Case 2: workspace exists but is owned by someone else.
	ws, pod := runningWorkspace(name, "alice")
	errUnowned := a.resolveExtraRepos(context.Background(), newFakeClient(ws, pod), nil, "bob", newReq())
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
	stubExtraRepoExec(t)
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
	a := &APIServer{}
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"any-ws:/workspace/rpms"}}

	err := a.resolveExtraRepos(context.Background(), k8sClient, nil, "bob", req)
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

// Validation is all-or-nothing with respect to exec: if a later entry is
// unauthorized, no server is started for earlier authorized entries.
func TestResolveExtraRepos_AllOrNothing(t *testing.T) {
	bobWS, bobPod := runningWorkspace("bob-ws", "bob")
	aliceWS, alicePod := runningWorkspace("alice-ws", "alice")
	k8sClient := newFakeClient(bobWS, bobPod, aliceWS, alicePod)
	calls := stubExtraRepoExec(t)
	a := &APIServer{}
	req := &buildcontract.BuildRequest{
		ExtraRepos: []string{"bob-ws:/workspace/rpms", "alice-ws:/workspace/rpms"},
	}

	err := a.resolveExtraRepos(context.Background(), k8sClient, nil, "bob", req)
	if err == nil {
		t.Fatal("expected ownership error on second entry, got nil")
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no exec calls (pass 1 must reject before pass 2), got %d", len(*calls))
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("expected no CustomDefs mutation on rejection, got %#v", req.CustomDefs)
	}
}

// The owner's own running workspace is accepted: exactly one server is started
// and the repo is injected into CustomDefs.
func TestResolveExtraRepos_AllowsOwnedRunningWorkspace(t *testing.T) {
	ws, pod := runningWorkspace("bob-ws", "bob")
	k8sClient := newFakeClient(ws, pod)
	calls := stubExtraRepoExec(t)
	a := &APIServer{log: logr.Discard()}
	req := &buildcontract.BuildRequest{ExtraRepos: []string{"bob-ws:/workspace/rpms"}}

	err := a.resolveExtraRepos(context.Background(), k8sClient, nil, "bob", req)
	if err != nil {
		t.Fatalf("expected owned workspace to be accepted, got %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 exec call, got %d", len(*calls))
	}
	if (*calls)[0].podName != "bob-ws-pod" {
		t.Fatalf("exec targeted pod %q, want %q", (*calls)[0].podName, "bob-ws-pod")
	}

	want := `extra_repos=[{"id":"workspace-bob-ws","baseurl":"http://10.0.0.1:8080"}]`
	found := false
	for _, d := range req.CustomDefs {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("CustomDefs missing %q, got %#v", want, req.CustomDefs)
	}
}
