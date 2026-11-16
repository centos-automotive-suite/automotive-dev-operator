package buildapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/workspacemanifest"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	hydrateWorkspaceName = "dev-ws"
	hydrateWorkspacePod  = "workspace-dev-ws"
)

// hydrateFixture is a build whose upload pod runs the agent as the
// controller starts it, over a directory standing for its shared PVC.
type hydrateFixture struct {
	kube      client.Client
	build     *automotivev1alpha1.ImageBuild
	shared    string
	uploadPod *httptest.Server
	uploader  uploadConnector
}

func newHydrateFixture(t *testing.T, refs []workspacemanifest.WorkspaceHydrateRef) *hydrateFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	build := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testBuildName,
			Namespace:   testNamespace,
			Annotations: map[string]string{labels.WorkspaceHydrate: string(raw)},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{Workspace: hydrateWorkspaceName},
	}
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: hydrateWorkspaceName, Namespace: testNamespace},
		Status:     automotivev1alpha1.WorkspaceStatus{Phase: phaseRunning, PodName: hydrateWorkspacePod},
	}
	uploadPod := newTestUploadPod(true)
	uploadPod.Namespace = testNamespace
	uploadPod.Labels[labels.ImageBuildName] = testBuildName
	shared := t.TempDir()
	agent, err := workspaceagent.New(filepath.Join(t.TempDir(), "runs"), shared, shared, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	agent.TakeBuildUploads()
	server := httptest.NewServer(agent.Handler("secret", nil))
	t.Cleanup(server.Close)
	return &hydrateFixture{
		kube:      fake.NewClientBuilder().WithScheme(scheme).WithObjects(build, ws, uploadPod).Build(),
		build:     build,
		shared:    shared,
		uploadPod: server,
		uploader: func(_ context.Context, target *automotivev1alpha1.ImageBuild) (*workspaceagent.Client, error) {
			if target.Name != testBuildName {
				t.Errorf("connected to the upload pod of %s", target.Name)
			}
			return workspaceagent.NewClient(server.URL, "secret", nil), nil
		},
	}
}

func (f *hydrateFixture) hydrate(connect agentConnector) error {
	return hydrateWorkspace(context.Background(), connect, f.uploader, f.kube, f.build)
}

// uploaded returns the files on the upload pod's shared PVC once the pod
// has finished with every request: a hydrate that fails partway returns
// before the pod has seen the upload cut and cleared what it staged.
func (f *hydrateFixture) uploaded(t *testing.T) map[string]string {
	t.Helper()
	f.uploadPod.Close()
	files := map[string]string{}
	err := filepath.WalkDir(f.shared, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, _ := filepath.Rel(f.shared, path)
		files[filepath.ToSlash(name)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// startHydrateAgent serves a real agent over a workspace holding files.
func startHydrateAgent(t *testing.T, files map[string]string, links map[string]string) agentConnector {
	t.Helper()
	workspace := t.TempDir()
	for name, content := range files {
		path := filepath.Join(workspace, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		path := filepath.Join(workspace, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	agent, err := workspaceagent.New(filepath.Join(t.TempDir(), "runs"), t.TempDir(), workspace, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return serveHydrateAgent(t, agent.Handler("secret", nil))
}

func serveHydrateAgent(t *testing.T, handler http.Handler) agentConnector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return func(_ context.Context, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		if ws.Name != hydrateWorkspaceName {
			t.Errorf("connected to workspace %s", ws.Name)
		}
		return workspaceagent.NewClient(server.URL, "secret", nil), nil
	}
}

func TestHydrateWorkspaceCopiesTheFilesTheAgentFinds(t *testing.T) {
	connect := startHydrateAgent(t, map[string]string{
		"src/hydrate-bin":    "app-bytes",
		"src/rpms/a.rpm":     "a",
		"src/rpms/x/b.rpm":   "b",
		"src/rpms/notes.txt": "notes",
		"conf/c.conf":        "c",
	}, nil)
	f := newHydrateFixture(t, []workspacemanifest.WorkspaceHydrateRef{
		{Kind: hydrateKindPath, AbsPath: "/workspace/src/hydrate-bin", RelPath: "src/hydrate-bin"},
		{Kind: hydrateKindGlob, AbsPath: "/workspace/src/rpms/**/*.rpm", RelPath: "src/rpms/**/*.rpm"},
		{Kind: hydrateKindPath, AbsPath: "/workspace/conf", RelPath: "conf"},
	})

	if err := f.hydrate(connect); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"src/hydrate-bin":  "app-bytes",
		"src/rpms/a.rpm":   "a",
		"src/rpms/x/b.rpm": "b",
		"conf/c.conf":      "c",
	}
	if got := f.uploaded(t); !maps.Equal(got, want) {
		t.Errorf("uploaded %v\nwant     %v", got, want)
	}
}

// One upload carries every file, so a hydrate that fails partway leaves the
// upload pod as it was for the retry.
func TestHydrateWorkspaceCopiesAllOrNothing(t *testing.T) {
	connect := serveHydrateAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/files/list":
			_ = json.NewEncoder(w).Encode(workspaceagent.ListFilesResponse{Files: []string{"src/a", "src/b"}})
		case "/files/src/a":
			_, _ = io.WriteString(w, "a")
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	f := newHydrateFixture(t, []workspacemanifest.WorkspaceHydrateRef{
		{Kind: hydrateKindPath, AbsPath: "/workspace/src", RelPath: "src"},
	})

	err := f.hydrate(connect)
	if err == nil || IsPermanentHydrateError(err) {
		t.Fatalf("error = %v, want one to retry", err)
	}
	if got := f.uploaded(t); len(got) != 0 {
		t.Errorf("uploaded %v from a failed hydrate", got)
	}
}

// Missing files and links out of the workspace fail the same way on every
// attempt, so the build fails at once, as does a name the upload pod won't
// take.
func TestHydrateWorkspaceFailsForGoodOnFilesItCannotCopy(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]workspacemanifest.WorkspaceHydrateRef{
		"missing":       {Kind: hydrateKindPath, AbsPath: "/workspace/src/missing", RelPath: "src/missing"},
		"no glob match": {Kind: hydrateKindGlob, AbsPath: "/workspace/src/*.deb", RelPath: "src/*.deb"},
		"a link out":    {Kind: hydrateKindPath, AbsPath: "/workspace/src/key", RelPath: "src/key"},
		"a plain name":  {Kind: hydrateKindPath, AbsPath: "/workspace/src/my file", RelPath: "src/my file"},
	} {
		t.Run(name, func(t *testing.T) {
			connect := startHydrateAgent(t, map[string]string{"src/a": "a", "src/my file": "x"}, map[string]string{"src/key": outside})
			f := newHydrateFixture(t, []workspacemanifest.WorkspaceHydrateRef{ref})
			err := f.hydrate(connect)
			if !IsPermanentHydrateError(err) {
				t.Fatalf("error = %v, want a permanent error", err)
			}
			if got := f.uploaded(t); len(got) != 0 {
				t.Errorf("uploaded %v", got)
			}
		})
	}
}

// The user controls their workspace's agent, so hydration checks the names
// it returns.
func TestHydrateWorkspaceRefusesAnInvalidNameFromTheAgent(t *testing.T) {
	var reads atomic.Int32
	connect := serveHydrateAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads.Add(1)
		}
		_ = json.NewEncoder(w).Encode(workspaceagent.ListFilesResponse{Files: []string{"../../etc/passwd"}})
	}))
	f := newHydrateFixture(t, []workspacemanifest.WorkspaceHydrateRef{
		{Kind: hydrateKindPath, AbsPath: "/workspace/x", RelPath: "x"},
	})

	err := f.hydrate(connect)
	if !IsPermanentHydrateError(err) {
		t.Fatalf("error = %v, want a permanent error", err)
	}
	if got := f.uploaded(t); len(got) != 0 || reads.Load() != 0 {
		t.Errorf("uploaded %v after %d reads", got, reads.Load())
	}
}

func TestHydrateWorkspaceRetriesWhenTheAgentFails(t *testing.T) {
	failing := serveHydrateAgent(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	unreachable := agentConnector(func(context.Context, *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		return nil, errors.New("reading the workspace agent token: not found")
	})
	for name, connect := range map[string]agentConnector{"failing": failing, "unreachable": unreachable} {
		t.Run(name, func(t *testing.T) {
			f := newHydrateFixture(t, []workspacemanifest.WorkspaceHydrateRef{
				{Kind: hydrateKindPath, AbsPath: "/workspace/x", RelPath: "x"},
			})
			err := f.hydrate(connect)
			if err == nil || IsPermanentHydrateError(err) {
				t.Fatalf("error = %v, want one to retry", err)
			}
		})
	}
}

func TestHydrateWorkspaceForImageBuild_UploadPodNotReady(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testBuildName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				labels.WorkspaceHydrate: `[{"kind":"path","absPath":"/workspace/src/hydrate-bin","relPath":"src/hydrate-bin"}]`,
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{Workspace: "dev-ws"},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib).Build()
	err := HydrateWorkspaceForImageBuild(context.Background(), fakeClient, fakeClient, ib)
	if !errors.Is(err, ErrUploadPodNotReady) {
		t.Fatalf("error = %v, want ErrUploadPodNotReady", err)
	}
}

func TestHydrateWorkspaceForImageBuild_NoAnnotation(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: testBuildName, Namespace: testNamespace},
	}
	if err := HydrateWorkspaceForImageBuild(context.Background(), nil, nil, ib); err != nil {
		t.Fatalf("expected no-op, got %v", err)
	}
}

// TestSetWorkspaceUploadAnnotations_RejectsOversizedPlan ensures an unbounded
// hydrate plan cannot be written into an annotation that would exceed
// Kubernetes' 256 KiB metadata limit and fail ImageBuild creation with a 500.
func TestSetWorkspaceUploadAnnotations_RejectsOversizedPlan(t *testing.T) {
	refs := make([]workspacemanifest.WorkspaceHydrateRef, 0, 6000)
	for i := range 6000 {
		p := fmt.Sprintf("src/some/deeply/nested/path/file-%06d.bin", i)
		refs = append(refs, workspacemanifest.WorkspaceHydrateRef{
			Kind:    hydrateKindPath,
			AbsPath: "/workspace/" + p,
			RelPath: p,
		})
	}
	ann := map[string]string{}
	err := setWorkspaceUploadAnnotations(ann, refs, &buildcontract.BuildRequest{Workspace: "dev-ws"})
	if !errors.Is(err, ErrWorkspaceHydratePlanTooLarge) {
		t.Fatalf("error = %v, want ErrWorkspaceHydratePlanTooLarge", err)
	}
	if _, ok := ann[labels.WorkspaceHydrate]; ok {
		t.Fatal("oversized plan must not be written to annotations")
	}
}

func TestSetWorkspaceUploadAnnotations_AllowsNormalPlan(t *testing.T) {
	refs := []workspacemanifest.WorkspaceHydrateRef{{
		Kind:    hydrateKindPath,
		AbsPath: "/workspace/src/app",
		RelPath: "src/app",
	}}
	ann := map[string]string{}
	if err := setWorkspaceUploadAnnotations(ann, refs, &buildcontract.BuildRequest{Workspace: "dev-ws"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ann[labels.WorkspaceHydrate] == "" {
		t.Fatal("expected workspace-hydrate annotation to be set")
	}
	if ann[labels.ClientSkipsUploads] != labels.ValueTrue {
		t.Fatal("expected client-skips-uploads annotation for --workspace build")
	}
}

func TestIsPermanentHydrateError(t *testing.T) {
	if IsPermanentHydrateError(ErrUploadPodNotReady) {
		t.Fatal("ErrUploadPodNotReady must be retryable")
	}
	if !IsPermanentHydrateError(permanentHydrateErrorf("bad dest")) {
		t.Fatal("permanentHydrateErrorf must be permanent")
	}
	if IsPermanentHydrateError(fmt.Errorf("workspace %q is not running", "ws")) {
		t.Fatal("workspace not running must be retryable")
	}
}
