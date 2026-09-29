package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/workspacemanifest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestHydrateWorkspaceForImageBuild(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const (
		wsName    = "dev-ws"
		wsPodName = "workspace-dev-ws"
		srcFile   = "/workspace/src/hydrate-bin"
		relFile   = "src/hydrate-bin"
	)

	refs := []workspacemanifest.WorkspaceHydrateRef{{
		Kind:    hydrateKindPath,
		AbsPath: srcFile,
		RelPath: relFile,
	}}
	raw, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}

	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testBuildName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				labels.WorkspaceHydrate: string(raw),
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{Workspace: wsName},
	}
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: wsName, Namespace: testNamespace},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseRunning,
			PodName: wsPodName,
		},
	}
	uploadPod := newTestUploadPod()
	wsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: wsPodName, Namespace: testNamespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: workspaceContainerName}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib, ws, uploadPod, wsPod).Build()

	origExec := newPodExecExecutorFn
	t.Cleanup(func() { newPodExecExecutorFn = origExec })

	uploaded := map[string][]byte{}
	newPodExecExecutorFn = func(_ *rest.Config, _, podName, _ string, cmd []string) (remotecommand.Executor, error) {
		joined := strings.Join(cmd, " ")
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
				switch {
				case strings.Contains(joined, "python3"):
					list, _ := json.Marshal([]hydrateFile{{Src: srcFile, Dest: relFile}})
					_, _ = opts.Stdout.Write(list)
				case strings.Contains(joined, "[ -f"):
					_, _ = opts.Stdout.Write([]byte("no"))
				case podName == wsPodName:
					_, _ = opts.Stdout.Write([]byte("app-bytes"))
				default:
					data, _ := io.ReadAll(opts.Stdin)
					uploaded[cmd[len(cmd)-1]] = data
				}
				return nil
			},
		}, nil
	}

	if err := HydrateWorkspaceForImageBuild(context.Background(), &rest.Config{}, fakeClient, ib); err != nil {
		t.Fatalf("HydrateWorkspaceForImageBuild: %v", err)
	}
	got := uploaded["/workspace/shared/"+relFile]
	if !bytes.Equal(got, []byte("app-bytes")) {
		t.Errorf("uploaded %q, want app-bytes", got)
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
	err := HydrateWorkspaceForImageBuild(context.Background(), &rest.Config{}, fakeClient, ib)
	if !errors.Is(err, ErrUploadPodNotReady) {
		t.Fatalf("error = %v, want ErrUploadPodNotReady", err)
	}
}

func TestHydrateWorkspaceForImageBuild_NoAnnotation(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: testBuildName, Namespace: testNamespace},
	}
	if err := HydrateWorkspaceForImageBuild(context.Background(), &rest.Config{}, nil, ib); err != nil {
		t.Fatalf("expected no-op, got %v", err)
	}
}

func TestHydrateWorkspaceForImageBuild_RejectsTraversalDest(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const (
		wsName    = "dev-ws"
		wsPodName = "workspace-dev-ws"
	)
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testBuildName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				labels.WorkspaceHydrate: `[{"kind":"path","absPath":"/workspace/x","relPath":"src/x"}]`,
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{Workspace: wsName},
	}
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: wsName, Namespace: testNamespace},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseRunning,
			PodName: wsPodName,
		},
	}
	uploadPod := newTestUploadPod()
	wsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: wsPodName, Namespace: testNamespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: workspaceContainerName}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib, ws, uploadPod, wsPod).Build()

	origExec := newPodExecExecutorFn
	t.Cleanup(func() { newPodExecExecutorFn = origExec })

	uploaded := map[string][]byte{}
	newPodExecExecutorFn = func(_ *rest.Config, _, podName, _ string, cmd []string) (remotecommand.Executor, error) {
		joined := strings.Join(cmd, " ")
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
				if strings.Contains(joined, "python3") {
					list, _ := json.Marshal([]hydrateFile{{Src: "/workspace/x", Dest: ".."}})
					_, _ = opts.Stdout.Write(list)
					return nil
				}
				if podName != wsPodName {
					data, _ := io.ReadAll(opts.Stdin)
					uploaded[cmd[len(cmd)-1]] = data
				}
				return nil
			},
		}, nil
	}

	err := HydrateWorkspaceForImageBuild(context.Background(), &rest.Config{}, fakeClient, ib)
	if err == nil {
		t.Fatal("expected destination path rejection")
	}
	if !IsPermanentHydrateError(err) {
		t.Fatalf("error %v should be permanent", err)
	}
	if len(uploaded) != 0 {
		t.Fatalf("uploaded %v, want no files written", uploaded)
	}
}

// TestHydrateWorkspaceForImageBuild_SkipsExistingFiles verifies that files
// already present on the upload pod are not re-copied, so a retried hydrate
// makes forward progress instead of restarting the whole transfer.
func TestHydrateWorkspaceForImageBuild_SkipsExistingFiles(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const (
		wsName    = "dev-ws"
		wsPodName = "workspace-dev-ws"
		srcFile   = "/workspace/src/hydrate-bin"
		relFile   = "src/hydrate-bin"
	)
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testBuildName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				labels.WorkspaceHydrate: `[{"kind":"path","absPath":"/workspace/src/hydrate-bin","relPath":"src/hydrate-bin"}]`,
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{Workspace: wsName},
	}
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: wsName, Namespace: testNamespace},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseRunning,
			PodName: wsPodName,
		},
	}
	uploadPod := newTestUploadPod()
	wsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: wsPodName, Namespace: testNamespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: workspaceContainerName}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib, ws, uploadPod, wsPod).Build()

	origExec := newPodExecExecutorFn
	t.Cleanup(func() { newPodExecExecutorFn = origExec })

	uploaded := map[string][]byte{}
	newPodExecExecutorFn = func(_ *rest.Config, _, podName, _ string, cmd []string) (remotecommand.Executor, error) {
		joined := strings.Join(cmd, " ")
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
				switch {
				case strings.Contains(joined, "python3"):
					list, _ := json.Marshal([]hydrateFile{{Src: srcFile, Dest: relFile}})
					_, _ = opts.Stdout.Write(list)
				case strings.Contains(joined, "[ -f"):
					_, _ = opts.Stdout.Write([]byte("yes"))
				case podName == wsPodName:
					_, _ = opts.Stdout.Write([]byte("app-bytes"))
				default:
					data, _ := io.ReadAll(opts.Stdin)
					uploaded[cmd[len(cmd)-1]] = data
				}
				return nil
			},
		}, nil
	}

	if err := HydrateWorkspaceForImageBuild(context.Background(), &rest.Config{}, fakeClient, ib); err != nil {
		t.Fatalf("HydrateWorkspaceForImageBuild: %v", err)
	}
	if len(uploaded) != 0 {
		t.Fatalf("uploaded %v, want no files (already present on upload pod)", uploaded)
	}
}

// TestListWorkspaceHydrateFiles_EscapeIsPermanent verifies that a symlink
// escape reported by the workspace lister is classified as a permanent error
// so the controller fails the build instead of retrying forever.
func TestListWorkspaceHydrateFiles_EscapeIsPermanent(t *testing.T) {
	origExec := newPodExecExecutorFn
	t.Cleanup(func() { newPodExecExecutorFn = origExec })
	newPodExecExecutorFn = func(_ *rest.Config, _, _, _ string, _ []string) (remotecommand.Executor, error) {
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
				_, _ = opts.Stderr.Write([]byte("workspace files escape /workspace: /workspace/evil\n"))
				return fmt.Errorf("command terminated with exit code 2")
			},
		}, nil
	}
	_, err := listWorkspaceHydrateFiles(
		context.Background(), &rest.Config{}, testNamespace, "workspace-dev-ws",
		[]workspacemanifest.WorkspaceHydrateRef{{Kind: hydrateKindPath, AbsPath: "/workspace/evil"}},
	)
	if err == nil {
		t.Fatal("expected error for escaped workspace file")
	}
	if !IsPermanentHydrateError(err) {
		t.Fatalf("error %v should be permanent", err)
	}
}

// TestWorkspaceListPython_RejectsSymlinkEscape runs the embedded lister script
// against a real temp workspace and asserts that a symlink pointing outside the
// workspace root is rejected before it can be copied.
func TestWorkspaceListPython_RejectsSymlinkEscape(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(root, "evil")
	if err := os.Symlink(secret, evil); err != nil {
		t.Fatal(err)
	}

	refs, _ := json.Marshal([]workspacemanifest.WorkspaceHydrateRef{{Kind: hydrateKindPath, AbsPath: evil, RelPath: "evil"}})
	stdout, stderr, err := runWorkspaceLister(t, root, refs)
	if err == nil {
		t.Fatalf("expected non-zero exit, stdout=%s", stdout)
	}
	if !strings.Contains(stderr, "escape") {
		t.Fatalf("stderr = %q, want escape message", stderr)
	}
}

// TestWorkspaceListPython_AllowsInternalSymlink confirms a symlink that stays
// inside the workspace root is still resolved and listed.
func TestWorkspaceListPython_AllowsInternalSymlink(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	refs, _ := json.Marshal([]workspacemanifest.WorkspaceHydrateRef{{Kind: hydrateKindPath, AbsPath: link, RelPath: "link"}})
	stdout, stderr, err := runWorkspaceLister(t, root, refs)
	if err != nil {
		t.Fatalf("lister failed: %v (stderr=%s)", err, stderr)
	}
	var files []hydrateFile
	if err := json.Unmarshal([]byte(stdout), &files); err != nil {
		t.Fatalf("parse lister output %q: %v", stdout, err)
	}
	if len(files) != 1 || files[0].Src != link {
		t.Fatalf("files = %+v, want single entry for %s", files, link)
	}
}

func runWorkspaceLister(t *testing.T, root string, refs []byte) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command("python3", "-c", workspaceListPython, root) //nolint:gosec // fixed script, test-only root
	cmd.Stdin = bytes.NewReader(refs)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
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
