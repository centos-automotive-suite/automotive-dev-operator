package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
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

	refs := []WorkspaceHydrateRef{{
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
