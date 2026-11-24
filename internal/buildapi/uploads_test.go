package buildapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
)

func newTestImageBuild() *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-build",
			Namespace:   "test-ns",
			Annotations: map[string]string{labels.RequestedBy: "test-user"},
		},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: automotivev1alpha1.ImageBuildPhaseUploading},
	}
}

// newTestUploadPod is test-build's upload pod, its agent ready or not.
func newTestUploadPod(ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build-upload-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{labels.ImageBuildName: "test-build", labels.Name: "upload-pod"},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}

// uploadTestClient returns a client for a build API whose upload pod's agent,
// started as the controller starts it, serves workdir, and the cluster it
// sees.
func uploadTestClient(t *testing.T, workdir string, objs ...ctrlclient.Object) (*buildapiclient.Client, ctrlclient.Client) {
	t.Helper()
	agent, err := workspaceagent.New(filepath.Join(t.TempDir(), "runs"), workdir, workdir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	agent.TakeBuildUploads()
	server := httptest.NewServer(agent.Handler("secret", nil))
	t.Cleanup(server.Close)
	return uploadTestAPI(t, server.URL, objs...)
}

// uploadTestAPI returns a client for a build API whose upload pod's agent is
// at agentURL, and the cluster it sees.
func uploadTestAPI(t *testing.T, agentURL string, objs ...ctrlclient.Object) (*buildapiclient.Client, ctrlclient.Client) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(&automotivev1alpha1.ImageBuild{}).Build()
	a := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (ctrlclient.Client, error) { return kube, nil }
		deps.uploadAgent = func(_ context.Context, _ ctrlclient.Client, build *automotivev1alpha1.ImageBuild) (*workspaceagent.Client, error) {
			if build.Namespace != "test-ns" || build.Name != "test-build" {
				t.Errorf("wrong upload agent: %s/%s", build.Namespace, build.Name)
			}
			return workspaceagent.NewClient(agentURL, "secret", nil), nil
		}
	})
	router := gin.New()
	// The client is test-user, who requested test-build.
	router.Use(func(c *gin.Context) { c.Set("requester", "test-user"); c.Next() })
	router.POST("/v1/builds/:name/uploads", a.wrapNamedHandler("uploads", a.uploadFiles))
	return newRunClient(t, router), kube
}

func writeSource(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	source := filepath.Join(dir, name)
	if err := os.WriteFile(source, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return source
}

func uploadsComplete(t *testing.T, kube ctrlclient.Client) bool {
	t.Helper()
	build := &automotivev1alpha1.ImageBuild{}
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "test-ns", Name: "test-build"}, build); err != nil {
		t.Fatal(err)
	}
	return build.Annotations[labels.UploadsComplete] == labels.ValueTrue
}

// The files go to the upload pod's agent in one request, which the build API
// relays, and land as exec used to write them: at their destination,
// readable, and not executable.
func TestUploadFilesReachTheUploadPod(t *testing.T) {
	workdir := t.TempDir()
	api, kube := uploadTestClient(t, workdir, newTestImageBuild(), newTestUploadPod(true))
	sources := t.TempDir()
	err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{
		{SourcePath: writeSource(t, sources, "a.rpm", "rpm", 0o644), DestPath: "rpms/a.rpm"},
		{SourcePath: writeSource(t, sources, "run.sh", "#!/bin/sh", 0o755), DestPath: "scripts/run.sh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"rpms/a.rpm": "rpm", "scripts/run.sh": "#!/bin/sh"} {
		path := filepath.Join(workdir, name)
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Errorf("%s = %q, %v; want %q", name, data, err, want)
			continue
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
			t.Errorf("%s mode = %v, %v; want 0644", name, info.Mode(), err)
		}
	}
	if !uploadsComplete(t, kube) {
		t.Error("the build is not marked as having its uploads")
	}
}

// The CLI retries while the upload pod's agent isn't ready, on this message.
func TestUploadFilesWaitForTheUploadAgent(t *testing.T) {
	for name, objs := range map[string][]ctrlclient.Object{
		"no pod":          {newTestImageBuild()},
		"a pod not ready": {newTestImageBuild(), newTestUploadPod(false)},
	} {
		t.Run(name, func(t *testing.T) {
			api, kube := uploadTestClient(t, t.TempDir(), objs...)
			source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
			err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "a.rpm"}})
			if err == nil || !strings.Contains(err.Error(), "upload pod not ready") {
				t.Errorf("err = %v, want the upload pod not ready", err)
			}
			if uploadsComplete(t, kube) {
				t.Error("the build is marked as having its uploads")
			}
		})
	}
}

// An agent that refuses connections is the not-ready state the CLI retries:
// the upload pod turns ready a moment before its Service routes to it.
func TestUploadFilesRetryWhenTheAgentIsUnreachable(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	api, kube := uploadTestAPI(t, gone.URL, newTestImageBuild(), newTestUploadPod(true))
	source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
	err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "a.rpm"}})
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "upload pod not ready") {
		t.Errorf("err = %v, want a 503 for the upload pod not ready", err)
	}
	if uploadsComplete(t, kube) {
		t.Error("the build is marked as having its uploads")
	}
}

// What the agent rejects reaches the client, and the build waits on.
func TestUploadFilesPassOnTheAgentsRejection(t *testing.T) {
	api, kube := uploadTestClient(t, t.TempDir(), newTestImageBuild(), newTestUploadPod(true))
	source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
	err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "my file.rpm"}})
	if err == nil || !strings.Contains(err.Error(), "my file.rpm") {
		t.Errorf("err = %v, want the agent's rejection naming the file", err)
	}
	if uploadsComplete(t, kube) {
		t.Error("the build is marked as having its uploads")
	}
}

// Files land only while the build is Uploading and before its uploads are
// marked complete. Later ones would change inputs the build is already using.
func TestUploadFilesOnlyWhileUploading(t *testing.T) {
	cases := map[string]func(*automotivev1alpha1.ImageBuild){
		"pending": func(b *automotivev1alpha1.ImageBuild) {
			b.Status.Phase = phasePending
		},
		"building": func(b *automotivev1alpha1.ImageBuild) {
			b.Status.Phase = phaseBuilding
		},
		"completed": func(b *automotivev1alpha1.ImageBuild) {
			b.Status.Phase = automotivev1alpha1.ImageBuildPhaseCompleted
		},
		"failed": func(b *automotivev1alpha1.ImageBuild) {
			b.Status.Phase = automotivev1alpha1.ImageBuildPhaseFailed
		},
		"uploads already complete": func(b *automotivev1alpha1.ImageBuild) {
			b.Annotations[labels.UploadsComplete] = labels.ValueTrue
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			build := newTestImageBuild()
			change(build)
			workdir := t.TempDir()
			api, _ := uploadTestClient(t, workdir, build, newTestUploadPod(true))
			source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
			err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "a.rpm"}})
			if err == nil || !strings.Contains(err.Error(), "409") {
				t.Errorf("err = %v, want a 409", err)
			}
			if entries, err := os.ReadDir(workdir); err != nil || len(entries) != 0 {
				t.Errorf("files reached the upload pod: %v, %v", entries, err)
			}
		})
	}
}

// Two uploads to one build overlap: the second is admitted while the first is
// still in the agent. Only the first may reach the agent, and the second must
// find the build complete instead of committing after it.
func TestUploadFilesDoNotCommitAfterCompletion(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var agentUploads atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if agentUploads.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"files":1,"deleted":0}`))
	}))
	t.Cleanup(agent.Close)
	api, kube := uploadTestAPI(t, agent.URL, newTestImageBuild(), newTestUploadPod(true))
	source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
	upload := func() error {
		return api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "a.rpm"}})
	}
	first := make(chan error, 1)
	go func() { first <- upload() }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first upload never reached the agent")
	}
	second := make(chan error, 1)
	go func() { second <- upload() }()
	// Give the second upload time to reach the API while the first is in the
	// agent. A local request takes milliseconds.
	time.Sleep(200 * time.Millisecond)
	unblock()
	if err := <-first; err != nil {
		t.Errorf("first upload: %v", err)
	}
	if err := <-second; err == nil || !strings.Contains(err.Error(), "409") {
		t.Errorf("second upload err = %v, want a 409 once the build is complete", err)
	}
	if n := agentUploads.Load(); n != 1 {
		t.Errorf("the agent got %d uploads, want 1", n)
	}
	if !uploadsComplete(t, kube) {
		t.Error("the first upload did not mark the build complete")
	}
}

// An upload without files would let the build start without its inputs.
func TestUploadFilesRequireAFile(t *testing.T) {
	api, kube := uploadTestClient(t, t.TempDir(), newTestImageBuild(), newTestUploadPod(true))
	err := api.UploadFiles(context.Background(), "test-build", nil)
	if err == nil || !strings.Contains(err.Error(), "at least one file") {
		t.Errorf("err = %v, want the empty upload rejected", err)
	}
	if uploadsComplete(t, kube) {
		t.Error("the build is marked as having its uploads")
	}
}

// Anyone may read a build, but only its requester may change what goes into
// it.
func TestUploadFilesRejectsOtherUsersBuild(t *testing.T) {
	build := newTestImageBuild()
	build.Annotations[labels.RequestedBy] = "mallory"
	workdir := t.TempDir()
	api, kube := uploadTestClient(t, workdir, build, newTestUploadPod(true))
	source := writeSource(t, t.TempDir(), "app.conf", "key=value", 0o644)
	err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "app.conf"}})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v, want a 403", err)
	}
	if entries, err := os.ReadDir(workdir); err != nil || len(entries) != 0 {
		t.Errorf("files reached another user's upload pod: %v, %v", entries, err)
	}
	if uploadsComplete(t, kube) {
		t.Error("the build is marked as having its uploads")
	}
}

func TestUploadFilesForAMissingBuild(t *testing.T) {
	api, _ := uploadTestClient(t, t.TempDir(), newTestUploadPod(true))
	source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
	err := api.UploadFiles(context.Background(), "test-build", []buildapiclient.Upload{{SourcePath: source, DestPath: "a.rpm"}})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want a 404", err)
	}
}

// The client sends the agent's format, which the build API relays as it is:
// an empty request, then a zstd stream.
func TestUploadFilesSendsTheAgentsFormat(t *testing.T) {
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		received <- body.Bytes()
		http.Error(w, "stop", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	source := writeSource(t, t.TempDir(), "a.rpm", "rpm", 0o644)
	_ = api.UploadFiles(context.Background(), "b", []buildapiclient.Upload{{SourcePath: source, DestPath: "a.rpm"}})
	body := <-received
	zstdMagic := []byte{0x28, 0xb5, 0x2f, 0xfd}
	if !bytes.HasPrefix(body, append([]byte("{}"), zstdMagic...)) {
		t.Errorf("the body starts %q, want {} and a zstd frame", body[:min(len(body), 8)])
	}
}
