package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

type fakeRemoteExecutor struct {
	streamWithContextFn func(context.Context, remotecommand.StreamOptions) error
}

func (f *fakeRemoteExecutor) Stream(options remotecommand.StreamOptions) error {
	return f.StreamWithContext(context.Background(), options)
}

func (f *fakeRemoteExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	if f.streamWithContextFn != nil {
		return f.streamWithContextFn(ctx, options)
	}
	return nil
}

func writeTempUploadFile(t *testing.T, data []byte) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "upload-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}

func TestSafeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty string", "", false},
		{"simple filename", "file.txt", true},
		{"path with slashes", "configs/app.conf", true},
		{"alphanumeric", "abc123", true},
		{"with dots hyphens underscores", "my-file_v2.tar.gz", true},
		{"with at sign", "user@host", true},
		{"semicolon injection", "file;rm -rf /", false},
		{"backtick injection", "file`whoami`", false},
		{"pipe injection", "file|cat /etc/passwd", false},
		{"dollar expansion", "file$(id)", false},
		{"space", "file name", false},
		{"single quote", "file'name", false},
		{"double quote", "file\"name", false},
		{"newline", "file\nname", false},
		{"null byte", "file\x00name", false},
		{"ampersand", "file&cmd", false},
		{"parentheses", "file(1)", false},
		{"hash", "file#1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeFilename(tt.input)
			if got != tt.expected {
				t.Errorf("safeFilename(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestValidateDestPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPath  string
		wantError bool
	}{
		{"simple file", "app.conf", "app.conf", false},
		{"nested path", "configs/app.conf", "configs/app.conf", false},
		{"deeply nested", "a/b/c/d.txt", "a/b/c/d.txt", false},
		{"with at sign", "user@host.key", "user@host.key", false},
		{"empty string", "", "", true},
		{"unsafe characters", "file;rm", "", true},
		{"dot-dot traversal cleaned", "../etc/passwd", "etc/passwd", false},
		{"mid-path traversal cleaned", "a/../b/c.txt", "b/c.txt", false},
		{"dot only", ".", "", true},
		{"slash only resolves to dot", "/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateDestPath(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateDestPath(%q) expected error, got path=%q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("validateDestPath(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.wantPath {
				t.Errorf("validateDestPath(%q) = %q, want %q", tt.input, got, tt.wantPath)
			}
		})
	}
}

type uploadTestFixture struct {
	server   *APIServer
	fakeK8s  ctrlclient.Client
	uploaded map[string][]byte // podPath -> content captured by fake executor
}

func setupUploadTest(t *testing.T, objs ...ctrlclient.Object) *uploadTestFixture {
	t.Helper()

	gin.SetMode(gin.TestMode)

	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&automotivev1alpha1.ImageBuild{})
	for _, obj := range objs {
		builder = builder.WithObjects(obj)
	}
	fakeClient := builder.Build()

	server := newTestServer(t, nil)
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
		return fakeClient, nil
	}
	server.deps.getRESTConfigFromRequest = func(_ *gin.Context) (*rest.Config, error) {
		return &rest.Config{}, nil
	}

	uploaded := make(map[string][]byte)
	server.exec.newExecutor = func(
		_ *rest.Config, _, _, _ string, cmd []string,
	) (remotecommand.Executor, error) {
		podPath := cmd[len(cmd)-1]
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, opts remotecommand.StreamOptions) error {
				data, _ := io.ReadAll(opts.Stdin)
				uploaded[podPath] = data
				return nil
			},
		}, nil
	}

	return &uploadTestFixture{
		server:   server,
		fakeK8s:  fakeClient,
		uploaded: uploaded,
	}
}

func newTestImageBuild() *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build",
			Namespace: "test-ns",
			Annotations: map[string]string{
				labels.RequestedBy: "test-user",
			},
		},
	}
}

func newTestUploadPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build-upload",
			Namespace: "test-ns",
			Labels: map[string]string{
				labels.ImageBuildName: "test-build",
				labels.Name:           "upload-pod",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "fileserver"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

type multipartPart struct{ name, content string }

func buildMultipartRequest(t *testing.T, parts []multipartPart) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, p := range parts {
		var part io.Writer
		var err error
		if p.name == "path" {
			part, err = writer.CreateFormField("path")
		} else {
			part, err = writer.CreateFormFile("file", p.name)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(p.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, "/v1/builds/test-build/uploads", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestUploadFiles_BuildNotFound(t *testing.T) {
	fix := setupUploadTest(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/nonexistent/uploads", nil)

	fix.server.uploadFiles(c, "nonexistent")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFiles_NoPodReady(t *testing.T) {
	build := newTestImageBuild()
	fix := setupUploadTest(t, build)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/test-build/uploads", nil)

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFiles_ContentTooLarge(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	fix.server.limits.MaxTotalUploadSize = 10

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/test-build/uploads", bytes.NewReader(make([]byte, 100)))
	c.Request.ContentLength = 100
	c.Request.Header.Set("Content-Type", "multipart/form-data; boundary=test")

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFiles_SingleFile(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"app.conf", "key=value"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if data, ok := fix.uploaded["/workspace/shared/app.conf"]; !ok {
		t.Fatal("file not uploaded to pod")
	} else if string(data) != "key=value" {
		t.Fatalf("uploaded content = %q, want %q", data, "key=value")
	}

	// Verify annotation was set
	updated := &automotivev1alpha1.ImageBuild{}
	if err := fix.fakeK8s.Get(context.Background(), ctrlclient.ObjectKeyFromObject(build), updated); err != nil {
		t.Fatal(err)
	}
	if updated.Annotations[labels.UploadsComplete] != labels.ValueTrue {
		t.Fatalf("UploadsComplete annotation = %q, want %q", updated.Annotations[labels.UploadsComplete], labels.ValueTrue)
	}
}

func TestUploadFiles_PathFieldSetsDestination(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"path", "configs/override.conf"},
		{"upload.dat", "data"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if _, ok := fix.uploaded["/workspace/shared/configs/override.conf"]; !ok {
		t.Fatalf("file not at expected path; uploaded keys: %v", keysOf(fix.uploaded))
	}
}

func TestUploadFiles_UnsafeFilenameRejected(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"path", "file;rm -rf /"},
		{"payload", "evil"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFiles_StreamToPodFails(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	fix.server.exec.newExecutor = func(
		_ *rest.Config, _, _, _ string, _ []string,
	) (remotecommand.Executor, error) {
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, _ remotecommand.StreamOptions) error {
				return fmt.Errorf("pod exec failed")
			},
		}, nil
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"file.txt", "content"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if msg := resp["error"]; msg == "" {
		t.Fatal("expected error message in response")
	}
}

func keysOf(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestUploadFiles_EmptyMultipartRejected(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/test-build/uploads", &body)
	c.Request.Header.Set("Content-Type", writer.FormDataContentType())

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "at least one file part is required" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestUploadFiles_PathOnlyNoFileRejected(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"path", "configs/app.conf"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFiles_PathFieldTooLargeRejected(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	longPath := strings.Repeat("a", 4097)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"path", longPath},
		{"file.txt", "content"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "path field too large" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestUploadFiles_TotalSizeEnforcedBeforePodCopy(t *testing.T) {
	build := newTestImageBuild()
	pod := newTestUploadPod()
	fix := setupUploadTest(t, build, pod)

	fix.server.limits.MaxTotalUploadSize = 5
	fix.server.limits.MaxUploadFileSize = 100

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{
		{"big.bin", "more-than-five-bytes"},
	})

	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", w.Code, w.Body.String())
	}
	if len(fix.uploaded) != 0 {
		t.Fatalf("expected no files copied to pod, got %d", len(fix.uploaded))
	}
}

func TestCopyFileToPodStreamsRawBytesWithNoTarCommand(t *testing.T) {
	executor := podExecutor{}
	content := []byte("hello\x00world\n")
	localPath := writeTempUploadFile(t, content)

	var gotNamespace, gotPodName, gotContainerName string
	var gotCmd []string
	var gotBytes []byte

	executor.newExecutor = func(
		_ *rest.Config,
		namespace, podName, containerName string,
		cmd []string,
	) (remotecommand.Executor, error) {
		gotNamespace = namespace
		gotPodName = podName
		gotContainerName = containerName
		gotCmd = append([]string(nil), cmd...)

		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, options remotecommand.StreamOptions) error {
				data, err := io.ReadAll(options.Stdin)
				if err != nil {
					return err
				}
				gotBytes = append([]byte(nil), data...)
				return nil
			},
		}, nil
	}

	err := executor.copyFileToPod(
		context.Background(),
		&rest.Config{},
		"test-ns",
		"test-pod",
		"fileserver",
		localPath,
		"/workspace/shared/configs/app.conf",
	)
	if err != nil {
		t.Fatalf("copyFileToPod returned error: %v", err)
	}

	wantCmd := []string{
		"/bin/sh",
		"-c",
		"mkdir -p \"$(dirname \"$1\")\" && tmp=\"$1.part.$$\" && cat > \"$tmp\" && chmod 0600 \"$tmp\" && mv -f \"$tmp\" \"$1\"",
		"--",
		"/workspace/shared/configs/app.conf",
	}
	if gotNamespace != "test-ns" || gotPodName != "test-pod" || gotContainerName != "fileserver" {
		t.Fatalf("unexpected exec target: namespace=%q pod=%q container=%q", gotNamespace, gotPodName, gotContainerName)
	}
	if !reflect.DeepEqual(gotCmd, wantCmd) {
		t.Fatalf("unexpected command:\n got: %#v\nwant: %#v", gotCmd, wantCmd)
	}
	if !bytes.Equal(gotBytes, content) {
		t.Fatalf("unexpected streamed bytes:\n got: %q\nwant: %q", gotBytes, content)
	}
}

func TestCopyFileToPodPropagatesStreamErrors(t *testing.T) {
	executor := podExecutor{}
	localPath := writeTempUploadFile(t, []byte("content"))

	wantErr := errors.New("stream failed")
	executor.newExecutor = func(
		_ *rest.Config,
		_, _, _ string,
		_ []string,
	) (remotecommand.Executor, error) {
		return &fakeRemoteExecutor{
			streamWithContextFn: func(_ context.Context, _ remotecommand.StreamOptions) error {
				return wantErr
			},
		}, nil
	}

	err := executor.copyFileToPod(context.Background(), &rest.Config{}, "test-ns", "test-pod", "fileserver", localPath, "/workspace/shared/file.txt")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}
}
