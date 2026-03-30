package buildapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
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

func TestCopyFileToPodStreamsRawBytesWithNoTarCommand(t *testing.T) {
	content := []byte("hello\x00world\n")
	localPath := writeTempUploadFile(t, content)

	originalNewPodExecExecutorFn := newPodExecExecutorFn
	t.Cleanup(func() {
		newPodExecExecutorFn = originalNewPodExecExecutorFn
	})

	var gotNamespace, gotPodName, gotContainerName string
	var gotCmd []string
	var gotBytes []byte

	newPodExecExecutorFn = func(
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

	err := copyFileToPod(
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
		"mkdir -p \"$(dirname \"$1\")\" && cat > \"$1\" && chmod 0600 \"$1\"",
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
	localPath := writeTempUploadFile(t, []byte("content"))

	originalNewPodExecExecutorFn := newPodExecExecutorFn
	t.Cleanup(func() {
		newPodExecExecutorFn = originalNewPodExecExecutorFn
	})

	wantErr := errors.New("stream failed")
	newPodExecExecutorFn = func(
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

	err := copyFileToPod(context.Background(), &rest.Config{}, "test-ns", "test-pod", "fileserver", localPath, "/workspace/shared/file.txt")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}
}
