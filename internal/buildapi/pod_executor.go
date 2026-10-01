package buildapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type podExecutor struct {
	newExecutor func(*rest.Config, string, string, string, []string) (remotecommand.Executor, error)
}

func newPodExecExecutor(
	config *rest.Config,
	namespace, podName, containerName string,
	cmd []string,
) (remotecommand.Executor, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	req := clientset.CoreV1().RESTClient().Post().Resource("pods").Name(podName).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, kscheme.ParameterCodec)
	return remotecommand.NewSPDYExecutor(config, http.MethodPost, req.URL())
}

func (p podExecutor) stream(
	ctx context.Context,
	config *rest.Config,
	namespace, podName, containerName string,
	cmd []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	executor, err := p.newExecutor(config, namespace, podName, containerName, cmd)
	if err != nil {
		return err
	}
	opts := remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
	return executor.StreamWithContext(ctx, opts)
}

func wrapPodStreamError(op string, err error, stderr *bytes.Buffer) error {
	if err == nil {
		return nil
	}
	if stderr.Len() > 0 {
		return fmt.Errorf("%s: %w (stderr: %s)", op, err, stderr.String())
	}
	return err
}

func (p podExecutor) copyFileToPod(ctx context.Context, config *rest.Config, namespace, podName, containerName, localPath, podPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close file: %v\n", err)
		}
	}()
	return p.copyReaderToPod(ctx, config, namespace, podName, containerName, f, podPath)
}

func (p podExecutor) copyReaderToPod(ctx context.Context, config *rest.Config, namespace, podName, containerName string, r io.Reader, podPath string) error {
	// Stream raw file bytes via stdin; the pod-side command writes them directly.
	// Uses only sh + cat (available in ubi-minimal), no tar dependency.
	// Write to a temp file and rename so an interrupted transfer never leaves a
	// truncated file at podPath (hydration skips files that already exist).
	cmd := []string{"/bin/sh", "-c",
		"mkdir -p \"$(dirname \"$1\")\" && tmp=\"$1.part.$$\" && cat > \"$tmp\" && chmod 0600 \"$tmp\" && mv -f \"$tmp\" \"$1\"",
		"--", podPath}
	var stderr bytes.Buffer
	err := p.stream(ctx, config, namespace, podName, containerName, cmd, r, io.Discard, &stderr)
	return wrapPodStreamError("copy to pod", err, &stderr)
}
