package buildapi

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/workspacemanifest"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent/agentconn"
	"github.com/klauspost/compress/zstd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrUploadPodNotReady is returned when workspace hydrate needs the upload
// pod but its agent is not ready yet.
var ErrUploadPodNotReady = errors.New("upload pod not ready")

type permanentHydrateError struct {
	err error
}

func (e *permanentHydrateError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *permanentHydrateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// IsPermanentHydrateError reports errors that will not succeed on retry
// (bad annotation, rejected path, missing files).
func IsPermanentHydrateError(err error) bool {
	var perm *permanentHydrateError
	return errors.As(err, &perm)
}

func permanentHydrateErrorf(format string, args ...any) error {
	return &permanentHydrateError{err: fmt.Errorf(format, args...)}
}

// HydrateWorkspaceForImageBuild copies workspace add_files onto the build's
// shared PVC using the workspace-hydrate annotation: it reads the files
// through the workspace's agent and writes them through the upload pod's,
// with credentials it reads through agentReader.
func HydrateWorkspaceForImageBuild(ctx context.Context, k8sClient client.Client, agentReader client.Reader, imageBuild *automotivev1alpha1.ImageBuild) error {
	connect := func(ctx context.Context, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		return agentconn.Connect(ctx, agentReader, ws)
	}
	connectUpload := func(ctx context.Context, build *automotivev1alpha1.ImageBuild) (*workspaceagent.Client, error) {
		return agentconn.ConnectUpload(ctx, agentReader, build)
	}
	return hydrateWorkspace(ctx, connect, connectUpload, k8sClient, imageBuild)
}

// agentConnector returns a client for a workspace's agent.
type agentConnector func(context.Context, *automotivev1alpha1.Workspace) (*workspaceagent.Client, error)

// uploadConnector returns a client for the agent in a build's upload pod.
type uploadConnector func(context.Context, *automotivev1alpha1.ImageBuild) (*workspaceagent.Client, error)

// hydrateWorkspace copies the build's workspace files to its upload pod in
// one upload, which the pod applies all or none of, so a retried hydrate
// starts over.
func hydrateWorkspace(
	ctx context.Context,
	connect agentConnector,
	connectUpload uploadConnector,
	k8sClient client.Client,
	imageBuild *automotivev1alpha1.ImageBuild,
) error {
	raw := ""
	if imageBuild.Annotations != nil {
		raw = imageBuild.Annotations[labels.WorkspaceHydrate]
	}
	if raw == "" {
		return nil
	}

	var refs []workspacemanifest.WorkspaceHydrateRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return permanentHydrateErrorf("parsing workspace-hydrate annotation: %w", err)
	}
	if len(refs) == 0 {
		return nil
	}

	ready, err := UploadPodReady(ctx, k8sClient, imageBuild.Namespace, imageBuild.Name)
	if err != nil {
		return err
	}
	if !ready {
		return ErrUploadPodNotReady
	}

	wsName := imageBuild.Spec.Workspace
	if wsName == "" {
		return permanentHydrateErrorf("workspace-hydrate annotation set but spec.workspace is empty")
	}
	ws := &automotivev1alpha1.Workspace{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: imageBuild.Namespace, Name: wsName}, ws); err != nil {
		return fmt.Errorf("getting workspace %q: %w", wsName, err)
	}
	if ws.Status.Phase != phaseRunning || ws.Status.PodName == "" {
		return fmt.Errorf("workspace %q is not running", wsName)
	}
	agent, err := connect(ctx, ws)
	if err != nil {
		return fmt.Errorf("connecting to workspace %q: %w", wsName, err)
	}

	fileRefs := make([]workspaceagent.FileRef, 0, len(refs))
	for _, ref := range refs {
		fileRefs = append(fileRefs, workspaceagent.FileRef{Path: ref.RelPath, Glob: ref.Kind == hydrateKindGlob})
	}
	files, err := agent.ListFiles(ctx, fileRefs)
	if err != nil {
		// The agent rejects refs and reports missing files and links out of
		// the workspace with a 4xx; retrying gets the same answer.
		return permanentOnRejection(fmt.Errorf("listing workspace files: %w", err))
	}
	for _, name := range files {
		// The user controls their workspace's agent, so check every name it
		// returns.
		if !fs.ValidPath(name) || name == "." {
			return permanentHydrateErrorf("workspace agent returned an invalid file name %q", name)
		}
	}

	uploader, err := connectUpload(ctx, imageBuild)
	if err != nil {
		return fmt.Errorf("connecting to the upload pod: %w", err)
	}
	reader, writer := io.Pipe()
	written := make(chan struct{})
	go func() {
		defer close(written)
		_ = writer.CloseWithError(writeWorkspaceFiles(ctx, writer, agent, files))
	}()
	// Whatever ends the upload stops the copy, which is over before the
	// clients go.
	defer func() {
		_ = reader.Close()
		<-written
	}()
	resp, err := uploader.SyncUpload(ctx, reader)
	if err != nil {
		// The upload pod rejects names a build can't take, and files past
		// the limits, with a 4xx.
		return permanentOnRejection(fmt.Errorf("copying workspace files to the upload pod: %w", err))
	}
	_ = resp.Body.Close()
	return nil
}

// permanentOnRejection makes err permanent when an agent rejected the request,
// which a retry would send again, rather than timing out on it.
func permanentOnRejection(err error) error {
	if apiErr, ok := errors.AsType[*workspaceagent.Error](err); ok &&
		apiErr.Code >= 400 && apiErr.Code < 500 && apiErr.Code != http.StatusRequestTimeout {
		return &permanentHydrateError{err: err}
	}
	return err
}

// writeWorkspaceFiles writes the body of an upload of the workspace files
// named to w, reading each from the workspace's agent as the upload goes.
func writeWorkspaceFiles(ctx context.Context, w io.Writer, agent *workspaceagent.Client, files []string) error {
	head, err := json.Marshal(buildcontract.SyncUploadRequest{})
	if err != nil {
		return err
	}
	if _, err := w.Write(head); err != nil {
		return err
	}
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)
	for _, name := range files {
		if err = writeWorkspaceFile(ctx, tw, agent, name); err != nil {
			break
		}
	}
	if err == nil {
		err = tw.Close()
	}
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	return err
}

func writeWorkspaceFile(ctx context.Context, tw *tar.Writer, agent *workspaceagent.Client, name string) error {
	body, size, err := agent.OpenFile(ctx, name)
	if err != nil {
		return fmt.Errorf("copy %s from workspace: %w", name, err)
	}
	defer func() { _ = body.Close() }()
	// Exec wrote hydrated files as new files, 0644 under the upload pod's
	// umask.
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o644}); err != nil {
		return err
	}
	if _, err := io.Copy(tw, body); err != nil {
		return fmt.Errorf("copy %s from workspace: %w", name, err)
	}
	return nil
}
