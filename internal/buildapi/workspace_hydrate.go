package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/workspacemanifest"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent/agentconn"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrUploadPodNotReady is returned when workspace hydrate needs the upload
// pod but it is not Running yet.
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

// HydrateWorkspaceForImageBuild copies workspace add_files onto the build
// upload pod (shared PVC) using the workspace-hydrate annotation. It reads the
// files through the workspace's agent, with credentials it reads through
// agentReader.
func HydrateWorkspaceForImageBuild(ctx context.Context, restCfg *rest.Config, k8sClient client.Client, agentReader client.Reader, imageBuild *automotivev1alpha1.ImageBuild) error {
	connect := func(ctx context.Context, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		return agentconn.Connect(ctx, agentReader, ws)
	}
	return hydrateWorkspace(ctx, podExecutor{newExecutor: newPodExecExecutor}, connect, restCfg, k8sClient, imageBuild)
}

// agentConnector returns a client for a workspace's agent.
type agentConnector func(context.Context, *automotivev1alpha1.Workspace) (*workspaceagent.Client, error)

func hydrateWorkspace(
	ctx context.Context,
	p podExecutor,
	connect agentConnector,
	restCfg *rest.Config,
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
	if restCfg == nil {
		return permanentHydrateErrorf("kubernetes rest config is required to hydrate workspace files")
	}

	var refs []workspacemanifest.WorkspaceHydrateRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return permanentHydrateErrorf("parsing workspace-hydrate annotation: %w", err)
	}
	if len(refs) == 0 {
		return nil
	}

	uploadPod, err := findRunningUploadPod(ctx, k8sClient, imageBuild.Namespace, imageBuild.Name)
	if err != nil {
		return err
	}
	if uploadPod == nil {
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
		err = fmt.Errorf("listing workspace files: %w", err)
		// The agent rejects refs and reports missing files and links out of
		// the workspace with a 4xx; retrying gets the same answer.
		if apiErr, ok := errors.AsType[*workspaceagent.Error](err); ok && apiErr.Code >= 400 && apiErr.Code < 500 {
			return &permanentHydrateError{err: err}
		}
		return err
	}

	uploadContainer := uploadPod.Spec.Containers[0].Name
	for _, name := range files {
		// The user controls their workspace's agent, so check every name it
		// returns.
		if !fs.ValidPath(name) || name == "." {
			return permanentHydrateErrorf("workspace agent returned an invalid file name %q", name)
		}
		cleanDest, err := validateDestPath(name)
		if err != nil {
			return permanentHydrateErrorf("workspace file %s: %w", name, err)
		}
		destPath := "/workspace/shared/" + cleanDest
		// Skip files already copied so a retried hydrate makes forward
		// progress instead of restarting the whole transfer. copyReaderToPod
		// writes atomically, so a present file is guaranteed complete.
		exists, err := p.fileExistsOnPod(ctx, restCfg, imageBuild.Namespace, uploadPod.Name, uploadContainer, destPath)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := copyWorkspaceFile(ctx, p, agent, name, restCfg, imageBuild.Namespace, uploadPod.Name, uploadContainer, destPath); err != nil {
			return err
		}
	}
	return nil
}

// copyWorkspaceFile streams the workspace file at name from the agent to
// destPath on the upload pod, without buffering it.
func copyWorkspaceFile(
	ctx context.Context,
	p podExecutor,
	agent *workspaceagent.Client,
	name string,
	config *rest.Config,
	namespace, podName, containerName, destPath string,
) error {
	body, err := agent.OpenFile(ctx, name)
	if err != nil {
		return fmt.Errorf("copy %s from workspace: %w", name, err)
	}
	defer func() { _ = body.Close() }()
	if err := p.copyReaderToPod(ctx, config, namespace, podName, containerName, body, destPath); err != nil {
		return fmt.Errorf("copy %s to upload pod: %w", destPath, err)
	}
	return nil
}

// fileExistsOnPod reports whether path is a regular file on the pod. It uses a
// command that always exits 0 so a transient exec failure is distinguishable
// from a missing file.
func (p podExecutor) fileExistsOnPod(
	ctx context.Context,
	config *rest.Config,
	namespace, podName, containerName, podPath string,
) (bool, error) {
	cmd := []string{"/bin/sh", "-c", `[ -f "$1" ] && printf yes || printf no`, "--", podPath}
	var stdout, stderr bytes.Buffer
	if err := p.stream(ctx, config, namespace, podName, containerName, cmd, bytes.NewReader(nil), &stdout, &stderr); err != nil {
		return false, wrapPodStreamError("stat on upload pod", err, &stderr)
	}
	return strings.TrimSpace(stdout.String()) == "yes", nil
}
