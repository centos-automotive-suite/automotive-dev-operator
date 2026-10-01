package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/workspacemanifest"
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

const workspaceListPython = `import glob, json, os, sys
root = sys.argv[1] if len(sys.argv) > 1 else "/workspace"
real_root = os.path.realpath(root)
refs = json.loads(sys.stdin.read())
out = []
missing = []
escaped = []
def within_root(p):
    real = os.path.realpath(p)
    return real == real_root or real.startswith(real_root + os.sep)
def emit(src, dest):
    if not within_root(src):
        escaped.append(src)
        return
    out.append({"src": src, "dest": dest})
for r in refs:
    kind = r.get("kind", "path")
    abs_path = r["absPath"]
    rel_path = r.get("relPath", "")
    if kind == "glob":
        files = [m for m in glob.glob(abs_path, recursive=True) if os.path.isfile(m)]
        if not files:
            missing.append(abs_path)
            continue
        for m in files:
            emit(m, os.path.relpath(m, root))
        continue
    if os.path.isdir(abs_path):
        found = False
        for dirpath, _, filenames in os.walk(abs_path):
            for name in filenames:
                p = os.path.join(dirpath, name)
                if os.path.isfile(p):
                    found = True
                    emit(p, os.path.relpath(p, root))
        if not found:
            missing.append(abs_path)
        continue
    if os.path.isfile(abs_path):
        dest = rel_path if rel_path else os.path.relpath(abs_path, root)
        emit(abs_path, dest)
        continue
    missing.append(abs_path)
if escaped:
    sys.stderr.write("workspace files escape %s: %s\n" % (root, ", ".join(escaped)))
    sys.exit(2)
if missing:
    sys.stderr.write("missing workspace files: %s\n" % ", ".join(missing))
    sys.exit(1)
sys.stdout.write(json.dumps(out))
`

type hydrateFile struct {
	Src  string `json:"src"`
	Dest string `json:"dest"`
}

// HydrateWorkspaceForImageBuild copies workspace add_files onto the build
// upload pod (shared PVC) using the workspace-hydrate annotation.
func HydrateWorkspaceForImageBuild(ctx context.Context, restCfg *rest.Config, k8sClient client.Client, imageBuild *automotivev1alpha1.ImageBuild) error {
	return hydrateWorkspace(ctx, podExecutor{newExecutor: newPodExecExecutor}, restCfg, k8sClient, imageBuild)
}

func hydrateWorkspace(
	ctx context.Context,
	p podExecutor,
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

	files, err := p.listWorkspaceHydrateFiles(ctx, restCfg, imageBuild.Namespace, ws.Status.PodName, refs)
	if err != nil {
		return err
	}

	uploadContainer := uploadPod.Spec.Containers[0].Name
	for _, f := range files {
		cleanDest, err := validateDestPath(f.Dest)
		if err != nil {
			return permanentHydrateErrorf("workspace file %s: %w", f.Src, err)
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
		if err := p.copyFileBetweenPods(
			ctx, restCfg, imageBuild.Namespace,
			ws.Status.PodName, workspaceContainerName, f.Src,
			uploadPod.Name, uploadContainer, destPath,
		); err != nil {
			return err
		}
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

func (p podExecutor) listWorkspaceHydrateFiles(
	ctx context.Context,
	restCfg *rest.Config,
	namespace, workspacePod string,
	refs []workspacemanifest.WorkspaceHydrateRef,
) ([]hydrateFile, error) {
	payload, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := []string{"python3", "-c", workspaceListPython, workspaceFSRoot}
	if err := p.stream(ctx, restCfg, namespace, workspacePod, workspaceContainerName, cmd, bytes.NewReader(payload), &stdout, &stderr); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			err = fmt.Errorf("listing workspace files: %w (%s)", err, msg)
		} else {
			err = fmt.Errorf("listing workspace files: %w", err)
		}
		// Missing files and symlink escapes are deterministic: retrying the
		// same refs will fail the same way, so fail the build immediately.
		if strings.Contains(msg, "missing workspace files") ||
			strings.Contains(msg, "escape "+workspaceFSRoot) {
			return nil, &permanentHydrateError{err: err}
		}
		return nil, err
	}
	var files []hydrateFile
	if err := json.Unmarshal(stdout.Bytes(), &files); err != nil {
		return nil, fmt.Errorf("parsing workspace file list: %w", err)
	}
	return files, nil
}

// copyFileBetweenPods streams srcPath from the source pod to dstPath on the
// destination pod through an io.Pipe so the operator never buffers the file.
func (p podExecutor) copyFileBetweenPods(
	ctx context.Context,
	config *rest.Config,
	namespace, srcPod, srcContainer, srcPath, dstPod, dstContainer, dstPath string,
) error {
	pr, pw := io.Pipe()
	srcErrCh := make(chan error, 1)
	go func() {
		err := p.copyFileFromPodToWriter(ctx, config, namespace, srcPod, srcContainer, srcPath, pw)
		_ = pw.CloseWithError(err)
		srcErrCh <- err
	}()

	destErr := p.copyReaderToPod(ctx, config, namespace, dstPod, dstContainer, pr, dstPath)
	_ = pr.Close()
	srcErr := <-srcErrCh
	if destErr != nil {
		return fmt.Errorf("copy %s to upload pod: %w", dstPath, destErr)
	}
	if srcErr != nil {
		return fmt.Errorf("copy %s from workspace: %w", srcPath, srcErr)
	}
	return nil
}

func (p podExecutor) copyFileFromPodToWriter(
	ctx context.Context,
	config *rest.Config,
	namespace, podName, containerName, podPath string,
	w io.Writer,
) error {
	cmd := []string{"/bin/sh", "-c", "cat -- \"$1\"", "--", podPath} //nolint:goconst // matches copyFileToPod
	var stderr bytes.Buffer
	// The pod executor always advertises Stdin; send an immediate EOF so
	// cat does not hang waiting for a closed stream.
	err := p.stream(ctx, config, namespace, podName, containerName, cmd, bytes.NewReader(nil), w, &stderr)
	return wrapPodStreamError("copy from pod", err, &stderr)
}
