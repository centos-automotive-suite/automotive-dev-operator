package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrUploadPodNotReady is returned when workspace hydrate needs the upload
// pod but it is not Running yet.
var ErrUploadPodNotReady = errors.New("upload pod not ready")

const workspaceListPython = `import glob, json, os, sys
root = "/workspace"
refs = json.loads(sys.stdin.read())
out = []
missing = []
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
            out.append({"src": m, "dest": os.path.relpath(m, root)})
        continue
    if os.path.isdir(abs_path):
        found = False
        for dirpath, _, filenames in os.walk(abs_path):
            for name in filenames:
                p = os.path.join(dirpath, name)
                if os.path.isfile(p):
                    found = True
                    out.append({"src": p, "dest": os.path.relpath(p, root)})
        if not found:
            missing.append(abs_path)
        continue
    if os.path.isfile(abs_path):
        dest = rel_path if rel_path else os.path.relpath(abs_path, root)
        out.append({"src": abs_path, "dest": dest})
        continue
    missing.append(abs_path)
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
func HydrateWorkspaceForImageBuild(
	ctx context.Context,
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
		return fmt.Errorf("kubernetes rest config is required to hydrate workspace files")
	}

	var refs []WorkspaceHydrateRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return fmt.Errorf("parsing workspace-hydrate annotation: %w", err)
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
		return fmt.Errorf("workspace-hydrate annotation set but spec.workspace is empty")
	}
	ws := &automotivev1alpha1.Workspace{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: imageBuild.Namespace, Name: wsName}, ws); err != nil {
		return fmt.Errorf("getting workspace %q: %w", wsName, err)
	}
	if ws.Status.Phase != phaseRunning || ws.Status.PodName == "" {
		return fmt.Errorf("workspace %q is not running", wsName)
	}

	files, err := listWorkspaceHydrateFiles(ctx, restCfg, imageBuild.Namespace, ws.Status.PodName, refs)
	if err != nil {
		return err
	}

	uploadContainer := uploadPod.Spec.Containers[0].Name
	for _, f := range files {
		cleanDest, err := validateDestPath(f.Dest)
		if err != nil {
			return fmt.Errorf("workspace file %s: %w", f.Src, err)
		}
		tmp, err := os.CreateTemp("", "ws-hydrate-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		_ = tmp.Close()
		if err := copyFileFromPod(ctx, restCfg, imageBuild.Namespace, ws.Status.PodName, workspaceContainerName, f.Src, tmpName); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("copy %s from workspace: %w", f.Src, err)
		}
		destPath := "/workspace/shared/" + cleanDest
		err = copyFileToPod(ctx, restCfg, imageBuild.Namespace, uploadPod.Name, uploadContainer, tmpName, destPath)
		_ = os.Remove(tmpName)
		if err != nil {
			return fmt.Errorf("copy %s to upload pod: %w", f.Dest, err)
		}
	}
	return nil
}

func listWorkspaceHydrateFiles(
	ctx context.Context,
	restCfg *rest.Config,
	namespace, workspacePod string,
	refs []WorkspaceHydrateRef,
) ([]hydrateFile, error) {
	payload, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := []string{"python3", "-c", workspaceListPython}
	if err := streamPodExec(ctx, restCfg, namespace, workspacePod, workspaceContainerName, cmd, bytes.NewReader(payload), &stdout, &stderr); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("listing workspace files: %w (%s)", err, msg)
		}
		return nil, fmt.Errorf("listing workspace files: %w", err)
	}
	var files []hydrateFile
	if err := json.Unmarshal(stdout.Bytes(), &files); err != nil {
		return nil, fmt.Errorf("parsing workspace file list: %w", err)
	}
	return files, nil
}

func streamPodExec(
	ctx context.Context,
	config *rest.Config,
	namespace, podName, containerName string,
	cmd []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	executor, err := newPodExecExecutorFn(config, namespace, podName, containerName, cmd)
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

func copyFileFromPod(ctx context.Context, config *rest.Config, namespace, podName, containerName, podPath, localPath string) error {
	f, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close temp file: %v\n", closeErr)
		}
	}()

	cmd := []string{"/bin/sh", "-c", "cat -- \"$1\"", "--", podPath} //nolint:goconst // matches copyFileToPod
	var stderr bytes.Buffer
	// newPodExecExecutorFn always advertises Stdin; send an immediate EOF so
	// cat does not hang waiting for a closed stream.
	if err := streamPodExec(ctx, config, namespace, podName, containerName, cmd, bytes.NewReader(nil), f, &stderr); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("copy from pod: %w (stderr: %s)", err, stderr.String())
		}
		return err
	}
	return nil
}
