package buildcmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

const execStreamPreamble = "Waiting for logs...\n"

// materializeWorkspaceFiles rewrites /workspace add_files to relative paths and
// copies those files out of the workspace via exec so they can be POSTed to
// /uploads. That closes the Uploading latch on operators that do not hydrate.
// file:// repo URLs are left for the server, which rewrites them using the
// workspace pod IP.
func (h *Handler) materializeWorkspaceFiles(
	ctx context.Context,
	api *buildapiclient.Client,
	workspace, manifest string,
) (string, []map[string]string, error) {
	rewritten, refs, err := buildapitypes.ExtractWorkspaceAddFiles(manifest)
	if err != nil {
		return "", nil, err
	}
	if len(refs) == 0 {
		return rewritten, nil, nil
	}

	dir, err := os.MkdirTemp("", "caib-ws-files-*")
	if err != nil {
		return "", nil, err
	}

	out := make([]map[string]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Kind != "path" {
			return "", nil, fmt.Errorf("workspace %s %q: only source_path is copied by caib; source_glob requires operator hydrate", ref.Kind, ref.AbsPath)
		}
		data, err := fetchWorkspaceFile(ctx, api, workspace, ref.AbsPath)
		if err != nil {
			return "", nil, err
		}
		local := filepath.Join(dir, filepath.FromSlash(ref.RelPath))
		if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
			return "", nil, err
		}
		if err := os.WriteFile(local, data, 0o600); err != nil {
			return "", nil, err
		}
		out = append(out, map[string]string{
			"source_path": local,
			"dest":        ref.RelPath,
		})
	}
	return rewritten, out, nil
}

func fetchWorkspaceFile(ctx context.Context, api *buildapiclient.Client, workspace, absPath string) ([]byte, error) {
	quoted := "'" + strings.ReplaceAll(absPath, "'", `'\''`) + "'"
	body, err := api.ExecWorkspace(ctx, workspace, buildapitypes.WorkspaceExecRequest{
		Command: "cat -- " + quoted,
	})
	if err != nil {
		return nil, fmt.Errorf("read %s from workspace %q: %w", absPath, workspace, err)
	}
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read %s from workspace %q: %w", absPath, workspace, err)
	}
	data, err := stripExecStream(raw)
	if err != nil {
		return nil, fmt.Errorf("read %s from workspace %q: %w", absPath, workspace, err)
	}
	return data, nil
}

func stripExecStream(b []byte) ([]byte, error) {
	b = bytes.TrimPrefix(b, []byte(execStreamPreamble))
	if msg, failed := execFailedTrailer(b); failed {
		return nil, fmt.Errorf("%s", msg)
	}
	return b, nil
}

// execFailedTrailer reports the server's exec-failure line only when it is the
// last line of the stream. Scanning the whole body would treat those bytes in
// a binary add_files payload as a hard error.
func execFailedTrailer(b []byte) (string, bool) {
	const mark = "[exec failed:"
	trimmed := bytes.TrimRight(b, "\n\r\t ")
	line := trimmed
	if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
		line = trimmed[i+1:]
	}
	if !bytes.HasPrefix(line, []byte(mark)) || !bytes.HasSuffix(line, []byte("]")) {
		return "", false
	}
	return string(line), true
}
