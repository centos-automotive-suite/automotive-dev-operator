package buildapi

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"gopkg.in/yaml.v3"
)

const workspaceFSRoot = "/workspace"

const (
	hydrateKindPath = "path"
	hydrateKindGlob = "glob"
)

// WorkspaceHydrateRef is a workspace-pod path that must be copied onto the
// build's shared PVC before AIB runs.
type WorkspaceHydrateRef struct {
	Kind    string `json:"kind"`    // "path" or "glob"
	AbsPath string `json:"absPath"` // canonical /workspace/... path in the workspace pod
	RelPath string `json:"relPath"` // path relative to /workspace (upload dest)
}

// ApplyWorkspaceManifest rewrites POSIX workspace references in an AIB manifest
// so the build pod can consume them without mounting the workspace PVC.
func ApplyWorkspaceManifest(manifest, wsURL string, workspaceRunning bool) (string, []WorkspaceHydrateRef, error) {
	return applyWorkspaceManifest(manifest, wsURL, workspaceRunning)
}

// ExtractWorkspaceAddFiles rewrites /workspace add_files to relative src/...
// paths and returns hydrate refs. file:// repo URLs are left unchanged: only
// the server has the workspace pod IP and can rewrite them to HTTP.
func ExtractWorkspaceAddFiles(manifest string) (string, []WorkspaceHydrateRef, error) {
	return transformWorkspaceManifest(manifest, "", true, false)
}

// applyWorkspaceManifest rewrites POSIX workspace references in an AIB manifest
// so the build pod can consume them without mounting the workspace PVC.
//
//   - file:///workspace/... repo/file URLs become http://<workspace>/...
//   - add_files source_path / source_glob / source under /workspace become
//     relative paths (src/...) for find_manifest.sh, and are returned as
//     hydrate refs to copy onto the upload PVC
//
// The original YAML is returned unchanged when nothing needed rewriting.
func applyWorkspaceManifest(manifest, wsURL string, workspaceRunning bool) (string, []WorkspaceHydrateRef, error) {
	return transformWorkspaceManifest(manifest, wsURL, workspaceRunning, true)
}

func transformWorkspaceManifest(manifest, wsURL string, workspaceRunning, rewriteFileURLs bool) (string, []WorkspaceHydrateRef, error) {
	if strings.TrimSpace(manifest) == "" {
		return manifest, nil, nil
	}

	var root any
	if err := yaml.Unmarshal([]byte(manifest), &root); err != nil {
		return "", nil, fmt.Errorf("parsing manifest for workspace rewrite: %w", err)
	}

	var refs []WorkspaceHydrateRef
	dirty, err := rewriteWorkspaceValue(root, wsURL, rewriteFileURLs, &refs)
	if err != nil {
		return "", nil, err
	}
	if !dirty {
		return manifest, nil, nil
	}

	if rewriteFileURLs {
		needsHTTP := manifestNeedsWorkspaceHTTP(manifest)
		if needsHTTP && strings.TrimSpace(wsURL) == "" {
			return "", nil, fmt.Errorf("manifest references file://%s paths but the workspace HTTP server is not available (is the workspace running?)", workspaceFSRoot)
		}
	}
	if len(refs) > 0 && !workspaceRunning {
		return "", nil, fmt.Errorf("manifest references %s add_files paths but the workspace is not running", workspaceFSRoot)
	}

	out, err := yaml.Marshal(root)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling rewritten manifest: %w", err)
	}
	return string(out), refs, nil
}

func manifestNeedsWorkspaceHTTP(manifest string) bool {
	// Cheap pre-check on the original text so we fail closed even if the YAML
	// walk could not rewrite (e.g. empty wsURL). The walker also errors.
	return strings.Contains(manifest, "file://"+workspaceFSRoot) ||
		strings.Contains(manifest, "file:///"+strings.TrimPrefix(workspaceFSRoot, "/"))
}

func rewriteWorkspaceValue(v any, wsURL string, rewriteFileURLs bool, refs *[]WorkspaceHydrateRef) (bool, error) {
	switch val := v.(type) {
	case map[string]any:
		dirty := false
		if addFiles, ok := val["add_files"].([]any); ok {
			for i, item := range addFiles {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				changed, err := rewriteAddFileEntry(m, wsURL, rewriteFileURLs, refs)
				if err != nil {
					return false, err
				}
				if changed {
					addFiles[i] = m
					dirty = true
				}
			}
			if dirty {
				val["add_files"] = addFiles
			}
		}
		for k, child := range val {
			if k == "add_files" {
				continue
			}
			if s, ok := child.(string); ok {
				if !rewriteFileURLs {
					continue
				}
				rewritten, changed, err := rewriteWorkspaceFileURL(s, wsURL)
				if err != nil {
					return false, err
				}
				if changed {
					val[k] = rewritten
					dirty = true
				}
				continue
			}
			changed, err := rewriteWorkspaceValue(child, wsURL, rewriteFileURLs, refs)
			if err != nil {
				return false, err
			}
			if changed {
				dirty = true
			}
		}
		return dirty, nil
	case []any:
		dirty := false
		for i, item := range val {
			if s, ok := item.(string); ok {
				if !rewriteFileURLs {
					continue
				}
				rewritten, changed, err := rewriteWorkspaceFileURL(s, wsURL)
				if err != nil {
					return false, err
				}
				if changed {
					val[i] = rewritten
					dirty = true
				}
				continue
			}
			changed, err := rewriteWorkspaceValue(item, wsURL, rewriteFileURLs, refs)
			if err != nil {
				return false, err
			}
			if changed {
				dirty = true
			}
		}
		return dirty, nil
	default:
		return false, nil
	}
}

func rewriteAddFileEntry(m map[string]any, wsURL string, rewriteFileURLs bool, refs *[]WorkspaceHydrateRef) (bool, error) {
	dirty := false
	for _, key := range []string{"source_path", "source", "source_glob"} {
		s, ok := m[key].(string)
		if !ok || s == "" {
			continue
		}
		rel, abs, isWS := workspaceRelPath(s)
		if !isWS {
			continue
		}
		kind := hydrateKindPath
		if key == "source_glob" {
			kind = hydrateKindGlob
		}
		*refs = append(*refs, WorkspaceHydrateRef{
			Kind:    kind,
			AbsPath: abs,
			RelPath: rel,
		})
		m[key] = rel
		dirty = true
	}
	if s, ok := m["url"].(string); ok && rewriteFileURLs {
		rewritten, changed, err := rewriteWorkspaceFileURL(s, wsURL)
		if err != nil {
			return false, err
		}
		if changed {
			m["url"] = rewritten
			dirty = true
		}
	}
	return dirty, nil
}

func rewriteWorkspaceFileURL(s, wsURL string) (string, bool, error) {
	if !strings.HasPrefix(s, "file://") {
		return s, false, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return s, false, nil
	}
	cleaned := path.Clean(u.Path)
	if !isCleanWorkspacePath(cleaned) {
		return s, false, nil
	}
	if strings.TrimSpace(wsURL) == "" {
		return s, true, fmt.Errorf("manifest references %s but the workspace HTTP server is not available (is the workspace running?)", s)
	}
	suffix := strings.TrimPrefix(cleaned, workspaceFSRoot)
	if suffix == "" {
		suffix = "/"
	}
	return strings.TrimRight(wsURL, "/") + suffix, true, nil
}

func workspaceRelPath(p string) (rel, abs string, ok bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", "", false
	}
	cleaned := path.Clean("/" + strings.TrimLeft(p, "/"))
	if !isCleanWorkspacePath(cleaned) {
		return "", "", false
	}
	rel = strings.TrimPrefix(cleaned, workspaceFSRoot)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", "", false
	}
	return rel, cleaned, true
}

func isCleanWorkspacePath(cleaned string) bool {
	return cleaned == workspaceFSRoot || strings.HasPrefix(cleaned, workspaceFSRoot+"/")
}

// ShouldSelfCompleteUploads reports whether the controller should mark uploads
// complete because the client will not POST /uploads.
//
// A client that skipped laptop files (typically --workspace) sets
// ClientSkipsUploads. If the API also planned a workspace hydrate, wait until
// that copy finishes. Otherwise close the upload latch immediately so the
// build does not sit in Uploading forever.
func ShouldSelfCompleteUploads(ann map[string]string) bool {
	if ann == nil {
		return false
	}
	if ann[labels.UploadsComplete] == labels.ValueTrue {
		return false
	}
	if ann[labels.AwaitClientUploads] == labels.ValueTrue {
		return false
	}
	if _, hasHydrate := ann[labels.WorkspaceHydrate]; hasHydrate {
		return ann[labels.WorkspaceHydrateDone] == labels.ValueTrue
	}
	return ann[labels.ClientSkipsUploads] == labels.ValueTrue
}
