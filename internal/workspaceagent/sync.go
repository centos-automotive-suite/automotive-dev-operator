package workspaceagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// MaxSyncListBytes bounds a request that lists files, a sync plan or delete:
// about 200 bytes per file leaves room for a few hundred thousand files.
const MaxSyncListBytes = 64 << 20

// SyncPlanRequest is the body of POST /sync/plan: the client's files,
// relative to the working directory, each with its SHA-256 in hex.
type SyncPlanRequest struct {
	Files          map[string]string `json:"files"`
	IncludeDeleted bool              `json:"includeDeleted,omitempty"`
}

// SyncPlanResponse says which files a sync must upload, and with
// IncludeDeleted, which files only the workspace has. The build API relays it
// as it is, so its JSON matches buildcontract.SyncPlanResponse, including the
// IncludeDeleted echo.
type SyncPlanResponse struct {
	Changed        []string `json:"changed"`
	Unchanged      int      `json:"unchanged"`
	Deleted        []string `json:"deleted,omitempty"`
	IncludeDeleted bool     `json:"includeDeleted,omitempty"`
}

// PlanSync compares the client's files with the working directory. A file
// the workspace lacks, or holds with other content or as something other
// than a regular file, is changed. Symlinks are followed, even out of the
// working directory, as the CLI follows them when it hashes; the owner can
// read those files with a run anyway. A file that can't be read fails the
// plan, as does a directory that can't be listed, so a plan never guesses.
// Cancelling ctx stops the plan before its next file. A plan in progress
// keeps the workspace active.
func (a *Agent) PlanSync(ctx context.Context, req SyncPlanRequest) (SyncPlanResponse, error) {
	// With includeDeleted, an empty manifest would list every file.
	if len(req.Files) == 0 {
		return SyncPlanResponse{}, apiError(http.StatusBadRequest, "manifest is empty")
	}
	a.syncing.Add(1)
	defer a.syncing.Add(-1)
	plan := SyncPlanResponse{IncludeDeleted: req.IncludeDeleted}
	for name, want := range req.Files {
		if err := ctx.Err(); err != nil {
			return SyncPlanResponse{}, err
		}
		if err := checkName(name); err != nil {
			return SyncPlanResponse{}, err
		}
		got, err := hashFile(filepath.Join(a.workdir, filepath.FromSlash(name)))
		if err != nil {
			return SyncPlanResponse{}, err
		}
		if got != "" && got == want {
			plan.Unchanged++
		} else {
			plan.Changed = append(plan.Changed, name)
		}
	}
	slices.Sort(plan.Changed)
	if req.IncludeDeleted {
		var err error
		if plan.Deleted, err = workspaceOnly(ctx, os.DirFS(a.workdir), req.Files); err != nil {
			return SyncPlanResponse{}, err
		}
	}
	return plan, nil
}

// workspaceOnly lists the files in workdir that files lacks. Like find -type f
// -o -type l, it lists regular files and symlinks without following
// symlinked directories. It skips the staging path, which belongs to uploads
// whatever is there.
func workspaceOnly(ctx context.Context, workdir fs.FS, files map[string]string) ([]string, error) {
	var names []string
	err := fs.WalkDir(workdir, ".", func(name string, entry fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			if name == "." && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if name == syncStaging {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if kind := entry.Type(); kind.IsRegular() || kind == fs.ModeSymlink {
			if _, ok := files[name]; !ok {
				names = append(names, name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// hashFile returns the SHA-256 in hex of the file at path, following
// symlinks, or "" when there is no regular file to compare. It opens without
// blocking, since opening a FIFO for reading otherwise waits for a writer,
// and checks what it opened, so nothing can swap in a FIFO after a check.
func hashFile(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkName accepts only clean paths relative to the working directory, so
// names match the ones a listing reports and a/../b can't stand for b, and
// none in the staging directory, which uploads own.
func checkName(name string) error {
	if !fs.ValidPath(name) || name == "." || strings.ContainsRune(name, 0) {
		return apiError(http.StatusBadRequest, "invalid path %q: must be a clean path relative to the workspace source directory", name)
	}
	if name == syncStaging || strings.HasPrefix(name, syncStaging+"/") {
		return apiError(http.StatusBadRequest, "invalid path %q: %s is reserved for sync uploads", name, syncStaging)
	}
	return nil
}

// decodeFileList decodes a request that lists files into v. It must hold one
// JSON value and nothing after it, so a malformed request is never acted on
// in part.
func decodeFileList(w http.ResponseWriter, r *http.Request, v any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxSyncListBytes))
	err := decoder.Decode(v)
	if err == nil {
		if _, err = decoder.Token(); errors.Is(err, io.EOF) {
			return nil
		}
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return apiError(http.StatusRequestEntityTooLarge, "file list exceeds %d MiB", MaxSyncListBytes>>20)
	}
	return apiError(http.StatusBadRequest, "invalid JSON request")
}

func (a *Agent) handleSyncPlan(w http.ResponseWriter, r *http.Request) {
	var req SyncPlanRequest
	if err := decodeFileList(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	plan, err := a.PlanSync(r.Context(), req)
	writeResult(w, http.StatusOK, plan, err)
}
