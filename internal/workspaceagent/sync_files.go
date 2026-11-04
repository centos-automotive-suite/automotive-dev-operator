package workspaceagent

import (
	"archive/tar"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

// maxSyncUploadBytes bounds a sync upload, and so the space its staged files
// take beside the ones they replace until they are renamed into place.
const maxSyncUploadBytes = 512 << 20

// syncUploadIdle bounds how long an upload may go without sending anything,
// so a stalled client can't hold the upload lock or keep the workspace
// active.
const syncUploadIdle = time.Minute

// syncStaging is the directory in the working directory that uploads stage
// files in before renaming them into place. The rename only works within
// one file system, and os.Root only within the working directory, so it
// lives there. Uploads replace whatever is at the path when they start and
// remove it when they finish, and New removes one an agent that died
// mid-upload left behind.
const syncStaging = ".caib-sync"

// SyncUploadRequest starts the body of POST /sync/upload, and the tar stream
// follows it: files to delete, relative to the working directory, as the
// upload applies. Its JSON matches buildcontract.SyncUploadRequest, which the
// build API relays as it is.
type SyncUploadRequest struct {
	Delete []string `json:"delete,omitempty"`
}

// SyncUploadResponse is the body of a successful POST /sync/upload.
type SyncUploadResponse struct {
	Files   int `json:"files"`
	Deleted int `json:"deleted"`
}

// SyncUpload deletes req.Delete from the working directory and unpacks a tar
// stream of regular files and symlinks into it, all or nothing. It stages the
// whole archive, then checks that no path in it is both a file and a
// directory, and that, once the deletes apply, no directory in the workspace
// stands where an entry has a file and no file, broken symlink or symlink to
// the staging directory where an entry needs a directory. Only then does it
// delete, and rename each entry into place, replacing what is there, a
// symlink included. A dropped connection, a bad entry or delete, a directory
// to delete, the size limit or a conflict therefore changes nothing; only a
// failure while applying could apply part of an upload. Nothing is written or
// deleted outside the working directory, even through a symlink. As with tar
// --no-same-owner --no-same-permissions, files belong to the agent and keep
// only their permission bits, under its umask; they keep the archive's
// modification times. Uploads run one at a time.
func (a *Agent) SyncUpload(req SyncUploadRequest, archive io.Reader) (SyncUploadResponse, error) {
	for _, name := range req.Delete {
		if err := checkName(name); err != nil {
			return SyncUploadResponse{}, err
		}
	}
	a.syncing.Add(1)
	defer a.syncing.Add(-1)
	a.uploading.Lock()
	defer a.uploading.Unlock()
	if err := os.MkdirAll(a.workdir, 0o755); err != nil {
		return SyncUploadResponse{}, err
	}
	root, err := os.OpenRoot(a.workdir)
	if err != nil {
		return SyncUploadResponse{}, err
	}
	defer func() { _ = root.Close() }()
	if err := checkDeletes(root, req.Delete); err != nil {
		return SyncUploadResponse{}, err
	}
	// A run may have left a file or a symlink at the staging path. Mkdir
	// after clearing it makes a directory of our own, which a symlink can't
	// redirect into one the cleanup below would miss.
	if err := root.RemoveAll(syncStaging); err != nil {
		return SyncUploadResponse{}, err
	}
	if err := root.Mkdir(syncStaging, 0o700); err != nil {
		return SyncUploadResponse{}, err
	}
	// Whatever an upload leaves staged goes with it.
	defer func() { _ = root.RemoveAll(syncStaging) }()
	entries, err := a.stage(root, archive)
	if err != nil {
		return SyncUploadResponse{}, err
	}
	if err := checkArchiveTree(entries); err != nil {
		return SyncUploadResponse{}, err
	}
	deletes := newRemoval(root, req.Delete)
	if err := checkConflicts(root, entries, deletes); err != nil {
		return SyncUploadResponse{}, err
	}
	deleted, err := deleteFiles(root, req.Delete)
	if err != nil {
		return SyncUploadResponse{}, err
	}
	for _, entry := range entries {
		if err := root.MkdirAll(path.Dir(entry.name), 0o755); err != nil {
			return SyncUploadResponse{}, err
		}
		if err := root.Rename(entry.temp, entry.name); err != nil {
			return SyncUploadResponse{}, err
		}
	}
	return SyncUploadResponse{Files: len(entries), Deleted: deleted}, nil
}

// stagedEntry is an archive entry written to temp in the staging directory,
// waiting to be renamed to name.
type stagedEntry struct {
	temp, name string
}

// stage writes every entry of the archive into the staging directory.
func (a *Agent) stage(root *os.Root, archive io.Reader) ([]stagedEntry, error) {
	var entries []stagedEntry
	reader := tar.NewReader(archive)
	for {
		hdr, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, a.archiveError(err)
		}
		if err := checkName(hdr.Name); err != nil {
			return nil, err
		}
		temp := path.Join(syncStaging, rand.Text())
		switch hdr.Typeflag {
		case tar.TypeReg:
			err = a.writeFile(root, temp, hdr, reader)
		case tar.TypeSymlink:
			err = root.Symlink(hdr.Linkname, temp)
		default:
			err = apiError(http.StatusBadRequest, "unsupported entry %q: only regular files and symlinks sync", hdr.Name)
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, stagedEntry{temp: temp, name: hdr.Name})
	}
}

// checkArchiveTree rejects an archive that holds a path both as a file and as
// a directory of other entries, which no workspace could take whole.
func checkArchiveTree(entries []stagedEntry) error {
	files := make(map[string]bool, len(entries))
	for _, entry := range entries {
		files[entry.name] = true
	}
	for _, entry := range entries {
		for parent := path.Dir(entry.name); parent != "."; parent = path.Dir(parent) {
			if files[parent] {
				return apiError(http.StatusBadRequest, "invalid archive: %q is both a file and a directory", parent)
			}
		}
	}
	return nil
}

// checkConflicts reports, without changing anything, every path in the
// workspace that would stop an entry from taking its place once the deletes
// apply: a directory where the entry is a file, or a file, broken symlink or
// symlink to the staging directory where the entry needs a directory.
func checkConflicts(root *os.Root, entries []stagedEntry, deletes *removal) error {
	staging, err := root.Stat(syncStaging)
	if err != nil {
		return err
	}
	var conflicts []string
	reported := map[string]bool{}
	report := func(name, what string) {
		if !reported[name] {
			reported[name] = true
			conflicts = append(conflicts, fmt.Sprintf("%q is %s", name, what))
		}
	}
	// Entries share parents, so each parent is looked at once.
	checked := map[string]bool{}
	for _, entry := range entries {
		info, err := root.Lstat(entry.name)
		if err != nil && !absent(err) {
			return err
		}
		if err == nil && info.IsDir() {
			removed, err := deletes.removes(entry.name, info)
			if err != nil {
				return err
			}
			if !removed {
				report(entry.name, "a directory in the workspace but a file in the upload")
				continue
			}
		}
		for parent := path.Dir(entry.name); parent != "." && !checked[parent]; parent = path.Dir(parent) {
			checked[parent] = true
			// What the deletes remove is out of the way, whatever it is.
			if info, err := root.Lstat(parent); err == nil {
				removed, err := deletes.removes(parent, info)
				if err != nil {
					return err
				}
				if removed {
					continue
				}
			}
			info, err := root.Stat(parent)
			if err == nil && !info.IsDir() {
				report(parent, "a file in the workspace but a directory in the upload")
				break
			}
			// The cleanup would remove what the renames put there.
			if err == nil && os.SameFile(info, staging) {
				report(parent, "a symlink to the sync staging directory in the workspace but a directory in the upload")
				break
			}
			if err != nil && !absent(err) {
				return err
			}
			// Stat follows a symlink, so a broken one looks absent.
			if err != nil {
				if _, err := root.Lstat(parent); err == nil {
					report(parent, "a broken symlink in the workspace but a directory in the upload")
					break
				}
			}
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	return apiError(http.StatusConflict, "%s; remove what is in the way from the workspace, or sync with --delete", strings.Join(conflicts, "; "))
}

// removal says what an upload's deletes remove: each deleted file, and each
// directory they empty, since the cleanup after a delete removes it.
type removal struct {
	root  *os.Root
	files map[string]bool
	dirs  map[string]bool
}

func newRemoval(root *os.Root, files []string) *removal {
	r := &removal{root: root, files: make(map[string]bool, len(files)), dirs: map[string]bool{}}
	for _, name := range files {
		r.files[name] = true
	}
	return r
}

// removes reports whether the deletes remove name, which info describes
// without following a symlink. A directory goes when everything in it does;
// an empty one stays, since the cleanup removes only the directories a delete
// empties.
func (r *removal) removes(name string, info fs.FileInfo) (bool, error) {
	if !info.IsDir() {
		return r.files[name], nil
	}
	if len(r.files) == 0 {
		return false, nil
	}
	if removed, ok := r.dirs[name]; ok {
		return removed, nil
	}
	entries, err := fs.ReadDir(r.root.FS(), name)
	if err != nil {
		return false, err
	}
	removed := len(entries) > 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return false, err
		}
		if removed, err = r.removes(path.Join(name, entry.Name()), info); err != nil {
			return false, err
		}
		if !removed {
			break
		}
	}
	r.dirs[name] = removed
	return removed, nil
}

// absent reports an error meaning nothing is at a path: neither it nor a
// parent exists, or a parent is not a directory.
func absent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func (a *Agent) writeFile(root *os.Root, name string, hdr *tar.Header, content io.Reader) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, hdr.FileInfo().Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, content); err != nil {
		_ = file.Close()
		return a.archiveError(err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.Chtimes(name, time.Time{}, hdr.ModTime)
}

// archiveError reports a failure to read the archive: past the size limit as
// a 413, a stalled client as a 408, and otherwise as a bad archive. A failed
// write passes through.
func (a *Agent) archiveError(err error) error {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return apiError(http.StatusRequestEntityTooLarge, "sync upload exceeds %d MiB", a.maxUpload>>20)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return apiError(http.StatusRequestTimeout, "sync upload sent nothing for %v", a.uploadIdle)
	}
	if _, ok := errors.AsType[*fs.PathError](err); ok {
		return err
	}
	return apiError(http.StatusBadRequest, "invalid archive: %v", err)
}

// checkDeletes rejects a directory to delete. Sync deletes files and
// symlinks, as a plan lists them, and removing a directory that holds
// something would fail after the deletes before it.
func checkDeletes(root *os.Root, files []string) error {
	for _, name := range files {
		info, err := root.Lstat(name)
		if err == nil && info.IsDir() {
			return apiError(http.StatusBadRequest, "invalid delete %q: it is a directory; sync deletes files and symlinks", name)
		}
		if err != nil && !absent(err) {
			return err
		}
	}
	return nil
}

// deleteFiles removes files from the working directory, then the parent
// directories each removal leaves empty, and returns how many it removed. A
// file already gone is skipped. A symlink is removed, not what it points to,
// and nothing outside the working directory is touched, even through a
// symlink.
func deleteFiles(root *os.Root, files []string) (int, error) {
	deleted := 0
	for _, name := range files {
		err := root.Remove(name)
		if absent(err) {
			continue
		}
		if err != nil {
			return deleted, err
		}
		deleted++
		// Remove fails on a directory that still holds something, but would
		// unlink a symlinked parent whatever its target holds.
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if info, err := root.Lstat(dir); err != nil || !info.IsDir() || root.Remove(dir) != nil {
				break
			}
		}
	}
	return deleted, nil
}

func (a *Agent) handleSyncUpload(w http.ResponseWriter, r *http.Request) {
	body := idleReader{http.MaxBytesReader(w, r.Body, a.maxUpload), http.NewResponseController(w), a.uploadIdle}
	decoder := json.NewDecoder(body)
	var req SyncUploadRequest
	if err := decoder.Decode(&req); err != nil {
		// archiveError reports the size limit and a stalled client.
		if _, ok := errors.AsType[*http.MaxBytesError](err); !ok && !errors.Is(err, os.ErrDeadlineExceeded) {
			err = apiError(http.StatusBadRequest, "invalid sync upload: the body must start with a JSON request")
		}
		writeError(w, a.archiveError(err))
		return
	}
	result, err := a.SyncUpload(req, io.MultiReader(decoder.Buffered(), body))
	writeResult(w, http.StatusOK, result, err)
}

// idleReader fails a read that waits longer than idle for the client.
type idleReader struct {
	body       io.Reader
	connection *http.ResponseController
	idle       time.Duration
}

func (r idleReader) Read(p []byte) (int, error) {
	_ = r.connection.SetReadDeadline(time.Now().Add(r.idle))
	return r.body.Read(p)
}
