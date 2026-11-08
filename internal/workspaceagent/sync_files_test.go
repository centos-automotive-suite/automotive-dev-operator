package workspaceagent

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var syncedAt = time.Date(2020, 1, 2, 3, 4, 5, 6789, time.UTC)

// tarFile and tarLink describe entries the way the CLI writes them, with PAX
// headers, which keep modification times to the nanosecond.
func tarFile(name, content string, mode int64) (*tar.Header, string) {
	return &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(content)), ModTime: syncedAt, Uid: 4242, Gid: 4242, Format: tar.FormatPAX}, content
}

func tarLink(name, target string) (*tar.Header, string) {
	return &tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777, ModTime: syncedAt, Format: tar.FormatPAX}, ""
}

type tarEntry struct {
	hdr     *tar.Header
	content string
}

func entry(hdr *tar.Header, content string) tarEntry { return tarEntry{hdr, content} }

func archive(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(e.hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// deleteHeader is the request that starts an upload's body.
func deleteHeader(t *testing.T, names []string) string {
	t.Helper()
	data, err := json.Marshal(SyncUploadRequest{Delete: names})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// deleteOnly sends an upload with no files that deletes names.
func deleteOnly(t *testing.T, a *Agent, names ...string) (SyncUploadResponse, error) {
	t.Helper()
	return a.SyncUpload(SyncUploadRequest{Delete: names}, bytes.NewReader(archive(t)))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// noTempFiles fails if an upload left its staging directory in dir.
func noTempFiles(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, syncStaging)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the staging directory is still there: %v", err)
	}
}

// notApplied fails if a failed upload applied any of names: an upload
// changes nothing unless all of it arrives and fits.
func notApplied(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was applied from a failed upload: %v", name, err)
		}
	}
}

func wantBadRequest(t *testing.T, what string, err error) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusBadRequest {
		t.Errorf("%s: err = %v, want a 400", what, err)
	}
}

func TestSyncUploadWritesFilesAndSymlinks(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "old", "link": "a regular file where the client has a symlink"})

	result, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t,
		entry(tarFile("a.txt", "new", 0o644)),
		entry(tarFile("dir/run.sh", "#!/bin/sh", 0o4755)),
		entry(tarLink("link", "a.txt")),
	)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 3 {
		t.Errorf("files = %d, want 3", result.Files)
	}
	if got := readFile(t, filepath.Join(a.workdir, "a.txt")); got != "new" {
		t.Errorf("a.txt = %q, want new", got)
	}
	if target, err := os.Readlink(filepath.Join(a.workdir, "link")); err != nil || target != "a.txt" {
		t.Errorf("link = %q, %v; want a symlink to a.txt", target, err)
	}
	info, err := os.Stat(filepath.Join(a.workdir, "dir/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// Ownership and special bits in the archive come from the client's machine.
	if info.Mode()&0o100 == 0 || info.Mode()&os.ModeSetuid != 0 {
		t.Errorf("run.sh mode = %v, want executable without setuid", info.Mode())
	}
	if !info.ModTime().Equal(syncedAt) {
		t.Errorf("run.sh mtime = %v, want %v from the archive", info.ModTime(), syncedAt)
	}
	noTempFiles(t, a.workdir)
}

// A file synced and left alone plans as unchanged in the next sync: the
// upload keeps what a plan compares.
func TestSyncUploadKeepsWhatAPlanCompares(t *testing.T) {
	a := newTestAgent(t)
	client := t.TempDir()
	writeTree(t, client, map[string]string{"a.txt": "content"})
	chtimes(t, filepath.Join(client, "a.txt"), syncedAt)
	if err := os.Symlink("a.txt", filepath.Join(client, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t,
		entry(tarFile("a.txt", "content", 0o644)),
		entry(tarLink("link", "a.txt")),
	))); err != nil {
		t.Fatal(err)
	}

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{
		"a.txt": version(t, filepath.Join(client, "a.txt")),
		"link":  version(t, filepath.Join(client, "link")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changed) != 0 || plan.Unchanged != 2 {
		t.Errorf("plan = %+v, want both unchanged", plan)
	}
}

func TestSyncUploadCreatesTheWorkdir(t *testing.T) {
	a := newTestAgent(t)
	a.workdir = filepath.Join(t.TempDir(), "absent")
	if _, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("a.txt", "a", 0o644))))); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(a.workdir, "a.txt")); got != "a" {
		t.Errorf("a.txt = %q, want a", got)
	}
}

// A file replaces a symlink at its path, as tar does, rather than writing
// through it.
func TestSyncUploadReplacesASymlink(t *testing.T) {
	a := newTestAgent(t)
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(a.workdir, "out")); err != nil {
		t.Fatal(err)
	}

	if _, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("out", "new", 0o644))))); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, outside); got != "keep" {
		t.Errorf("the symlink's target = %q, want it untouched", got)
	}
	if info, err := os.Lstat(filepath.Join(a.workdir, "out")); err != nil || !info.Mode().IsRegular() {
		t.Errorf("out = %v, %v; want a regular file", info, err)
	}
}

func TestSyncUploadStaysInTheWorkdir(t *testing.T) {
	a := newTestAgent(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(a.workdir, "escape")); err != nil {
		t.Fatal(err)
	}

	upload := archive(t, entry(tarFile("ok.txt", "ok", 0o644)), entry(tarFile("escape/x", "x", 0o644)))
	if _, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(upload)); err == nil {
		t.Error("an upload wrote through a symlink out of the workdir")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Errorf("the directory outside holds %v, want nothing", entries)
	}
	notApplied(t, a.workdir, "ok.txt")
	noTempFiles(t, a.workdir)
}

func TestSyncUploadRejectsInvalidNames(t *testing.T) {
	a := newTestAgent(t)
	for _, name := range []string{"../escape", "/etc/passwd", "a/../b", ".", ".caib-sync", ".caib-sync/x"} {
		upload := archive(t, entry(tarFile("ok.txt", "ok", 0o644)), entry(tarFile(name, "x", 0o644)))
		_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(upload))
		wantBadRequest(t, fmt.Sprintf("%q", name), err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(a.workdir), "escape")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("../escape was written: %v", err)
	}
	notApplied(t, a.workdir, "ok.txt")
}

// The CLI sends only regular files and symlinks, so nothing else may create
// hard links, devices or FIFOs in the workspace.
func TestSyncUploadRejectsOtherEntryTypes(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "a"})
	for _, typ := range []byte{tar.TypeLink, tar.TypeFifo, tar.TypeChar, tar.TypeDir} {
		hdr := &tar.Header{Typeflag: typ, Name: "other", Linkname: "a.txt", Mode: 0o644, ModTime: syncedAt}
		_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("ok.txt", "ok", 0o644)), entry(hdr, ""))))
		wantBadRequest(t, fmt.Sprintf("type %q", typ), err)
	}
	notApplied(t, a.workdir, "other", "ok.txt")
}

// An upload cut short, say by a dropped connection, leaves the workspace as
// it was, so nothing can build from a mix of old and new files.
func TestSyncUploadAppliesNothingWhenCutShort(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"b.txt": "old"})
	content := strings.Repeat("b", 100)
	full := archive(t, entry(tarFile("a.txt", "new", 0o644)), entry(tarFile("b.txt", content, 0o644)))
	// All of a.txt, b.txt's header, then 10 of its bytes.
	cut := full[:bytes.Index(full, []byte(content))+10]

	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(cut))
	wantBadRequest(t, "a cut archive", err)
	notApplied(t, a.workdir, "a.txt")
	if got := readFile(t, filepath.Join(a.workdir, "b.txt")); got != "old" {
		t.Errorf("b.txt = %q, want the workspace's copy", got)
	}
	noTempFiles(t, a.workdir)
}

// wantConflict expects a 409 that names the path in the way and how to clear
// it.
func wantConflict(t *testing.T, err error, path string) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusConflict ||
		!strings.Contains(apiErr.Message, fmt.Sprintf("%q", path)) || !strings.Contains(apiErr.Message, "--delete") {
		t.Errorf("err = %v, want a 409 naming %q and --delete", err, path)
	}
}

func TestSyncUploadReportsADirectoryWhereTheUploadHasAFile(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"d/inner": "x"})
	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("ok.txt", "ok", 0o644)), entry(tarFile("d", "file", 0o644)))))
	wantConflict(t, err, "d")
	if got := readFile(t, filepath.Join(a.workdir, "d/inner")); got != "x" {
		t.Errorf("d/inner = %q, want it kept", got)
	}
	notApplied(t, a.workdir, "ok.txt")
	noTempFiles(t, a.workdir)
}

func TestSyncUploadReportsAFileWhereTheUploadHasADirectory(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"foo": "a file"})
	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("ok.txt", "ok", 0o644)), entry(tarFile("foo/bar/baz", "x", 0o644)))))
	wantConflict(t, err, "foo")
	if got := readFile(t, filepath.Join(a.workdir, "foo")); got != "a file" {
		t.Errorf("foo = %q, want it kept", got)
	}
	notApplied(t, a.workdir, "ok.txt")
	noTempFiles(t, a.workdir)
}

// A broken symlink where the upload needs a directory is in the way too.
// Creating the directory would fail on the link right above an entry, or
// create the link's target further up.
func TestSyncUploadReportsABrokenSymlinkWhereTheUploadHasADirectory(t *testing.T) {
	a := newTestAgent(t)
	for name, target := range map[string]string{"d": "missing", "a": "gone"} {
		if err := os.Symlink(target, filepath.Join(a.workdir, name)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t,
		entry(tarFile("ok.txt", "ok", 0o644)),
		entry(tarFile("d/f", "f", 0o644)),
		entry(tarFile("a/b/f", "f", 0o644)),
	)))
	wantConflict(t, err, "d")
	wantConflict(t, err, "a")
	notApplied(t, a.workdir, "ok.txt", "missing", "gone")
	noTempFiles(t, a.workdir)
}

// A symlink to the staging directory would land files there, where the
// cleanup removes them after the upload reports success, so it conflicts,
// however the link reaches it.
func TestSyncUploadReportsASymlinkToTheStagingDirectory(t *testing.T) {
	a := newTestAgent(t)
	if err := os.Mkdir(filepath.Join(a.workdir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"s": syncStaging, "t": "x/../" + syncStaging} {
		if err := os.Symlink(target, filepath.Join(a.workdir, name)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t,
		entry(tarFile("ok.txt", "ok", 0o644)),
		entry(tarFile("s/f", "f", 0o644)),
		entry(tarFile("t/u/f", "f", 0o644)),
	)))
	wantConflict(t, err, "s")
	wantConflict(t, err, "t")
	notApplied(t, a.workdir, "ok.txt")
	noTempFiles(t, a.workdir)
}

// Every conflict is checked before anything changes, so one error names them
// all, each path once.
func TestSyncUploadReportsEveryConflictAtOnce(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"d/inner": "x", "foo": "a file"})
	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t,
		entry(tarFile("ok.txt", "ok", 0o644)),
		entry(tarFile("d", "file", 0o644)),
		entry(tarFile("foo/a", "a", 0o644)),
		entry(tarFile("foo/b/c", "c", 0o644)),
	)))
	wantConflict(t, err, "d")
	wantConflict(t, err, "foo")
	if err != nil && strings.Count(err.Error(), `"foo"`) != 1 {
		t.Errorf("err = %v, want foo named once", err)
	}
	notApplied(t, a.workdir, "ok.txt")
	noTempFiles(t, a.workdir)
}

// An archive that holds a path both as a file and as a directory of other
// entries can't be applied whole, in whichever order it lists them.
func TestSyncUploadRejectsAPathThatIsAFileAndADirectory(t *testing.T) {
	a := newTestAgent(t)
	for _, entries := range [][]tarEntry{
		{entry(tarFile("ok.txt", "ok", 0o644)), entry(tarFile("d", "file", 0o644)), entry(tarFile("d/f", "f", 0o644))},
		{entry(tarFile("ok.txt", "ok", 0o644)), entry(tarFile("d/f", "f", 0o644)), entry(tarFile("d", "file", 0o644))},
	} {
		_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entries...)))
		wantBadRequest(t, fmt.Sprintf("d as a file and a directory, %s first", entries[1].hdr.Name), err)
		notApplied(t, a.workdir, "ok.txt", "d")
	}
	noTempFiles(t, a.workdir)
}

// A run can leave anything at the staging path. An upload replaces it rather
// than failing on a file, or staging through a symlink into a directory it
// won't clear.
func TestSyncUploadReplacesWhatIsAtTheStagingPath(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{syncStaging: "a file"})
	if _, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("a.txt", "a", 0o644))))); err != nil {
		t.Fatalf("with a file at the staging path: %v", err)
	}
	noTempFiles(t, a.workdir)

	if err := os.Mkdir(filepath.Join(a.workdir, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(a.workdir, syncStaging)); err != nil {
		t.Fatal(err)
	}
	fifo := &tar.Header{Typeflag: tar.TypeFifo, Name: "fifo", Mode: 0o644, ModTime: syncedAt}
	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("ok.txt", "ok", 0o644)), entry(fifo, ""))))
	wantBadRequest(t, "a fifo", err)
	if left, err := os.ReadDir(filepath.Join(a.workdir, "elsewhere")); err != nil || len(left) != 0 {
		t.Errorf("elsewhere holds %v, %v; want nothing staged there", left, err)
	}
	noTempFiles(t, a.workdir)
}

// An agent that died mid-upload leaves its staging directory behind, so the
// next one clears it before anything can read it as part of the tree.
func TestNewClearsAnInterruptedUpload(t *testing.T) {
	workdir := t.TempDir()
	writeTree(t, workdir, map[string]string{syncStaging + "/partial": "half", "kept.txt": "kept"})
	if _, err := New(filepath.Join(t.TempDir(), "runs"), workdir, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	noTempFiles(t, workdir)
	if got := readFile(t, filepath.Join(workdir, "kept.txt")); got != "kept" {
		t.Errorf("kept.txt = %q, want it kept", got)
	}
}

// Uploads share the staging directory, so one finishing must not remove it
// from under another: they run one at a time.
func TestSyncUploadsRunOneAtATime(t *testing.T) {
	a := newTestAgent(t)
	a.procDir, a.ptsDir = t.TempDir(), t.TempDir()
	first := archive(t, entry(tarFile("first.txt", "first", 0o644)))
	reader, writer := io.Pipe()
	firstDone := make(chan error, 1)
	go func() {
		_, err := a.SyncUpload(SyncUploadRequest{}, reader)
		firstDone <- err
	}()
	// Send the header and part of the content, so the first upload is mid-file.
	if _, err := writer.Write(first[:512+2]); err != nil {
		t.Fatal(err)
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("second.txt", "second", 0o644)))))
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("the second upload finished (%v) while the first was in progress", err)
	case <-time.After(100 * time.Millisecond):
	}
	// Both keep the workspace active, the waiting one included.
	if activity, err := a.Activity(); err != nil || activity.Syncs != 2 {
		t.Errorf("activity = %+v, %v; want 2 syncs", activity, err)
	}

	go func() {
		_, _ = writer.Write(first[512+2:])
		_ = writer.Close()
	}()
	for _, done := range []chan error{firstDone, secondDone} {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	noTempFiles(t, a.workdir)
}

func TestSyncUploadRejectsAnOversizedBody(t *testing.T) {
	a := newTestAgent(t)
	a.maxUpload = 1 << 20
	body := archive(t, entry(tarFile("small.txt", "small", 0o644)), entry(tarFile("big", strings.Repeat("x", 2<<20), 0o644)))
	req := httptest.NewRequest(http.MethodPost, "/sync/upload", io.MultiReader(strings.NewReader("{}"), bytes.NewReader(body)))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	a.Handler("secret", nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "1 MiB") {
		t.Errorf("response = %d %s, want a 413 naming the limit", rec.Code, rec.Body.String())
	}
	notApplied(t, a.workdir, "small.txt", "big")
	noTempFiles(t, a.workdir)
}

func TestSyncUploadDeleteRemovesFilesAndEmptyParents(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{
		"a/b/c.txt":  "c",
		"a/keep.txt": "keep",
		"x/y/z.txt":  "z",
		"notes..old": "dots in a name are not traversal",
	})
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(a.workdir, "link")); err != nil {
		t.Fatal(err)
	}

	result, err := deleteOnly(t, a, "a/b/c.txt", "x/y/z.txt", "link", "notes..old", "missing.txt")
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 4 {
		t.Errorf("deleted = %d, want 4", result.Deleted)
	}
	for _, gone := range []string{"a/b", "x", "link", "notes..old"} {
		if _, err := os.Lstat(filepath.Join(a.workdir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v, want it removed", gone, err)
		}
	}
	if got := readFile(t, filepath.Join(a.workdir, "a/keep.txt")); got != "keep" {
		t.Errorf("a/keep.txt = %q, want it kept", got)
	}
	if got := readFile(t, outside); got != "keep" {
		t.Errorf("the symlink's target = %q, want it kept", got)
	}
}

func TestSyncUploadDeleteRejectsInvalidPaths(t *testing.T) {
	a := newTestAgent(t)
	for _, name := range []string{"../escape", "/etc/passwd", "", "a/../../b", ".", "a/../b", "a//b", "a/", "a\x00b", ".caib-sync/x"} {
		_, err := deleteOnly(t, a, name)
		wantBadRequest(t, fmt.Sprintf("%q", name), err)
	}
}

// A file under a path that is now a file is already gone, and doesn't stop
// the rest of the delete.
func TestSyncUploadDeleteSkipsAFileUnderAFile(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"d": "now a file", "x": "x"})
	result, err := deleteOnly(t, a, "d/old", "x")
	if err != nil || result.Deleted != 1 {
		t.Errorf("result = %+v, %v; want x deleted", result, err)
	}
	if _, err := os.Lstat(filepath.Join(a.workdir, "x")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("x is still there: %v", err)
	}
}

// Removing a symlink would not leave its parent empty, so a symlinked parent
// stays, whatever its target still holds.
func TestSyncUploadDeleteKeepsASymlinkedParent(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"real/a": "a", "real/b": "b"})
	if err := os.Symlink("real", filepath.Join(a.workdir, "link")); err != nil {
		t.Fatal(err)
	}
	result, err := deleteOnly(t, a, "link/a")
	if err != nil || result.Deleted != 1 {
		t.Errorf("result = %+v, %v; want link/a deleted", result, err)
	}
	if _, err := os.Lstat(filepath.Join(a.workdir, "link")); err != nil {
		t.Errorf("the symlink was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(a.workdir, "real", "b")); err != nil {
		t.Errorf("real/b is gone: %v", err)
	}
}

func TestSyncUploadDeleteWithoutAWorkdirDeletesNothing(t *testing.T) {
	a := newTestAgent(t)
	a.workdir = filepath.Join(t.TempDir(), "absent")
	result, err := deleteOnly(t, a, "a.txt")
	if err != nil || result.Deleted != 0 {
		t.Errorf("result = %+v, %v; want nothing deleted", result, err)
	}
}

func TestSyncUploadDeleteStaysInTheWorkdir(t *testing.T) {
	a := newTestAgent(t)
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"x": "x"})
	if err := os.Symlink(outside, filepath.Join(a.workdir, "escape")); err != nil {
		t.Fatal(err)
	}

	if _, err := deleteOnly(t, a, "escape/x"); err == nil {
		t.Error("a delete went through a symlink out of the workdir")
	}
	if got := readFile(t, filepath.Join(outside, "x")); got != "x" {
		t.Errorf("the file outside = %q, want it kept", got)
	}
}

// A client that stops sending must not hold the upload lock, or keep the
// workspace active, for as long as its connection stays open.
func TestSyncUploadGivesUpOnAStalledClient(t *testing.T) {
	a := newTestAgent(t)
	a.uploadIdle = 50 * time.Millisecond
	// HTTP/2 over TLS, as the build API calls the agent.
	server := httptest.NewUnstartedServer(a.Handler("secret", nil))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close() })
	go func() {
		// The header and one byte of content, then nothing.
		_, _ = writer.Write(append([]byte("{}"), archive(t, entry(tarFile("a.txt", "abc", 0o644)))[:512+1]...))
	}()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/sync/upload", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	stalled := make(chan *http.Response, 1)
	go func() {
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Error(err)
		}
		stalled <- resp
	}()

	next := make(chan error, 1)
	go func() {
		// Let the stalled upload take the lock first.
		time.Sleep(20 * time.Millisecond)
		_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("b.txt", "b", 0o644)))))
		next <- err
	}()
	select {
	case err := <-next:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled upload still holds the lock")
	}
	if _, err := os.Lstat(filepath.Join(a.workdir, "a.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("part of the stalled upload landed: %v", err)
	}
	if resp := <-stalled; resp != nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusRequestTimeout {
			t.Errorf("stalled client got %s %s, want an HTTP/2 408", resp.Proto, resp.Status)
		}
	}
}

// Whatever follows the request is the archive, so garbage after it fails the
// upload, and with it the deletes.
func TestSyncUploadRejectsGarbageAfterTheRequest(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "a"})
	req := httptest.NewRequest(http.MethodPost, "/sync/upload", strings.NewReader(`{"delete":["a.txt"]}garbage`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	a.Handler("secret", nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("response = %d %s, want a 400", rec.Code, rec.Body.String())
	}
	if got := readFile(t, filepath.Join(a.workdir, "a.txt")); got != "a" {
		t.Errorf("a.txt = %q, want it kept", got)
	}
}

// An upload that doesn't start with its request is rejected whole.
func TestSyncUploadRequiresTheRequest(t *testing.T) {
	a := newTestAgent(t)
	req := httptest.NewRequest(http.MethodPost, "/sync/upload", bytes.NewReader(archive(t, entry(tarFile("a.txt", "a", 0o644)))))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	a.Handler("secret", nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("response = %d %s, want a 400", rec.Code, rec.Body.String())
	}
	notApplied(t, a.workdir, "a.txt")
}

// The request and the archive arrive as one body, the way the build API
// relays it.
func TestSyncUploadOverHTTPDeletesAndUploads(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"old.txt": "old"})
	body := io.MultiReader(strings.NewReader(`{"delete":["old.txt"]}`), bytes.NewReader(archive(t, entry(tarFile("new.txt", "new", 0o644)))))
	req := httptest.NewRequest(http.MethodPost, "/sync/upload", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	a.Handler("secret", nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":1`) {
		t.Errorf("response = %d %s, want a 200 with one file deleted", rec.Code, rec.Body.String())
	}
	if got := readFile(t, filepath.Join(a.workdir, "new.txt")); got != "new" {
		t.Errorf("new.txt = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(a.workdir, "old.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("old.txt is still there: %v", err)
	}
}

// An upload's deletes apply with its files.
func TestSyncUploadAppliesDeletesWithTheFiles(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"old.txt": "old", "keep.txt": "keep"})
	result, err := a.SyncUpload(SyncUploadRequest{Delete: []string{"old.txt"}},
		bytes.NewReader(archive(t, entry(tarFile("new.txt", "new", 0o644)))))
	if err != nil || result != (SyncUploadResponse{Files: 1, Deleted: 1}) {
		t.Fatalf("result = %+v, %v; want one file uploaded and one deleted", result, err)
	}
	if _, err := os.Lstat(filepath.Join(a.workdir, "old.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("old.txt is still there: %v", err)
	}
	for name, want := range map[string]string{"new.txt": "new", "keep.txt": "keep"} {
		if got := readFile(t, filepath.Join(a.workdir, name)); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// An upload that fails deletes nothing, so a sync with --delete never leaves
// the workspace without both its stale and its new files.
func TestSyncUploadThatFailsDeletesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		deletes []string
		archive func(t *testing.T) []byte
	}{
		"a conflict": {[]string{"old.txt"}, func(t *testing.T) []byte {
			return archive(t, entry(tarFile("dir", "file", 0o644)))
		}},
		"an invalid archive": {[]string{"old.txt"}, func(t *testing.T) []byte {
			return []byte("not a tar archive at all, but long enough to read a header from it")
		}},
		"an invalid delete": {[]string{"old.txt", "../escape"}, func(t *testing.T) []byte { return archive(t) }},
		"too large": {[]string{"old.txt"}, func(t *testing.T) []byte {
			return archive(t, entry(tarFile("big", strings.Repeat("x", 2<<20), 0o644)))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestAgent(t)
			a.maxUpload = 1 << 20
			writeTree(t, a.workdir, map[string]string{"old.txt": "old", "dir/inner": "x"})
			req := httptest.NewRequest(http.MethodPost, "/sync/upload",
				io.MultiReader(strings.NewReader(deleteHeader(t, tc.deletes)), bytes.NewReader(tc.archive(t))))
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			a.Handler("secret", nil).ServeHTTP(rec, req)
			if rec.Code < 400 {
				t.Errorf("response = %d %s, want a failure", rec.Code, rec.Body.String())
			}
			if got := readFile(t, filepath.Join(a.workdir, "old.txt")); got != "old" {
				t.Errorf("old.txt = %q, want it kept", got)
			}
			noTempFiles(t, a.workdir)
		})
	}
}

// A path that changed from a directory to a file replaces the directory when
// the upload's deletes empty it.
func TestSyncUploadReplacesADirectoryItsDeletesEmpty(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"foo/a": "a", "foo/sub/b": "b"})
	_, err := a.SyncUpload(SyncUploadRequest{Delete: []string{"foo/a", "foo/sub/b"}},
		bytes.NewReader(archive(t, entry(tarFile("foo", "now a file", 0o644)))))
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(a.workdir, "foo")); got != "now a file" {
		t.Errorf("foo = %q", got)
	}
}

// A directory the deletes don't empty still stands where the upload has a
// file: one holding other files, or an empty directory, which the cleanup
// after a delete leaves.
func TestSyncUploadReportsADirectoryItsDeletesLeave(t *testing.T) {
	for name, extra := range map[string]string{"another file": "foo/keep", "an empty directory": "foo/empty/"} {
		t.Run(name, func(t *testing.T) {
			a := newTestAgent(t)
			writeTree(t, a.workdir, map[string]string{"foo/a": "a"})
			if strings.HasSuffix(extra, "/") {
				if err := os.Mkdir(filepath.Join(a.workdir, extra), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				writeTree(t, a.workdir, map[string]string{extra: "x"})
			}
			_, err := a.SyncUpload(SyncUploadRequest{Delete: []string{"foo/a"}},
				bytes.NewReader(archive(t, entry(tarFile("foo", "now a file", 0o644)))))
			wantConflict(t, err, "foo")
			if got := readFile(t, filepath.Join(a.workdir, "foo/a")); got != "a" {
				t.Errorf("foo/a = %q, want it kept", got)
			}
		})
	}
}

// A path that changed from a file, or a broken symlink, to a directory takes
// the upload when the deletes remove what is there.
func TestSyncUploadReplacesWhatItsDeletesRemoveWithADirectory(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"file": "was a file"})
	if err := os.Symlink("missing", filepath.Join(a.workdir, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := a.SyncUpload(SyncUploadRequest{Delete: []string{"file", "link"}}, bytes.NewReader(archive(t,
		entry(tarFile("file/inner", "inner", 0o644)),
		entry(tarFile("link/inner", "inner", 0o644)),
	)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file/inner", "link/inner"} {
		if got := readFile(t, filepath.Join(a.workdir, name)); got != "inner" {
			t.Errorf("%s = %q", name, got)
		}
	}
}

// Sync deletes files and symlinks, as the plan lists them. A directory to
// delete is rejected before anything applies: removing a full one would fail
// after earlier deletes.
func TestSyncUploadRejectsADirectoryToDelete(t *testing.T) {
	for _, dir := range []string{"full", "empty"} {
		t.Run(dir, func(t *testing.T) {
			a := newTestAgent(t)
			writeTree(t, a.workdir, map[string]string{"old.txt": "old", "full/inner": "x"})
			if err := os.Mkdir(filepath.Join(a.workdir, "empty"), 0o755); err != nil {
				t.Fatal(err)
			}
			_, err := a.SyncUpload(SyncUploadRequest{Delete: []string{"old.txt", dir}},
				bytes.NewReader(archive(t, entry(tarFile("new.txt", "new", 0o644)))))
			wantBadRequest(t, dir, err)
			if got := readFile(t, filepath.Join(a.workdir, "old.txt")); got != "old" {
				t.Errorf("old.txt = %q, want it kept", got)
			}
			notApplied(t, a.workdir, "new.txt")
		})
	}
}

// A client that stalls before its request ends gets the same 408 as one that
// stalls in the archive.
func TestSyncUploadTimesOutAStalledRequest(t *testing.T) {
	a := newTestAgent(t)
	a.uploadIdle = 50 * time.Millisecond
	server := httptest.NewUnstartedServer(a.Handler("secret", nil))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close() })
	go func() { _, _ = writer.Write([]byte(`{"delete":[`)) }()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/sync/upload", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("stalled client got %s, want a 408", resp.Status)
	}
}
