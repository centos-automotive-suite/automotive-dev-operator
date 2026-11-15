package workspaceagent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// version is the file's version as a client sends it in a plan.
func version(t *testing.T, path string) string {
	t.Helper()
	v, err := buildcontract.SyncFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func chtimes(t *testing.T, path string, modified time.Time) {
	t.Helper()
	if err := os.Chtimes(path, time.Time{}, modified); err != nil {
		t.Fatal(err)
	}
}

func TestPlanSyncReportsEveryFile(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{
		"same.txt":     "same",
		"dir/same.txt": "nested",
		"edited.txt":   "remote",
		"sub/file":     "a directory where the client has a file",
	})
	for name, target := range map[string]string{"link": "same.txt", "moved": "same.txt"} {
		if err := os.Symlink(target, filepath.Join(a.workdir, name)); err != nil {
			t.Fatal(err)
		}
	}
	client := t.TempDir()
	writeTree(t, client, map[string]string{"edited.txt": "local", "missing.txt": "new", "sub": "file"})
	for name, target := range map[string]string{"link": "same.txt", "moved": "dir/same.txt"} {
		if err := os.Symlink(target, filepath.Join(client, name)); err != nil {
			t.Fatal(err)
		}
	}
	// What an earlier sync wrote keeps the client's size and time.
	files := map[string]string{
		"same.txt":     version(t, filepath.Join(a.workdir, "same.txt")),
		"dir/same.txt": version(t, filepath.Join(a.workdir, "dir/same.txt")),
	}
	for _, name := range []string{"edited.txt", "missing.txt", "sub", "link", "moved"} {
		files[name] = version(t, filepath.Join(client, name))
	}

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"edited.txt", "missing.txt", "moved", "sub"}; !slices.Equal(plan.Changed, want) {
		t.Errorf("changed = %q, want %q", plan.Changed, want)
	}
	if plan.Unchanged != 3 {
		t.Errorf("unchanged = %d, want 3", plan.Unchanged)
	}
	if plan.Deleted != nil {
		t.Errorf("deleted = %q without includeDeleted", plan.Deleted)
	}
}

// A plan compares sizes and modification times, as rsync does by default,
// and reads no file: the same content written later is changed, and other
// content of the same size and time is not.
func TestPlanSyncComparesSizesAndModificationTimes(t *testing.T) {
	a := newTestAgent(t)
	client := t.TempDir()
	writeTree(t, a.workdir, map[string]string{"touched.txt": "same", "rewritten.txt": "old!", "secret": "x"})
	writeTree(t, client, map[string]string{"touched.txt": "same", "rewritten.txt": "new!", "secret": "x"})
	at := time.Date(2020, 1, 2, 3, 4, 5, 6789, time.UTC)
	for _, dir := range []string{a.workdir, client} {
		chtimes(t, filepath.Join(dir, "rewritten.txt"), at)
		chtimes(t, filepath.Join(dir, "secret"), at)
	}
	chtimes(t, filepath.Join(a.workdir, "touched.txt"), at)
	chtimes(t, filepath.Join(client, "touched.txt"), at.Add(time.Nanosecond))
	if err := os.Chmod(filepath.Join(a.workdir, "secret"), 0); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, name := range []string{"touched.txt", "rewritten.txt", "secret"} {
		files[name] = version(t, filepath.Join(client, name))
	}

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Changed, []string{"touched.txt"}) || plan.Unchanged != 2 {
		t.Errorf("plan = %+v, want only touched.txt changed", plan)
	}
}

func TestPlanSyncListsFilesOnlyTheWorkspaceHas(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{
		"kept.txt":      "kept",
		"extra.txt":     "extra",
		"build/out.bin": "artifact",
	})
	if err := os.Symlink("kept.txt", filepath.Join(a.workdir, "link")); err != nil {
		t.Fatal(err)
	}

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"kept.txt": version(t, filepath.Join(a.workdir, "kept.txt"))}, IncludeDeleted: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"build/out.bin", "extra.txt", "link"}; !slices.Equal(plan.Deleted, want) {
		t.Errorf("deleted = %q, want %q", plan.Deleted, want)
	}
	if len(plan.Changed) != 0 || plan.Unchanged != 1 || !plan.IncludeDeleted {
		t.Errorf("plan = %+v, want nothing changed, 1 unchanged and includeDeleted echoed", plan)
	}
}

// An upload in progress keeps its files in the staging directory, which a
// delete must not touch.
// Nothing at the staging path is the client's, and a delete rejects the
// reserved name, so listing a file a run left there would fail the sync.
func TestPlanSyncSkipsTheStagingPath(t *testing.T) {
	for _, staged := range []string{syncStaging + "/partial", syncStaging} {
		a := newTestAgent(t)
		writeTree(t, a.workdir, map[string]string{"kept.txt": "kept", staged: "half"})
		plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"kept.txt": version(t, filepath.Join(a.workdir, "kept.txt"))}, IncludeDeleted: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Deleted) != 0 {
			t.Errorf("with %s: deleted = %q, want nothing", staged, plan.Deleted)
		}
	}
}

// With includeDeleted, an empty manifest would list every workspace file for
// deletion.
func TestPlanSyncRejectsAnEmptyManifest(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "a"})
	_, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{}, IncludeDeleted: true})
	wantBadRequest(t, "an empty manifest", err)
}

func TestPlanSyncWithoutAWorkdirChangesEverything(t *testing.T) {
	a := newTestAgent(t)
	a.workdir = filepath.Join(t.TempDir(), "absent")

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"a.txt": "file 1 1"}, IncludeDeleted: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Changed, []string{"a.txt"}) || len(plan.Deleted) != 0 {
		t.Errorf("plan = %+v, want a.txt changed and nothing deleted", plan)
	}
}

// Only clean relative names match the names the listing reports, so a file
// sent as a/../b can't come back as deleted b.
func TestPlanSyncRejectsInvalidPaths(t *testing.T) {
	a := newTestAgent(t)
	for _, name := range []string{"../escape", "/etc/passwd", "", "a/../../b", ".", "a/../b", "a//b", "a/", "a\x00b", ".caib-sync/x"} {
		_, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{name: "file 1 1"}})
		wantBadRequest(t, fmt.Sprintf("%q", name), err)
	}
}

// Opening a FIFO for reading blocks until something writes to it, so the
// plan must not open it.
func TestPlanSyncDoesNotOpenAFIFO(t *testing.T) {
	a := newTestAgent(t)
	fifo := filepath.Join(a.workdir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan []string, 1)
	go func() {
		plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"pipe": "file 1 1"}})
		if err != nil {
			t.Error(err)
		}
		done <- plan.Changed
	}()
	select {
	case changed := <-done:
		if !slices.Equal(changed, []string{"pipe"}) {
			t.Errorf("changed = %q, want the FIFO changed", changed)
		}
	case <-time.After(5 * time.Second):
		// Release the blocked open so the goroutine can finish.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		<-done
		t.Fatal("the plan blocked opening a FIFO")
	}
}

func TestPlanSyncFailsOnAnUnlistableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"locked/inside": "x"})
	locked := filepath.Join(a.workdir, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	if _, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"a": "file 1 1"}, IncludeDeleted: true}); err == nil {
		t.Fatal("a partial listing was reported instead of failing the plan")
	}
}

// A plan stops when its request is cancelled instead of going on for a
// caller that has gone.
func TestPlanSyncStopsWhenCancelled(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "a"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := a.PlanSync(ctx, SyncPlanRequest{Files: map[string]string{"a.txt": "file 1 1"}}); !errors.Is(err, context.Canceled) {
		t.Errorf("comparing: err = %v, want context.Canceled", err)
	}
	if _, err := workspaceOnly(ctx, os.DirFS(a.workdir), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("listing: err = %v, want context.Canceled", err)
	}
}

// The build API relays a manifest of unknown length without reading it, so
// the agent's limit is the one that applies.
func TestSyncPlanRejectsAnOversizedBody(t *testing.T) {
	a := newTestAgent(t)
	body := strings.NewReader(`{"files":{"a":"` + strings.Repeat("0", MaxSyncListBytes) + `"}}`)
	req := httptest.NewRequest(http.MethodPost, "/sync/plan", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	a.Handler("secret", nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "64 MiB") {
		t.Errorf("response = %d %s, want a 413 naming the limit", rec.Code, rec.Body.String())
	}
}
