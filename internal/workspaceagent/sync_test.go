package workspaceagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
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

func sha(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestPlanSyncReportsEveryFile(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{
		"same.txt":     "same",
		"dir/same.txt": "nested",
		"edited.txt":   "remote",
		"sub/file":     "a directory where the client has a file",
	})
	// The CLI hashes what a symlink points to, so the plan follows it too.
	if err := os.Symlink("same.txt", filepath.Join(a.workdir, "link")); err != nil {
		t.Fatal(err)
	}

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{
		"same.txt":     sha("same"),
		"dir/same.txt": sha("nested"),
		"edited.txt":   sha("local"),
		"missing.txt":  sha("new"),
		"sub":          sha("file"),
		"link":         sha("same"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"edited.txt", "missing.txt", "sub"}; !slices.Equal(plan.Changed, want) {
		t.Errorf("changed = %q, want %q", plan.Changed, want)
	}
	if plan.Unchanged != 3 {
		t.Errorf("unchanged = %d, want 3", plan.Unchanged)
	}
	if plan.Deleted != nil {
		t.Errorf("deleted = %q without includeDeleted", plan.Deleted)
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

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"kept.txt": sha("kept")}, IncludeDeleted: true})
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

// With includeDeleted, an empty manifest would list every workspace file for
// deletion.
func TestPlanSyncRejectsAnEmptyManifest(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "a"})
	_, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{}, IncludeDeleted: true})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusBadRequest {
		t.Errorf("err = %v, want a 400", err)
	}
}

func TestPlanSyncWithoutAWorkdirChangesEverything(t *testing.T) {
	a := newTestAgent(t)
	a.workdir = filepath.Join(t.TempDir(), "absent")

	plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"a.txt": sha("a")}, IncludeDeleted: true})
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
	for _, name := range []string{"../escape", "/etc/passwd", "", "a/../../b", ".", "a/../b", "a//b", "a/", "a\x00b"} {
		_, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{name: sha("x")}})
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Code != http.StatusBadRequest {
			t.Errorf("path %q: err = %v, want a 400", name, err)
		}
	}
}

// Opening a FIFO for reading blocks until something writes to it, so the
// plan must see that it isn't a regular file before opening it.
func TestPlanSyncDoesNotOpenAFIFO(t *testing.T) {
	a := newTestAgent(t)
	fifo := filepath.Join(a.workdir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan []string, 1)
	go func() {
		plan, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"pipe": sha("x")}})
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

func TestPlanSyncFailsOnAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"secret": "x"})
	if err := os.Chmod(filepath.Join(a.workdir, "secret"), 0); err != nil {
		t.Fatal(err)
	}

	if _, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"secret": sha("x")}}); err == nil {
		t.Fatal("an unreadable file was reported instead of failing the plan")
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

	if _, err := a.PlanSync(t.Context(), SyncPlanRequest{Files: map[string]string{"a": sha("a")}, IncludeDeleted: true}); err == nil {
		t.Fatal("a partial listing was reported instead of failing the plan")
	}
}

// A plan stops when its request is cancelled instead of hashing on for a
// caller that has gone.
func TestPlanSyncStopsWhenCancelled(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workdir, map[string]string{"a.txt": "a"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := a.PlanSync(ctx, SyncPlanRequest{Files: map[string]string{"a.txt": sha("a")}}); !errors.Is(err, context.Canceled) {
		t.Errorf("hashing: err = %v, want context.Canceled", err)
	}
	if _, err := workspaceOnly(ctx, os.DirFS(a.workdir), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("listing: err = %v, want context.Canceled", err)
	}
}

// The build API relays a manifest of unknown length without reading it, so
// the agent's limit is the one that applies.
func TestSyncPlanRejectsAnOversizedBody(t *testing.T) {
	a := newTestAgent(t)
	body := strings.NewReader(`{"files":{"a":"` + strings.Repeat("0", MaxSyncPlanBytes) + `"}}`)
	req := httptest.NewRequest(http.MethodPost, "/sync/plan", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	a.Handler("secret", nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "64 MiB") {
		t.Errorf("response = %d %s, want a 413 naming the limit", rec.Code, rec.Body.String())
	}
}
