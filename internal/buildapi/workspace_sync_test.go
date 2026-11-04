package buildapi

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/gin-gonic/gin"
)

func syncTestRouter(t *testing.T, workdir string) *gin.Engine {
	t.Helper()
	agent, err := workspaceagent.New(filepath.Join(t.TempDir(), "runs"), workdir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(agent.Handler("secret", nil))
	t.Cleanup(server.Close)
	return syncRouter(t, server.URL)
}

func syncRouter(t *testing.T, agentURL string) *gin.Engine {
	t.Helper()
	a, router := runTestServer(t, agentURL, "alice", false)
	router.POST("/v1/workspaces/:name/sync", a.wrapNamedHandler("sync", a.syncWorkspace))
	router.POST("/v1/workspaces/:name/sync/plan", a.wrapNamedHandler("sync plan", a.syncPlanWorkspace))
	return router
}

// The build API relays the manifest and the plan without decoding them, so
// its memory doesn't grow with either, and nothing is re-encoded on the way:
// Go's encoder would turn < into \u003c, growing the manifest past the limit.
func TestSyncPlanRelaysBytesUnchanged(t *testing.T) {
	const manifest = `{"files":{"a<b":"00"},"includeDeleted":true}`
	const plan = `{"changed":["a<b"],"unchanged":0,"includeDeleted":true}`
	received := make(chan string, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, plan)
	}))
	t.Cleanup(agent.Close)

	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/sync/plan", strings.NewReader(manifest))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	syncRouter(t, agent.URL).ServeHTTP(rec, req)

	select {
	case got := <-received:
		if got != manifest {
			t.Errorf("agent received %s, want %s", got, manifest)
		}
	default:
		t.Error("the manifest never reached the agent")
	}
	if rec.Code != http.StatusOK || rec.Body.String() != plan {
		t.Errorf("response = %d %s, want 200 %s", rec.Code, rec.Body.String(), plan)
	}
}

func TestSyncPlanComesFromTheWorkspaceAgent(t *testing.T) {
	workdir := t.TempDir()
	for name, content := range map[string]string{"same.txt": "same", "extra.txt": "extra"} {
		if err := os.WriteFile(filepath.Join(workdir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	api := newRunClient(t, syncTestRouter(t, workdir))
	sum := sha256.Sum256([]byte("same"))

	plan, err := api.SyncPlan(context.Background(), "dev", buildcontract.SyncPlanRequest{
		Files:          map[string]string{"same.txt": hex.EncodeToString(sum[:]), "new.txt": "00"},
		IncludeDeleted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Changed, []string{"new.txt"}) || plan.Unchanged != 1 ||
		!slices.Equal(plan.Deleted, []string{"extra.txt"}) || !plan.IncludeDeleted {
		t.Errorf("plan = %+v, want new.txt changed, 1 unchanged, extra.txt deleted", plan)
	}
}

func TestSyncPlanPassesOnTheAgentsRejection(t *testing.T) {
	router := syncTestRouter(t, t.TempDir())
	body := strings.NewReader(`{"files":{"../escape":"00"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/sync/plan", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "../escape") {
		t.Errorf("response = %d %s, want a 400 naming the path", rec.Code, rec.Body.String())
	}
}

// The build API relays a manifest without reading it, so the agent's limit
// applies to the client's request.
func TestSyncPlanRejectsAnOversizedManifest(t *testing.T) {
	router := syncTestRouter(t, t.TempDir())
	body := io.MultiReader(
		strings.NewReader(`{"files":{"a":"`),
		strings.NewReader(strings.Repeat("0", workspaceagent.MaxSyncListBytes)),
		strings.NewReader(`"}}`),
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/dev/sync/plan", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "64 MiB") {
		t.Errorf("response = %d %s, want a 413 naming the limit", rec.Code, rec.Body.String())
	}
}

func TestSyncUploadReachesTheWorkspace(t *testing.T) {
	workdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workdir, "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "old/stale.txt"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	api := newRunClient(t, syncTestRouter(t, workdir))
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "src/main.go", Mode: 0o644, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("main")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	req := buildcontract.SyncUploadRequest{Delete: []string{"old/stale.txt"}}
	if err := api.SyncWorkspace(context.Background(), "dev", req, &archive); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(workdir, "src/main.go")); err != nil || string(data) != "main" {
		t.Errorf("src/main.go = %q, %v; want main", data, err)
	}
	if _, err := os.Stat(filepath.Join(workdir, "old")); !os.IsNotExist(err) {
		t.Errorf("old: %v, want it pruned with its last file", err)
	}
}

func TestSyncUploadPassesOnTheAgentsRejection(t *testing.T) {
	api := newRunClient(t, syncTestRouter(t, t.TempDir()))
	req := buildcontract.SyncUploadRequest{Delete: []string{"../escape"}}
	err := api.SyncWorkspace(context.Background(), "dev", req, bytes.NewReader(nil))
	if err == nil || !strings.Contains(err.Error(), "../escape") {
		t.Errorf("err = %v, want the agent's rejection naming the path", err)
	}
}
