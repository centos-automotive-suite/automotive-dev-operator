package buildapi

import (
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

func syncPlanTestRouter(t *testing.T, workdir string) *gin.Engine {
	t.Helper()
	agent, err := workspaceagent.New(filepath.Join(t.TempDir(), "runs"), workdir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(agent.Handler("secret", nil))
	t.Cleanup(server.Close)
	return syncPlanRouter(t, server.URL)
}

func syncPlanRouter(t *testing.T, agentURL string) *gin.Engine {
	t.Helper()
	a, router := runTestServer(t, agentURL, "alice", false)
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
	syncPlanRouter(t, agent.URL).ServeHTTP(rec, req)

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
	api := newRunClient(t, syncPlanTestRouter(t, workdir))
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
	router := syncPlanTestRouter(t, t.TempDir())
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
	router := syncPlanTestRouter(t, t.TempDir())
	body := io.MultiReader(
		strings.NewReader(`{"files":{"a":"`),
		strings.NewReader(strings.Repeat("0", workspaceagent.MaxSyncPlanBytes)),
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
