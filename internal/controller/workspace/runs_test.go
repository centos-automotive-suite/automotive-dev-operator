package workspace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/go-logr/logr"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// stubAgent answers the controller's activity checks with handler.
func stubAgent(t *testing.T, r *Reconciler, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/activity" || req.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, `{"error":"unexpected request"}`, http.StatusBadRequest)
			return
		}
		handler(w, req)
	}))
	t.Cleanup(server.Close)
	r.connectAgent = func(context.Context, *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
		return workspaceagent.NewClient(server.URL, "secret", nil), nil
	}
}

// idleForAnHour makes ws due for auto-pause unless its agent reports activity.
func idleForAnHour(ws *automotivev1alpha1.Workspace) metav1.Time {
	ws.Spec.AutoPauseTimeoutMinutes = new(int32(1))
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	ws.Status.LastActivityTime = &old
	return old
}

func TestActiveRunPreventsAutoPause(t *testing.T) {
	ws, _, _ := runningWorkspace("run-ws", "developer-project")
	old := idleForAnHour(ws)
	r, kube := newTestReconciler(ws)
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), ws); err != nil {
		t.Fatal(err)
	}
	stubAgent(t, r, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":true,"liveRuns":1}`))
	})
	result, err := r.checkAutoPause(context.Background(), ws, logr.Discard())
	if err != nil || result.RequeueAfter == 0 {
		t.Fatalf("check: %+v, %v", result, err)
	}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), ws); err != nil {
		t.Fatal(err)
	}
	if ws.Spec.Stopped || !ws.Status.LastActivityTime.After(old.Time) {
		t.Fatalf("live run was considered idle: %+v", ws)
	}
}

func TestRunActivityCheckFailsClosed(t *testing.T) {
	for _, respond := range []func(http.ResponseWriter){
		func(w http.ResponseWriter) { _, _ = w.Write([]byte("invalid JSON")) },
		func(w http.ResponseWriter) {
			http.Error(w, `{"error":"volume unavailable"}`, http.StatusInternalServerError)
		},
	} {
		ws, _, _ := runningWorkspace("run-ws", "default")
		idleForAnHour(ws)
		r, _ := newTestReconciler(ws)
		stubAgent(t, r, func(w http.ResponseWriter, _ *http.Request) { respond(w) })
		result, err := r.checkAutoPause(context.Background(), ws, logr.Discard())
		if err != nil || result.RequeueAfter == 0 || ws.Spec.Stopped {
			t.Fatalf("failed activity check paused workspace: %+v, %v", result, err)
		}
	}

	// An agent that cannot be reached is not idle either.
	ws, _, _ := runningWorkspace("run-ws", "default")
	idleForAnHour(ws)
	r, _ := newTestReconciler(ws)
	result, err := r.checkAutoPause(context.Background(), ws, logr.Discard())
	if err != nil || result.RequeueAfter == 0 || ws.Spec.Stopped {
		t.Fatalf("unreachable agent paused workspace: %+v, %v", result, err)
	}
}

func TestAutoPauseConflictsWithNewRunActivity(t *testing.T) {
	ws, _, _ := runningWorkspace("run-ws", "default")
	idleForAnHour(ws)
	r, kube := newTestReconciler(ws)
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), ws); err != nil {
		t.Fatal(err)
	}
	stubAgent(t, r, func(w http.ResponseWriter, _ *http.Request) {
		// Simulate POST /runs updating activity after the controller read idle.
		current := &automotivev1alpha1.Workspace{}
		if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), current); err != nil {
			http.Error(w, `{"error":"get failed"}`, http.StatusInternalServerError)
			return
		}
		patch := client.MergeFrom(current.DeepCopy())
		now := metav1.Now()
		current.Status.LastActivityTime = &now
		if err := kube.Status().Patch(context.Background(), current, patch); err != nil {
			http.Error(w, `{"error":"patch failed"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"active":false}`))
	})
	_, err := r.checkAutoPause(context.Background(), ws, logr.Discard())
	if !k8serrors.IsConflict(err) {
		t.Fatalf("expected optimistic-lock conflict, got %v", err)
	}
	current := &automotivev1alpha1.Workspace{}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), current); err != nil {
		t.Fatal(err)
	}
	if current.Spec.Stopped {
		t.Fatal("stale idle decision paused a newly active workspace")
	}
}
