package workspace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspacerun"
	"github.com/go-logr/logr"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestActivityExecRequestEnablesStdinWithoutRunnerInURL(t *testing.T) {
	requests := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests <- req.URL.Query()
		http.Error(w, "stop after inspecting exec request", http.StatusBadRequest)
	}))
	defer server.Close()
	r := &Reconciler{RestConfig: &rest.Config{Host: server.URL}}
	ws := &automotivev1alpha1.Workspace{ObjectMeta: metav1.ObjectMeta{Name: "dev", Namespace: "project"}}
	command, input := workspacerun.ActivityCommand()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := r.runActivityCommand(ctx, ws, command, input); err == nil {
		t.Fatal("test server must reject the exec handshake")
	}
	select {
	case query := <-requests:
		argv := query["command"]
		if query.Get("stdin") != "true" || len(argv) != 9 || !slices.Equal(argv[6:], []string{"python3", "-I", "-"}) {
			t.Fatalf("activity request cannot receive runner on stdin: stdin=%s argc=%d", query.Get("stdin"), len(argv))
		}
		if len(query.Encode()) > 2048 {
			t.Fatalf("activity request includes a large runner payload: %d query bytes", len(query.Encode()))
		}
	default:
		t.Fatal("no pod exec request reached the test server")
	}
}

func TestActiveRunPreventsAutoPause(t *testing.T) {
	ws, _, _ := runningWorkspace("run-ws", "developer-project")
	ws.Spec.AutoPauseTimeoutMinutes = new(int32(1))
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	ws.Status.LastActivityTime = &old
	r, kube := newTestReconciler(ws)
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), ws); err != nil {
		t.Fatal(err)
	}
	r.execActivity = func(_ context.Context, target *automotivev1alpha1.Workspace, argv []string, input string) (string, error) {
		if target.Namespace != "developer-project" {
			t.Fatalf("wrong activity target namespace: %s", target.Namespace)
		}
		if argv[0] != "/bin/sh" || !slices.Equal(argv[6:], []string{"python3", "-I", "-"}) || !strings.Contains(input, `"active"`) {
			t.Fatal("activity check did not use the combined runner")
		}
		return `{"active":true}`, nil
	}
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
	for _, response := range []string{"invalid JSON", `{"error":"volume unavailable"}`, `{"code":409,"error":"unsupported run record version 2"}`} {
		ws, _, _ := runningWorkspace("run-ws", "default")
		ws.Spec.AutoPauseTimeoutMinutes = new(int32(1))
		old := metav1.NewTime(time.Now().Add(-time.Hour))
		ws.Status.LastActivityTime = &old
		r, _ := newTestReconciler(ws)
		r.execActivity = func(context.Context, *automotivev1alpha1.Workspace, []string, string) (string, error) {
			return response, nil
		}
		result, err := r.checkAutoPause(context.Background(), ws, logr.Discard())
		if err != nil || result.RequeueAfter == 0 || ws.Spec.Stopped {
			t.Fatalf("failed activity check paused workspace: %+v, %v", result, err)
		}
	}
}

func TestAutoPauseConflictsWithNewRunActivity(t *testing.T) {
	ws, _, _ := runningWorkspace("run-ws", "default")
	ws.Spec.AutoPauseTimeoutMinutes = new(int32(1))
	old := metav1.NewTime(time.Now().Add(-time.Hour))
	ws.Status.LastActivityTime = &old
	r, kube := newTestReconciler(ws)
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), ws); err != nil {
		t.Fatal(err)
	}
	r.execActivity = func(_ context.Context, _ *automotivev1alpha1.Workspace, _ []string, _ string) (string, error) {
		// Simulate POST /runs updating activity after the controller read idle.
		current := &automotivev1alpha1.Workspace{}
		if err := kube.Get(context.Background(), client.ObjectKeyFromObject(ws), current); err != nil {
			return "", err
		}
		patch := client.MergeFrom(current.DeepCopy())
		now := metav1.Now()
		current.Status.LastActivityTime = &now
		if err := kube.Status().Patch(context.Background(), current, patch); err != nil {
			return "", err
		}
		return `{"active":false}`, nil
	}
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
