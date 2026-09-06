package buildapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	tekton "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	knative "knative.dev/pkg/apis/duck/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestStoredTerminalAPIProjection(t *testing.T) {
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{api.AddToScheme, tekton.AddToScheme, corev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.Now()
	build := &api.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "test-ns"}, Spec: api.ImageBuildSpec{ExternalID: "correlation"}, Status: api.ImageBuildStatus{
		Phase: "Expired", Message: "expired", CompletionTime: &now,
		TerminalResult: &api.BuildTerminalResult{Phase: "Failed", Message: "flash failed", CompletedAt: now, Artifacts: []api.ArtifactStatus{{Kind: "disk", URL: "registry/published"}}, Flash: &api.FlashOutcomeStatus{Enabled: true, State: "Failed", LeaseID: "lease"}},
	}}
	flash := &tekton.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: "flash", Namespace: "test-ns", Labels: map[string]string{labels.FlashTaskRun: "flash"}}}
	flash.Status.CompletionTime = &now
	flash.Status.Conditions = knative.Conditions{{Type: "Succeeded", Status: corev1.ConditionFalse, Reason: string(tekton.TaskRunReasonCancelled), Message: "cancelled"}}
	flash.Status.Results = []tekton.TaskRunResult{{Name: "lease-id", Value: tekton.ParamValue{Type: tekton.ParamTypeString, StringVal: "flash-lease"}}}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(build, flash).Build()
	original := getClientFromRequestFn
	getClientFromRequestFn = func(*gin.Context) (client.Client, error) { return k8s, nil }
	t.Cleanup(func() { getClientFromRequestFn = original })
	server := NewAPIServer(":0", logr.Discard())
	for _, path := range []string{"build", "builds", "flash", "flashes"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest("GET", "/v1/"+path, nil)
			switch path {
			case "build":
				server.getBuild(ctx, "build")
			case "builds":
				listBuilds(ctx)
			case "flash":
				server.getFlash(ctx, "flash")
			case "flashes":
				server.listFlash(ctx)
			}
			if response.Code != 200 {
				t.Fatalf("response: %d %s", response.Code, response.Body)
			}
			var body map[string]any
			if path == "builds" || path == "flashes" {
				var items []map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &items); err != nil {
					t.Fatal(err)
				}
				if len(items) != 1 {
					t.Fatal(items)
				}
				body = items[0]
			} else if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if path == "build" || path == "builds" {
				if body["externalId"] != "correlation" || body["diskImage"] != "registry/published" || body["phase"] != "Expired" || body["artifacts"] == nil || body["flash"] == nil {
					t.Fatal(body)
				}
			} else if body["phase"] != "Cancelled" {
				t.Fatal(body)
			}
			if path == "flash" && body["leaseId"] != "flash-lease" {
				t.Fatal(body)
			}
		})
	}
}
