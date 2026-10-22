package buildapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	"github.com/gin-gonic/gin"
	tekton "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	knative "knative.dev/pkg/apis/duck/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newRegistryTokenTestServer(t *testing.T, build client.Object) (*APIServer, *atomic.Int64) {
	t.Helper()
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	tokenRequests := &atomic.Int64{}
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/namespaces/test-ns/serviceaccounts/ado-build/token" {
			t.Errorf("unexpected token request: %s %s", r.Method, r.URL.Path)
		}
		tokenRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: "registry-token"}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(tokens.Close)
	config := &api.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "test-ns"},
		Spec:       api.OperatorConfigSpec{OSBuilds: &api.OSBuildsConfig{ClusterRegistryRoute: "registry.example"}},
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(build, config).Build()
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) { return &rest.Config{Host: tokens.URL}, nil }
		deps.loadOperatorConfig = func(context.Context, client.Client, string) (*api.OperatorConfig, error) { return config, nil }
	})
	return server, tokenRequests
}

func assertRegistryToken(t *testing.T, requests *atomic.Int64, token string, want bool) {
	t.Helper()
	wantRequests := int64(0)
	if want {
		wantRequests = 1
	}
	if got := requests.Load(); got != wantRequests {
		t.Fatalf("minted %d tokens, want %d", got, wantRequests)
	}
	if (token != "") != want {
		t.Fatalf("token returned=%t, want %t", token != "", want)
	}
}

func TestGetBuildTokenRequiresRecordedArtifact(t *testing.T) {
	for _, tc := range []struct {
		name, phase, kind                                            string
		resolveOnly, legacy, flashAttempt, staleArtifacts, wantToken bool
	}{
		{name: "failed", phase: "Failed"},
		{name: "cancelled", phase: "Cancelled"},
		{name: "expired without artifacts", phase: "Expired"},
		{name: "completed without artifacts", phase: "Completed"},
		{name: "container", phase: "Completed", kind: "container", wantToken: true},
		{name: "disk", phase: "Completed", kind: "disk", wantToken: true},
		{name: "flash failed", phase: "Failed", kind: "disk", wantToken: true},
		{name: "expired with recorded artifacts", phase: "Expired", kind: "disk", wantToken: true},
		{name: "active with artifacts", phase: "Flashing", kind: "disk"},
		{name: "resolved lockfile", phase: "Completed", kind: "disk", resolveOnly: true, wantToken: true},
		{name: "legacy completed without artifacts", phase: "Completed", legacy: true},
		{name: "legacy failed flash without artifacts", phase: "Failed", legacy: true, flashAttempt: true},
		{name: "legacy active without artifacts", phase: "Flashing", legacy: true},
		{name: "legacy completed with artifacts", phase: "Completed", kind: "disk", legacy: true, wantToken: true},
		{name: "legacy expired with artifacts", phase: "Expired", kind: "disk", legacy: true, wantToken: true},
		{name: "legacy lockfile", phase: "Completed", kind: "disk", legacy: true, resolveOnly: true, wantToken: true},
		{name: "empty snapshot overrides live artifacts", phase: "Completed", staleArtifacts: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := &api.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "test-ns", Annotations: map[string]string{labels.RequestedBy: "user"}},
				Spec: api.ImageBuildSpec{
					AIB:    &api.AIBSpec{ResolveOnly: tc.resolveOnly},
					Export: &api.ExportSpec{UseServiceAccountAuth: true, Disk: &api.DiskExport{OCI: defaultInternalRegistryURL + "/test-ns/requested:disk"}},
				},
				Status: api.ImageBuildStatus{Phase: tc.phase, TerminalResult: &api.BuildTerminalResult{Phase: tc.phase}},
			}
			var artifacts []api.ArtifactStatus
			if tc.kind != "" {
				artifacts = []api.ArtifactStatus{{Kind: tc.kind, URL: defaultInternalRegistryURL + "/test-ns/published:latest"}}
			}
			if tc.legacy {
				build.Status.TerminalResult = nil
				build.Status.Artifacts = artifacts
			} else {
				build.Status.TerminalResult.Artifacts = artifacts
			}
			if tc.flashAttempt {
				build.Status.FlashTaskRunName = "flash"
			}
			if tc.staleArtifacts {
				build.Status.Artifacts = []api.ArtifactStatus{{Kind: "disk", URL: "registry.example/old:latest"}}
			}
			server, requests := newRegistryTokenTestServer(t, build)
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/v1/builds/build", nil)
			ctx.Set("requester", "user")
			server.getBuild(ctx, "build")
			if response.Code != http.StatusOK {
				t.Fatalf("response: %d %s", response.Code, response.Body)
			}
			var body buildcontract.BuildResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			assertRegistryToken(t, requests, body.RegistryToken, tc.wantToken)
			if body.Warning != "" {
				t.Fatalf("unexpected warning: %q", body.Warning)
			}
			if tc.wantToken {
				artifact := body.DiskImage
				if tc.kind == "container" {
					artifact = body.ContainerImage
				} else if tc.resolveOnly {
					artifact = body.LockfileArtifact
				}
				if artifact != "registry.example/test-ns/published:latest" {
					t.Fatalf("artifact URL = %q, want recorded URL", artifact)
				}
			}
		})
	}
}

func TestGetBuildReportsCost(t *testing.T) {
	cost := &api.BuildCost{ArtifactBytes: new(int64(734003200)), DownloadedBytes: new(int64(0))}
	build := &api.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "test-ns"},
		Status:     api.ImageBuildStatus{Phase: "Completed", Cost: cost},
	}
	server, _ := newRegistryTokenTestServer(t, build)
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v1/builds/build", nil)
	server.getBuild(ctx, "build")
	if response.Code != http.StatusOK {
		t.Fatalf("response: %d %s", response.Code, response.Body)
	}
	var body struct {
		Cost map[string]any `json:"cost"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"artifactBytes": float64(734003200), "downloadedBytes": float64(0)}
	if !reflect.DeepEqual(body.Cost, want) {
		t.Fatalf("cost = %v, want %v", body.Cost, want)
	}
}

func TestClassifyBuildArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name               string
		resolveOnly        bool
		wantDisk, wantLock string
	}{
		{name: "image build", wantDisk: "registry.example/disk"},
		{name: "resolve", resolveOnly: true, wantLock: "registry.example/disk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := &api.ImageBuild{Spec: api.ImageBuildSpec{AIB: &api.AIBSpec{ResolveOnly: tc.resolveOnly}}}
			container, disk, lockfile := classifyBuildArtifactURLs(build, "registry.example/container", "registry.example/disk")
			if container != "registry.example/container" || disk != tc.wantDisk || lockfile != tc.wantLock {
				t.Fatalf("classified URLs = %q, %q, %q", container, disk, lockfile)
			}
		})
	}
}

func TestStoredResolveArtifacts(t *testing.T) {
	build := &api.ImageBuild{Spec: api.ImageBuildSpec{AIB: &api.AIBSpec{ResolveOnly: true}}, Status: api.ImageBuildStatus{
		Artifacts: []api.ArtifactStatus{{Kind: "disk", URL: "registry.example/lock"}},
	}}
	artifacts := storedArtifacts(build)
	if len(artifacts) != 1 || artifacts[0].Kind != "lockfile" || artifacts[0].URL != "registry.example/lock" {
		t.Fatalf("projected artifacts = %#v", artifacts)
	}
	if build.Status.Artifacts[0].Kind != "disk" {
		t.Fatal("stored status was mutated")
	}
	_, disk := storedArtifactURLs(build)
	if disk != "registry.example/lock" {
		t.Fatalf("stored artifact URL = %q", disk)
	}
	build.Status.TerminalResult = &api.BuildTerminalResult{Artifacts: []api.ArtifactStatus{{Kind: "disk", URL: "registry.example/terminal-lock"}}}
	if got := storedArtifacts(build); len(got) != 1 || got[0].Kind != "lockfile" || got[0].URL != "registry.example/terminal-lock" {
		t.Fatalf("projected terminal artifacts = %#v", got)
	}
}

func TestStoredTerminalAPIProjection(t *testing.T) {
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{api.AddToScheme, tekton.AddToScheme, corev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.Now()
	build := &api.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "test-ns", UID: "build-uid"}, Spec: api.ImageBuildSpec{ExternalID: "correlation", CallbackSecretRef: "build-callback"}, Status: api.ImageBuildStatus{
		Phase: "Expired", Message: "expired", CompletionTime: &now,
		TerminalResult: &api.BuildTerminalResult{Phase: "Failed", Message: "flash failed", CompletedAt: now, Artifacts: []api.ArtifactStatus{{Kind: "disk", URL: "registry/published"}}, Flash: &api.FlashOutcomeStatus{Enabled: true, State: "Failed", LeaseID: "lease"}},
	}}
	flash := &tekton.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: "flash", Namespace: "test-ns", UID: "flash-uid", Labels: map[string]string{labels.FlashTaskRun: "flash"}, Annotations: map[string]string{
		notifications.AnnotationExternalID: "flash-correlation", notifications.AnnotationCallbackSecretRef: "flash-callback",
	}}}
	flash.Status.CompletionTime = &now
	flash.Status.Conditions = knative.Conditions{{Type: "Succeeded", Status: corev1.ConditionFalse, Reason: string(tekton.TaskRunReasonCancelled), Message: "cancelled"}}
	flash.Status.Results = []tekton.TaskRunResult{{Name: "lease-id", Value: tekton.ParamValue{Type: tekton.ParamTypeString, StringVal: "flash-lease"}}}
	buildDelivery := &api.WebhookDelivery{ObjectMeta: metav1.ObjectMeta{Name: notifications.DeliveryName("build-uid"), Namespace: "test-ns"}, Spec: api.WebhookDeliverySpec{
		Subject: api.DeliverySubject{UID: build.UID},
	}, Status: api.WebhookDeliveryStatus{NotificationStatus: api.NotificationStatus{State: api.DeliveryDelivered, Attempts: 1}}}
	flashDelivery := &api.WebhookDelivery{ObjectMeta: metav1.ObjectMeta{Name: notifications.DeliveryName("flash-uid"), Namespace: "test-ns"}, Spec: api.WebhookDeliverySpec{
		Subject: api.DeliverySubject{UID: flash.UID},
	}, Status: api.WebhookDeliveryStatus{NotificationStatus: api.NotificationStatus{State: api.DeliveryFailed, Attempts: 2, LastError: "receiver rejected request"}}}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(build, flash, buildDelivery, flashDelivery).Build()

	server := newTestServer(t, nil)
	server.deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
	for _, path := range []string{"build", "builds", "flash", "flashes"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest("GET", "/v1/"+path, nil)
			switch path {
			case "build":
				server.getBuild(ctx, "build")
			case "builds":
				server.listBuilds(ctx)
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
				if body["externalId"] != "correlation" || body["diskImage"] != "registry/published" || body["phase"] != "Expired" || body["artifacts"] == nil || body["flash"] == nil || body["notification"].(map[string]any)["state"] != "Delivered" {
					t.Fatal(body)
				}
			} else if body["phase"] != "Cancelled" || body["externalId"] != "flash-correlation" || body["notification"].(map[string]any)["state"] != "Failed" {
				t.Fatal(body)
			}
			if path == "flash" && body["leaseId"] != "flash-lease" {
				t.Fatal(body)
			}
		})
	}
}
