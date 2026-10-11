package buildapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/gin-gonic/gin"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type testRepoEntry struct {
	ID       string `json:"id"`
	BaseURL  string `json:"baseurl"`
	Priority *int   `json:"priority,omitempty"`
}

func newOCIRepoTestRegistry(t *testing.T, image v1.Image, requireAuth bool) (name.Tag, func(v1.Image)) {
	t.Helper()
	var manifest atomic.Value
	publish := func(image v1.Image) {
		t.Helper()
		if image == nil {
			manifest.Store([]byte(nil))
			return
		}
		raw, err := image.RawManifest()
		if err != nil {
			t.Fatal(err)
		}
		manifest.Store(raw)
	}
	publish(image)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth {
			user, password, _ := r.BasicAuth()
			if user != "builder" || password != "secret" {
				w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		raw := manifest.Load().([]byte)
		if r.URL.Path != "/v2/rpms/manifests/latest" || raw == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)
	tag, err := name.NewTag(strings.TrimPrefix(server.URL, "http://") + "/rpms:latest")
	if err != nil {
		t.Fatal(err)
	}
	return tag, publish
}

func TestResolveOCIRepoImages_PinsTag(t *testing.T) {
	tag, publish := newOCIRepoTestRegistry(t, empty.Image, false)
	digest, err := empty.Image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req := &buildcontract.BuildRequest{OCIRepoImages: []string{"  " + tag.Name() + "  "}}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	want := tag.Context().Digest(digest.String()).Name()
	if req.OCIRepoImages[0] != want {
		t.Fatalf("resolved image = %q, want %q", req.OCIRepoImages[0], want)
	}
	updated := mutate.Annotations(empty.Image, map[string]string{"revision": "updated"}).(v1.Image)
	publish(updated)
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	spec := buildAIBSpec(req, "name: test\n", "test.aib.yml", false)
	if spec.OCIRepoImages[0] != want {
		t.Fatalf("build image changed after retagging: %q", spec.OCIRepoImages[0])
	}
}

func TestResolveOCIRepoImages_ResolutionFailures(t *testing.T) {
	tag, _ := newOCIRepoTestRegistry(t, nil, false)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		ref  string
		ctx  context.Context
	}{
		{"invalid reference", "invalid ref", t.Context()},
		{"invalid digest", "quay.io/org/rpms@sha256:bad", t.Context()},
		{"missing image", tag.Name(), t.Context()},
		{"cancelled request", tag.Name(), cancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &buildcontract.BuildRequest{OCIRepoImages: []string{tc.ref}, CustomDefs: []string{"existing=value"}}
			if err := resolveOCIRepoImages(tc.ctx, req); err == nil {
				t.Fatal("expected resolution to fail")
			}
			if req.OCIRepoImages[0] != tc.ref || len(req.CustomDefs) != 1 || req.CustomDefs[0] != "existing=value" {
				t.Fatalf("failed resolution modified build inputs: %+v", req)
			}
		})
	}
}

func TestCreateBuildOCIRepoImages(t *testing.T) {
	t.Setenv("BUILD_API_NAMESPACE", "test")
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "private repository", true: "missing image"}[missing], func(t *testing.T) {
			tag, publish := newOCIRepoTestRegistry(t, empty.Image, true)
			if missing {
				publish(nil)
			}
			dockerConfig, err := json.Marshal(map[string]any{"auths": map[string]any{
				tag.Context().RegistryStr(): map[string]string{"username": "builder", "password": "secret"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			k8sClient := newFakeClient(
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: api.BuildServiceAccountName, Namespace: "test"}, ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull-auth"}}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-auth", Namespace: "test"}, Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: dockerConfig}},
			)
			server := newTestServer(t, func(deps *apiDependencies) {
				deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8sClient, nil }
			})
			request := buildcontract.BuildRequest{Name: "oci-build", Manifest: "name: test\n", AutomotiveImageBuilder: tag.Name(), OCIRepoImages: []string{tag.Name()}}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			server.createBuild(c)
			builds := &api.ImageBuildList{}
			if err := k8sClient.List(t.Context(), builds); err != nil {
				t.Fatal(err)
			}
			if missing {
				if response.Code != http.StatusBadRequest || len(builds.Items) != 0 {
					t.Fatalf("unresolved image accepted: status=%d builds=%d body=%s", response.Code, len(builds.Items), response.Body)
				}
				return
			}
			if response.Code != http.StatusAccepted || len(builds.Items) != 1 {
				t.Fatalf("submission failed: status=%d builds=%d body=%s", response.Code, len(builds.Items), response.Body)
			}
			digest, err := empty.Image.Digest()
			if err != nil {
				t.Fatal(err)
			}
			want := tag.Context().Digest(digest.String()).Name()
			if refs := builds.Items[0].Spec.GetOCIRepoImages(); len(refs) != 1 || refs[0] != want {
				t.Fatalf("submitted repository images = %v, want %q", refs, want)
			}
		})
	}
}

func parseTestExtraRepos(t *testing.T, customDefs []string) []testRepoEntry {
	t.Helper()
	for _, def := range customDefs {
		if strings.HasPrefix(def, "extra_repos=") {
			jsonStr := def[len("extra_repos="):]
			var entries []testRepoEntry
			if err := json.Unmarshal([]byte(jsonStr), &entries); err != nil {
				t.Fatalf("failed to parse extra_repos JSON: %v", err)
			}
			return entries
		}
	}
	return nil
}

func TestResolveOCIRepoImages_Empty(t *testing.T) {
	req := &buildcontract.BuildRequest{}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("expected no CustomDefs, got %v", req.CustomDefs)
	}
}

func TestResolveOCIRepoImages_Single(t *testing.T) {
	req := &buildcontract.BuildRequest{
		OCIRepoImages: []string{"quay.io/org/rpms@sha256:" + strings.Repeat("a", 64)},
	}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	repos := parseTestExtraRepos(t, req.CustomDefs)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo entry, got %d", len(repos))
	}
	if repos[0].ID != tasks.OCIRepoVolumeName {
		t.Errorf("expected id %q, got %q", tasks.OCIRepoVolumeName, repos[0].ID)
	}
	wantURL := "file://" + tasks.OCIRepoMountPath
	if repos[0].BaseURL != wantURL {
		t.Errorf("expected baseurl %q, got %q", wantURL, repos[0].BaseURL)
	}
}

func TestResolveOCIRepoImages_ExceedsMax(t *testing.T) {
	req := &buildcontract.BuildRequest{
		OCIRepoImages: []string{
			"quay.io/a:v1",
			"quay.io/b:v1",
		},
	}
	err := resolveOCIRepoImages(t.Context(), req)
	if err == nil {
		t.Fatal("expected error for >1 OCI repos, got nil")
	}
	if !strings.Contains(err.Error(), "too many OCI repo images") {
		t.Errorf("expected 'too many OCI repo images' error, got: %v", err)
	}
}

func TestResolveOCIRepoImages_EmptyRef(t *testing.T) {
	req := &buildcontract.BuildRequest{
		OCIRepoImages: []string{"  "},
	}
	err := resolveOCIRepoImages(t.Context(), req)
	if err == nil {
		t.Fatal("expected error for empty OCI repo ref, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty ref, got: %v", err)
	}
}

func TestResolveOCIRepoImages_MergeWithWorkspaceRepos(t *testing.T) {
	wsRepos := []testRepoEntry{
		{ID: "workspace-my-ws", BaseURL: "http://10.0.0.1:8080"},
	}
	wsJSON, _ := json.Marshal(wsRepos)

	req := &buildcontract.BuildRequest{
		CustomDefs:    []string{"some_def=value", "extra_repos=" + string(wsJSON)},
		OCIRepoImages: []string{"quay.io/org/rpms@sha256:" + strings.Repeat("a", 64)},
	}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	repos := parseTestExtraRepos(t, req.CustomDefs)
	if len(repos) != 2 {
		t.Fatalf("expected 2 merged repo entries, got %d: %+v", len(repos), repos)
	}
	if repos[0].ID != "workspace-my-ws" {
		t.Errorf("repos[0].ID = %q, want %q", repos[0].ID, "workspace-my-ws")
	}
	if repos[1].ID != tasks.OCIRepoVolumeName {
		t.Errorf("repos[1].ID = %q, want %q", repos[1].ID, tasks.OCIRepoVolumeName)
	}

	count := 0
	for _, def := range req.CustomDefs {
		if strings.HasPrefix(def, "extra_repos=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 extra_repos entry in CustomDefs, got %d", count)
	}
}

func TestResolveOCIRepoImages_NoExistingExtraRepos(t *testing.T) {
	req := &buildcontract.BuildRequest{
		CustomDefs:    []string{"some_def=value"},
		OCIRepoImages: []string{"quay.io/org/rpms@sha256:" + strings.Repeat("a", 64)},
	}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	repos := parseTestExtraRepos(t, req.CustomDefs)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo entry, got %d", len(repos))
	}
	if req.CustomDefs[0] != "some_def=value" {
		t.Errorf("expected first CustomDef to be preserved, got %q", req.CustomDefs[0])
	}
}

func TestBuildAIBSpecOCIRepoImages(t *testing.T) {
	req := &buildcontract.BuildRequest{
		Distro:        "autosd",
		Target:        "qemu",
		Mode:          buildcontract.ModeBootc,
		OCIRepoImages: []string{"quay.io/org/rpms@sha256:" + strings.Repeat("a", 64)},
	}
	spec := buildAIBSpec(req, "name: test\n", "test.aib.yml", false)

	if len(spec.OCIRepoImages) != 1 {
		t.Fatalf("expected 1 OCIRepoImages, got %d", len(spec.OCIRepoImages))
	}
	if spec.OCIRepoImages[0] != "quay.io/org/rpms@sha256:"+strings.Repeat("a", 64) {
		t.Errorf("OCIRepoImages[0] = %q, want %q", spec.OCIRepoImages[0], "quay.io/org/rpms@sha256:"+strings.Repeat("a", 64))
	}
}

func TestBuildAIBSpecNoOCIRepoImages(t *testing.T) {
	req := &buildcontract.BuildRequest{
		Distro: "autosd",
		Target: "qemu",
		Mode:   buildcontract.ModeBootc,
	}
	spec := buildAIBSpec(req, "name: test\n", "test.aib.yml", false)

	if len(spec.OCIRepoImages) != 0 {
		t.Fatalf("expected 0 OCIRepoImages, got %d", len(spec.OCIRepoImages))
	}
}

func TestResolveOCIRepoImages_LocalRepoPriority(t *testing.T) {
	req := &buildcontract.BuildRequest{
		OCIRepoImages: []string{"quay.io/org/rpms@sha256:" + strings.Repeat("a", 64)},
		LocalRepo:     true,
	}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	repos := parseTestExtraRepos(t, req.CustomDefs)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo entry, got %d", len(repos))
	}
	if repos[0].Priority == nil || *repos[0].Priority != 1 {
		t.Errorf("expected priority=1 for local repo, got %v", repos[0].Priority)
	}
}

func TestResolveOCIRepoImages_ExtraRepoNoPriority(t *testing.T) {
	req := &buildcontract.BuildRequest{
		OCIRepoImages: []string{"quay.io/org/rpms@sha256:" + strings.Repeat("a", 64)},
	}
	if err := resolveOCIRepoImages(t.Context(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	repos := parseTestExtraRepos(t, req.CustomDefs)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo entry, got %d", len(repos))
	}
	if repos[0].Priority != nil {
		t.Errorf("expected no priority for extra repo, got %d", *repos[0].Priority)
	}
}
