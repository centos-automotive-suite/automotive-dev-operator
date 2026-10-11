package buildapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/gin-gonic/gin"
)

type testRepoEntry struct {
	ID       string `json:"id"`
	BaseURL  string `json:"baseurl"`
	Priority *int   `json:"priority,omitempty"`
}

func TestApplyOCIRepoImagesWithoutRegistryAccess(t *testing.T) {
	for _, ref := range []string{"rpms:v1", "image-registry.openshift-image-registry.svc:5000/org/rpms:v1", "127.0.0.1:1/rpms:v1"} {
		t.Run(ref, func(t *testing.T) {
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			ctx, span := apiTracer.Start(t.Context(), "test")
			defer span.End()
			req := &buildcontract.BuildRequest{OCIRepoImages: []string{ref}}
			server := newTestServer(t, nil)
			if !server.applyAllExtraRepos(ctx, c, span, nil, "alice", req) {
				t.Fatalf("repository requires registry access or credentials: %s", response.Body)
			}
			if req.OCIRepoImages[0] != ref {
				t.Fatalf("reference rewritten: %q", req.OCIRepoImages[0])
			}
		})
	}
}

func TestInvalidOCIRepoRejectedBeforeWorkspaceResolution(t *testing.T) {
	for _, tc := range []struct {
		name, ref, message string
		secure             bool
	}{
		{name: "empty reference", ref: " ", message: "OCI repo image ref is empty"},
		{name: "secure tag", ref: "quay.io/org/rpms:v1", secure: true, message: "secure builds do not support OCI repository images"},
		{name: "secure digest", ref: "quay.io/org/rpms@sha256:" + strings.Repeat("a", 64), secure: true, message: "secure builds do not support OCI repository images"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t, nil)
			body, err := json.Marshal(buildcontract.BuildRequest{Name: "invalid-oci", Manifest: "name: test", OCIRepoImages: []string{tc.ref}, SecureBuild: tc.secure, ExtraRepos: []string{"dev:/rpms"}})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			server.createBuild(c)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.message) {
				t.Fatalf("unexpected validation response: %d %s", response.Code, response.Body)
			}
		})
	}
}

func TestResolveOCIRepoImages_Idempotent(t *testing.T) {
	for _, ref := range []string{"rpms:v1", "internal.svc:5000/org/rpms:v1", "quay.io/org/rpms:v1@sha256:" + strings.Repeat("a", 64)} {
		t.Run(ref, func(t *testing.T) {
			req := &buildcontract.BuildRequest{OCIRepoImages: []string{"  " + ref + "  "}, CustomDefs: []string{`extra_repos=[{"id":"workspace","baseurl":"http://workspace:8080"}]`}}
			for range 2 {
				if err := resolveOCIRepoImages(req); err != nil {
					t.Fatal(err)
				}
			}
			if req.OCIRepoImages[0] != ref {
				t.Fatalf("reference rewritten: %q, want %q", req.OCIRepoImages[0], ref)
			}
			repos := parseTestExtraRepos(t, req.CustomDefs)
			if len(req.CustomDefs) != 1 || len(repos) != 2 || repos[0].ID != "workspace" || repos[1].ID != tasks.OCIRepoVolumeName {
				t.Fatalf("repositories duplicated or replaced: %+v", repos)
			}
		})
	}
}

func TestResolveOCIRepoImages_InvalidReference(t *testing.T) {
	for _, ref := range []string{"invalid ref", "quay.io/org/rpms@sha256:bad"} {
		req := &buildcontract.BuildRequest{OCIRepoImages: []string{ref}}
		if err := resolveOCIRepoImages(req); err == nil {
			t.Fatalf("invalid reference accepted: %q", ref)
		}
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
	if err := resolveOCIRepoImages(req); err != nil {
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
	if err := resolveOCIRepoImages(req); err != nil {
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
	err := resolveOCIRepoImages(req)
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
	err := resolveOCIRepoImages(req)
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
	if err := resolveOCIRepoImages(req); err != nil {
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
	if err := resolveOCIRepoImages(req); err != nil {
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
	if err := resolveOCIRepoImages(req); err != nil {
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
	if err := resolveOCIRepoImages(req); err != nil {
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

func TestSecureBuildRejectsOCIRepo(t *testing.T) {
	for _, tc := range []struct {
		name, ref                     string
		secure, reproducible, invalid bool
	}{
		{name: "ordinary tag", ref: "quay.io/org/rpms:v1"},
		{name: "ordinary digest", ref: "quay.io/org/rpms:v1@sha256:" + strings.Repeat("a", 64)},
		{name: "secure tag", ref: "quay.io/org/rpms:v1", secure: true, invalid: true},
		{name: "secure digest", ref: "quay.io/org/rpms:v1@sha256:" + strings.Repeat("a", 64), secure: true, invalid: true},
		{name: "reproducible tag", ref: "quay.io/org/rpms:v1", secure: true, reproducible: true, invalid: true},
		{name: "reproducible digest", ref: "quay.io/org/rpms:v1@sha256:" + strings.Repeat("a", 64), secure: true, reproducible: true, invalid: true},
		{name: "secure without repositories", secure: true},
		{name: "reproducible without repositories", secure: true, reproducible: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &buildcontract.BuildRequest{Name: "test", Manifest: "name: test", Reproducible: tc.reproducible, SecureBuild: tc.secure}
			if tc.ref != "" {
				req.OCIRepoImages = []string{tc.ref}
			}
			err := validateBuildRequest(req)
			if (err != nil) != tc.invalid {
				t.Fatalf("validation = %v", err)
			}
			if tc.invalid && !strings.Contains(err.Error(), "secure builds do not support OCI repository images") {
				t.Fatalf("unclear validation error: %v", err)
			}
		})
	}
}
