package buildapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

type testRepoEntry struct {
	ID       string `json:"id"`
	BaseURL  string `json:"baseurl"`
	Priority *int   `json:"priority,omitempty"`
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
	req := &BuildRequest{}
	if err := resolveOCIRepoImages(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.CustomDefs) != 0 {
		t.Fatalf("expected no CustomDefs, got %v", req.CustomDefs)
	}
}

func TestResolveOCIRepoImages_Single(t *testing.T) {
	req := &BuildRequest{
		OCIRepoImages: []string{"quay.io/org/rpms:v1"},
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
	req := &BuildRequest{
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
	req := &BuildRequest{
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

	req := &BuildRequest{
		CustomDefs:    []string{"some_def=value", "extra_repos=" + string(wsJSON)},
		OCIRepoImages: []string{"quay.io/org/rpms:v1"},
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
	req := &BuildRequest{
		CustomDefs:    []string{"some_def=value"},
		OCIRepoImages: []string{"quay.io/org/rpms:v1"},
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
	req := &BuildRequest{
		Distro:        "autosd",
		Target:        "qemu",
		Mode:          ModeBootc,
		OCIRepoImages: []string{"quay.io/org/rpms:v1"},
	}
	spec := buildAIBSpec(req, "name: test\n", "test.aib.yml", false)

	if len(spec.OCIRepoImages) != 1 {
		t.Fatalf("expected 1 OCIRepoImages, got %d", len(spec.OCIRepoImages))
	}
	if spec.OCIRepoImages[0] != "quay.io/org/rpms:v1" {
		t.Errorf("OCIRepoImages[0] = %q, want %q", spec.OCIRepoImages[0], "quay.io/org/rpms:v1")
	}
}

func TestBuildAIBSpecNoOCIRepoImages(t *testing.T) {
	req := &BuildRequest{
		Distro: "autosd",
		Target: "qemu",
		Mode:   ModeBootc,
	}
	spec := buildAIBSpec(req, "name: test\n", "test.aib.yml", false)

	if len(spec.OCIRepoImages) != 0 {
		t.Fatalf("expected 0 OCIRepoImages, got %d", len(spec.OCIRepoImages))
	}
}

func TestResolveOCIRepoImages_LocalRepoPriority(t *testing.T) {
	req := &BuildRequest{
		OCIRepoImages: []string{"quay.io/org/rpms:v1"},
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
	req := &BuildRequest{
		OCIRepoImages: []string{"quay.io/org/rpms:v1"},
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
