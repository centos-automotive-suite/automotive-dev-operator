package buildapi

import (
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"gopkg.in/yaml.v3"
)

func TestApplyWorkspaceManifest_FileURLAndAddFiles(t *testing.T) {
	manifest := `
name: sample
content:
  repos:
    - id: local
      baseurl: file:///workspace/src/bin
  add_files:
    - path: /usr/bin/app
      source_path: /workspace/src/build/app
    - dest: /etc/
      source_glob: /workspace/src/etc/**/*.conf
qm:
  content:
    add_files:
      - path: /etc/qm.conf
        source_path: //workspace/src/qm.conf
`
	got, refs, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", true)
	if err != nil {
		t.Fatalf("applyWorkspaceManifest: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("unmarshal rewritten manifest: %v", err)
	}

	content := parsed["content"].(map[string]any)
	repos := content["repos"].([]any)
	repo := repos[0].(map[string]any)
	if repo["baseurl"] != "http://10.0.0.5:9090/src/bin" {
		t.Errorf("baseurl = %v, want http://10.0.0.5:9090/src/bin", repo["baseurl"])
	}

	addFiles := content["add_files"].([]any)
	first := addFiles[0].(map[string]any)
	if first["source_path"] != "src/build/app" {
		t.Errorf("source_path = %v, want src/build/app", first["source_path"])
	}
	second := addFiles[1].(map[string]any)
	if second["source_glob"] != "src/etc/**/*.conf" {
		t.Errorf("source_glob = %v, want src/etc/**/*.conf", second["source_glob"])
	}

	qm := parsed["qm"].(map[string]any)
	qmAdd := qm["content"].(map[string]any)["add_files"].([]any)[0].(map[string]any)
	if qmAdd["source_path"] != "src/qm.conf" {
		t.Errorf("qm source_path = %v, want src/qm.conf", qmAdd["source_path"])
	}

	if len(refs) != 3 {
		t.Fatalf("hydrate refs = %d, want 3: %+v", len(refs), refs)
	}
	want := map[WorkspaceHydrateRef]bool{
		{Kind: hydrateKindPath, AbsPath: "/workspace/src/build/app", RelPath: "src/build/app"}:         true,
		{Kind: hydrateKindGlob, AbsPath: "/workspace/src/etc/**/*.conf", RelPath: "src/etc/**/*.conf"}: true,
		{Kind: hydrateKindPath, AbsPath: "/workspace/src/qm.conf", RelPath: "src/qm.conf"}:             true,
	}
	for _, ref := range refs {
		if !want[ref] {
			t.Errorf("unexpected ref %+v", ref)
		}
		delete(want, ref)
	}
	for ref := range want {
		t.Errorf("missing ref %+v", ref)
	}
}

func TestApplyWorkspaceManifest_NoOpPreservesOriginal(t *testing.T) {
	manifest := "name: simple\ncontent:\n  add_files:\n    - source_path: local-bin\n      path: /usr/bin/local-bin\n"
	got, refs, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", true)
	if err != nil {
		t.Fatalf("applyWorkspaceManifest: %v", err)
	}
	if got != manifest {
		t.Errorf("expected original YAML to be preserved, got:\n%s", got)
	}
	if len(refs) != 0 {
		t.Errorf("hydrate refs = %d, want 0", len(refs))
	}
}

func TestApplyWorkspaceManifest_IgnoresNonWorkspaceFileURLs(t *testing.T) {
	manifest := "content:\n  repos:\n    - id: oci\n      baseurl: file:///extra-repos/oci-repo\n"
	got, refs, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", true)
	if err != nil {
		t.Fatalf("applyWorkspaceManifest: %v", err)
	}
	if got != manifest {
		t.Errorf("oci file:// URL should be left alone, got:\n%s", got)
	}
	if len(refs) != 0 {
		t.Errorf("hydrate refs = %d, want 0", len(refs))
	}
}

func TestApplyWorkspaceManifest_FileURLRequiresHTTP(t *testing.T) {
	manifest := "content:\n  repos:\n    - baseurl: file:///workspace/src/bin\n"
	_, _, err := applyWorkspaceManifest(manifest, "", true)
	if err == nil {
		t.Fatal("expected error when file:// workspace URL has no HTTP server")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error %q should mention server not available", err)
	}
}

func TestExtractWorkspaceAddFiles_RepoOnlyLeavesFileURL(t *testing.T) {
	manifest := "content:\n  repos:\n    - id: local\n      baseurl: file:///workspace/src/bin\n"
	got, refs, err := ExtractWorkspaceAddFiles(manifest)
	if err != nil {
		t.Fatalf("ExtractWorkspaceAddFiles: %v", err)
	}
	if got != manifest {
		t.Errorf("repo-only extract should preserve original YAML, got:\n%s", got)
	}
	if len(refs) != 0 {
		t.Errorf("hydrate refs = %d, want 0", len(refs))
	}
}

func TestExtractWorkspaceAddFiles_RewritesAddFilesLeavesRepos(t *testing.T) {
	manifest := `
content:
  repos:
    - id: local
      baseurl: file:///workspace/src/bin
  add_files:
    - path: /usr/bin/app
      source_path: /workspace/src/build/app
`
	got, refs, err := ExtractWorkspaceAddFiles(manifest)
	if err != nil {
		t.Fatalf("ExtractWorkspaceAddFiles: %v", err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatal(err)
	}
	content := parsed["content"].(map[string]any)
	baseurl := content["repos"].([]any)[0].(map[string]any)["baseurl"]
	if baseurl != "file:///workspace/src/bin" {
		t.Errorf("baseurl = %v, want file:///workspace/src/bin", baseurl)
	}
	source := content["add_files"].([]any)[0].(map[string]any)["source_path"]
	if source != "src/build/app" {
		t.Errorf("source_path = %v, want src/build/app", source)
	}
	if len(refs) != 1 || refs[0].AbsPath != "/workspace/src/build/app" {
		t.Errorf("refs = %+v, want one path hydrate", refs)
	}
}

func TestApplyWorkspaceManifest_AddFilesRequireRunningWorkspace(t *testing.T) {
	manifest := "content:\n  add_files:\n    - path: /usr/bin/app\n      source_path: /workspace/src/app\n"
	_, _, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", false)
	if err == nil {
		t.Fatal("expected error when add_files workspace paths and workspace is not running")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("error %q should mention workspace not running", err)
	}
}

func TestApplyWorkspaceManifest_PathTraversalNotRewritten(t *testing.T) {
	manifest := "content:\n  repos:\n    - baseurl: file:///workspace/../etc/passwd\n"
	got, refs, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", true)
	if err != nil {
		t.Fatalf("applyWorkspaceManifest: %v", err)
	}
	if got != manifest {
		t.Errorf("traversal URL should be left alone, got:\n%s", got)
	}
	if len(refs) != 0 {
		t.Errorf("hydrate refs = %d, want 0", len(refs))
	}
}

func TestApplyWorkspaceManifest_WorkspaceRootRepoURL(t *testing.T) {
	manifest := "content:\n  repos:\n    - baseurl: file:///workspace\n"
	got, refs, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", true)
	if err != nil {
		t.Fatalf("applyWorkspaceManifest: %v", err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatal(err)
	}
	baseurl := parsed["content"].(map[string]any)["repos"].([]any)[0].(map[string]any)["baseurl"]
	if baseurl != "http://10.0.0.5:9090/" {
		t.Errorf("baseurl = %v, want http://10.0.0.5:9090/", baseurl)
	}
	if len(refs) != 0 {
		t.Errorf("hydrate refs = %d, want 0", len(refs))
	}
}

func TestApplyWorkspaceManifest_AddFilesURL(t *testing.T) {
	manifest := "content:\n  add_files:\n    - path: /usr/bin/app\n      url: file:///workspace/src/app\n"
	got, refs, err := applyWorkspaceManifest(manifest, "http://10.0.0.5:9090", true)
	if err != nil {
		t.Fatalf("applyWorkspaceManifest: %v", err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatal(err)
	}
	url := parsed["content"].(map[string]any)["add_files"].([]any)[0].(map[string]any)["url"]
	if url != "http://10.0.0.5:9090/src/app" {
		t.Errorf("url = %v, want http://10.0.0.5:9090/src/app", url)
	}
	if len(refs) != 0 {
		t.Errorf("url entries should not be hydrated, got %+v", refs)
	}
}

func TestWorkspaceRelPath(t *testing.T) {
	tests := []struct {
		in      string
		wantRel string
		wantAbs string
		wantOK  bool
	}{
		{"/workspace/src/tool", "src/tool", "/workspace/src/tool", true},
		{"//workspace/src/bin", "src/bin", "/workspace/src/bin", true},
		{"/workspace", "", "", false},
		{"/workspace-other/src", "", "", false},
		{"src/foo", "", "", false},
		{"/etc/passwd", "", "", false},
		{"/workspace/../etc/passwd", "", "", false},
	}
	for _, tt := range tests {
		rel, abs, ok := workspaceRelPath(tt.in)
		if ok != tt.wantOK || rel != tt.wantRel || abs != tt.wantAbs {
			t.Errorf("workspaceRelPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, rel, abs, ok, tt.wantRel, tt.wantAbs, tt.wantOK)
		}
	}
}

func TestShouldSelfCompleteUploads(t *testing.T) {
	tests := []struct {
		name string
		ann  map[string]string
		want bool
	}{
		{name: "laptop only", ann: map[string]string{}, want: false},
		{
			name: "hydrate pending",
			ann:  map[string]string{labels.WorkspaceHydrate: "[]"},
			want: false,
		},
		{
			name: "hydrate done no client",
			ann: map[string]string{
				labels.WorkspaceHydrate:     "[]",
				labels.WorkspaceHydrateDone: labels.ValueTrue,
			},
			want: true,
		},
		{
			name: "hydrate done waiting for client",
			ann: map[string]string{
				labels.WorkspaceHydrate:     "[]",
				labels.WorkspaceHydrateDone: labels.ValueTrue,
				labels.AwaitClientUploads:   labels.ValueTrue,
			},
			want: false,
		},
		{
			name: "already complete",
			ann: map[string]string{
				labels.WorkspaceHydrate:     "[]",
				labels.WorkspaceHydrateDone: labels.ValueTrue,
				labels.UploadsComplete:      labels.ValueTrue,
			},
			want: false,
		},
		{
			name: "client skips uploads, no hydrate",
			ann:  map[string]string{labels.ClientSkipsUploads: labels.ValueTrue},
			want: true,
		},
		{
			name: "client skips uploads, hydrate pending",
			ann: map[string]string{
				labels.ClientSkipsUploads: labels.ValueTrue,
				labels.WorkspaceHydrate:   "[]",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldSelfCompleteUploads(tt.ann); got != tt.want {
				t.Errorf("shouldSelfCompleteUploads() = %v, want %v", got, tt.want)
			}
		})
	}
}
