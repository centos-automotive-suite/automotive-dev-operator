package buildcmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapi "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"gopkg.in/yaml.v3"
)

func TestPrepareManifestUploads_LocalPaths(t *testing.T) {
	for _, tt := range []struct {
		name      string
		key       string
		source    string
		absolute  bool
		qm        bool
		workspace bool
		files     []string
	}{
		{name: "file", key: "source_path", source: "../../files/app.conf", files: []string{"files/app.conf"}},
		{name: "legacy source", key: "source", source: "../../files/app.conf", files: []string{"files/app.conf"}},
		{name: "glob", key: "source_glob", source: "../../files/*.conf", files: []string{"files/app.conf", "files/other.conf"}},
		{name: "recursive QM glob", key: "source_glob", source: "../../files/**/*.conf", qm: true, files: []string{"files/app.conf", "files/nested/other.conf"}},
		{name: "workspace with local file", key: "source_path", source: "../../files/app.conf", workspace: true, files: []string{"files/app.conf"}},
		{name: "internal parent", key: "source_path", source: "../../files/unused/../app.conf", files: []string{"files/app.conf"}},
		{name: "manifest directory", key: "source_path", source: "files/app.conf", files: []string{"files/app.conf"}},
		{name: "absolute file", key: "source_path", source: "files/app.conf", absolute: true, files: []string{"files/app.conf"}},
		{name: "absolute glob", key: "source_glob", source: "files/*.conf", absolute: true, files: []string{"files/app.conf", "files/other.conf"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			manifestDir := filepath.Join(root, "manifests", "nested")
			if err := os.MkdirAll(manifestDir, 0o755); err != nil {
				t.Fatal(err)
			}
			fileRoot := root
			if tt.name == "manifest directory" {
				fileRoot = manifestDir
			}
			want := make(map[string]string, len(tt.files))
			for _, name := range tt.files {
				dest := name
				if tt.absolute {
					dest = strings.TrimPrefix(filepath.ToSlash(filepath.Join(fileRoot, name)), "/")
				}
				want[dest] = "contents of " + name
				writeUploadTestFile(t, filepath.Join(fileRoot, name), want[dest])
			}
			source := tt.source
			if tt.absolute {
				source = filepath.Join(fileRoot, source)
			}
			entry := map[string]any{"path": "/etc/configs", tt.key: source, "preserve_path": true}
			section := map[string]any{"content": map[string]any{"add_files": []any{entry}}}
			manifestData := section
			if tt.qm {
				manifestData = map[string]any{"qm": section}
			}
			manifestBytes, err := yaml.Marshal(manifestData)
			if err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(manifestDir, "image.aib.yml")
			writeUploadTestFile(t, manifestPath, string(manifestBytes))
			h := &Handler{}
			if tt.workspace {
				h.opts.Workspace = new("test-workspace")
				t.Setenv("CAIB_CLIENT_WORKSPACE_UPLOAD", "0")
			}
			req := &buildapi.BuildRequest{Manifest: string(manifestBytes)}
			refs, cleanup, err := h.prepareManifestUploads(context.Background(), nil, req, manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			sharedDir := filepath.Join(root, "shared")
			got := make(map[string]string, len(refs))
			for _, ref := range refs {
				if !filepath.IsLocal(ref["dest"]) {
					t.Fatalf("upload destination escapes staging: %q", ref["dest"])
				}
				data, err := os.ReadFile(ref["source_path"])
				if err != nil {
					t.Fatalf("read upload source from outside manifest directory: %v", err)
				}
				got[ref["dest"]] = string(data)
				writeUploadTestFile(t, filepath.Join(sharedDir, ref["dest"]), string(data))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("uploads = %v, want %v", got, want)
			}
			if strings.Contains(req.Manifest, "../") {
				t.Fatalf("parent path remains in manifest:\n%s", req.Manifest)
			}
			assertLocalManifestSource(t, req.Manifest, tt.key, tt.qm)
			original, err := os.ReadFile(manifestPath)
			if err != nil || string(original) != string(manifestBytes) {
				t.Fatalf("original manifest changed: %v", err)
			}

			t.Run("build script resolves uploaded files", func(t *testing.T) {
				if _, err := exec.LookPath("yq"); err != nil {
					t.Skip("yq is required to exercise find_manifest.sh")
				}
				configDir := filepath.Join(root, "config")
				workDir := filepath.Join(root, "manifest-work")
				if err := os.MkdirAll(workDir, 0o755); err != nil {
					t.Fatal(err)
				}
				writeUploadTestFile(t, filepath.Join(configDir, "image.aib.yml"), req.Manifest)
				script := strings.NewReplacer(
					"$(workspaces.manifest-config-workspace.path)", configDir,
					"$(workspaces.shared-workspace.path)", sharedDir,
					"/manifest-work", workDir,
					"/tekton/results", filepath.Join(root, "results"),
				).Replace(tasks.FindManifestScript)
				if output, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
					t.Fatalf("find_manifest.sh: %v\n%s", err, output)
				}
				builtManifest, err := os.ReadFile(filepath.Join(workDir, "image.aib.yml"))
				if err != nil {
					t.Fatal(err)
				}
				_, builtRefs, err := common.PrepareLocalFileUploads(string(builtManifest), workDir, false)
				if err != nil {
					t.Fatal(err)
				}
				built := make(map[string]string, len(builtRefs))
				for _, ref := range builtRefs {
					source := ref["source_path"]
					if !filepath.IsAbs(source) {
						source = filepath.Join(workDir, source)
					}
					name, err := filepath.Rel(workDir, source)
					if err != nil || !filepath.IsLocal(name) {
						t.Fatalf("build source escapes staging: %q (%v)", source, err)
					}
					data, err := os.ReadFile(source)
					if err != nil {
						t.Fatalf("build source missing: %v", err)
					}
					built[name] = string(data)
				}
				if !reflect.DeepEqual(built, want) {
					t.Fatalf("build files = %v, want %v", built, want)
				}
			})
		})
	}
}

func TestPrepareManifestUploads_PathCollisions(t *testing.T) {
	for _, sameFile := range []bool{false, true} {
		t.Run(fmt.Sprintf("same file %v", sameFile), func(t *testing.T) {
			second := "files/app.conf"
			if sameFile {
				second = "../../files/./app.conf"
			}
			manifest := fmt.Sprintf("content:\n  add_files:\n    - path: /etc/one\n      source_path: ../../files/app.conf\n    - path: /etc/two\n      source_path: %s\n", second)
			h := &Handler{}
			req := &buildapi.BuildRequest{Manifest: manifest}
			refs, cleanup, err := h.prepareManifestUploads(context.Background(), nil, req, filepath.Join(t.TempDir(), "image.aib.yml"))
			if cleanup != nil {
				defer cleanup()
			}
			if sameFile && err != nil {
				t.Fatal(err)
			}
			if sameFile && len(refs) != 1 {
				t.Fatalf("expected one upload for duplicate references, got %d", len(refs))
			}
			if !sameFile && (err == nil || !strings.Contains(err.Error(), "same upload destination")) {
				t.Fatalf("expected collision error, got %v", err)
			}
		})
	}
}

func TestPrepareManifestUploads_PreservesNonLocalReferences(t *testing.T) {
	manifest := `# Preserve formatting when no paths need rewriting.
content:
  add_files:
    - path: /etc/workspace
      source_path: /workspace/src/app.conf
    - path: /etc/glob
      source_glob: /workspace/src/*.conf
    - path: /etc/note
      text: ../../literal
    - path: /etc/remote
      url: https://example.com/data
`
	for _, upload := range []string{"0", "1"} {
		t.Run("client workspace upload="+upload, func(t *testing.T) {
			t.Setenv("CAIB_CLIENT_WORKSPACE_UPLOAD", upload)
			h := &Handler{opts: Options{Workspace: new("test-workspace")}}
			req := &buildapi.BuildRequest{Manifest: manifest}
			refs, cleanup, err := h.prepareManifestUploads(context.Background(), nil, req, "image.aib.yml")
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if req.Manifest != manifest || len(refs) != 0 {
				t.Fatalf("non-local references changed: manifest=%q refs=%v", req.Manifest, refs)
			}
		})
	}
}

func assertLocalManifestSource(t *testing.T, manifest, key string, qm bool) {
	t.Helper()
	var rewritten map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &rewritten); err != nil {
		t.Fatal(err)
	}
	if qm {
		rewritten = rewritten["qm"].(map[string]any)
	}
	rewrittenFiles := rewritten["content"].(map[string]any)["add_files"].([]any)
	rewrittenSource := rewrittenFiles[0].(map[string]any)[key].(string)
	if !filepath.IsLocal(rewrittenSource) {
		t.Fatalf("manifest source does not point into staging: %q", rewrittenSource)
	}
}

func writeUploadTestFile(t *testing.T, name, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
