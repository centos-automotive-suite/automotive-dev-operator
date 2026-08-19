package caibcommon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManifestTarget(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     string
	}{
		{
			name:     "target present",
			manifest: "name: my-image\ntarget: j784s4evm\n",
			want:     "j784s4evm",
		},
		{
			name:     "target absent",
			manifest: "name: my-image\n",
			want:     "",
		},
		{
			name:     "empty manifest",
			manifest: "",
			want:     "",
		},
		{
			name:     "invalid yaml",
			manifest: ": : :\n",
			want:     "",
		},
		{
			name:     "target is empty string",
			manifest: "name: my-image\ntarget: \"\"\n",
			want:     "",
		},
		{
			name:     "target is whitespace only",
			manifest: "name: my-image\ntarget: \"  \"\n",
			want:     "",
		},
		{
			name:     "target with surrounding whitespace",
			manifest: "name: my-image\ntarget: \" qemu \"\n",
			want:     "qemu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ManifestTarget([]byte(tt.manifest))
			if got != tt.want {
				t.Errorf("ManifestTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindLocalFileReferences_SourcePath(t *testing.T) {
	manifest := `
content:
  add_files:
    - path: /usr/bin/app
      source_path: app-binary
    - path: /etc/config.yaml
      source_path: configs/config.yaml
`
	refs, err := FindLocalFileReferences(manifest, "/tmp/manifest-dir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs[0]["source_path"] != "app-binary" {
		t.Errorf("expected source_path 'app-binary', got %q", refs[0]["source_path"])
	}
	if refs[1]["source_path"] != "configs/config.yaml" {
		t.Errorf("expected source_path 'configs/config.yaml', got %q", refs[1]["source_path"])
	}
}

func TestFindLocalFileReferences_QMSourcePath(t *testing.T) {
	manifest := `
qm:
  content:
    add_files:
      - path: /etc/qm.conf
        source_path: qm.conf
`
	refs, err := FindLocalFileReferences(manifest, "/tmp/manifest-dir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0]["source_path"] != "qm.conf" {
		t.Errorf("expected source_path 'qm.conf', got %q", refs[0]["source_path"])
	}
}

func TestFindLocalFileReferences_TextAndURL(t *testing.T) {
	manifest := `
content:
  add_files:
    - path: /etc/note.txt
      text: "hello world"
    - path: /etc/data.json
      url: https://example.com/data.json
`
	refs, err := FindLocalFileReferences(manifest, "/tmp/manifest-dir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected 0 refs for text/url entries, got %d", len(refs))
	}
}

func TestFindLocalFileReferences_SourceGlob(t *testing.T) {
	dir := t.TempDir()

	// Create test files matching the glob
	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.yaml", "b.yaml", "c.txt"} {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	manifest := `
content:
  add_files:
    - path: /etc/configs
      source_glob: "conf/*.yaml"
`
	refs, err := FindLocalFileReferences(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs (*.yaml), got %d: %v", len(refs), refs)
	}

	paths := map[string]bool{}
	for _, ref := range refs {
		paths[ref["source_path"]] = true
	}
	if !paths["conf/a.yaml"] {
		t.Error("expected conf/a.yaml in results")
	}
	if !paths["conf/b.yaml"] {
		t.Error("expected conf/b.yaml in results")
	}
	if paths["conf/c.txt"] {
		t.Error("c.txt should not match *.yaml glob")
	}
}

func TestFindLocalFileReferences_SourceGlobSkipsDirectories(t *testing.T) {
	dir := t.TempDir()

	confDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(filepath.Join(confDir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "file.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := `
content:
  add_files:
    - path: /etc/data
      source_glob: "data/*"
`
	refs, err := FindLocalFileReferences(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should only match the file, not the subdirectory
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref (file only, not dir), got %d: %v", len(refs), refs)
	}
	if refs[0]["source_path"] != "data/file.txt" {
		t.Errorf("expected data/file.txt, got %q", refs[0]["source_path"])
	}
}

func TestFindLocalFileReferences_SourceGlobNoMatches(t *testing.T) {
	dir := t.TempDir()

	manifest := `
content:
  add_files:
    - path: /etc/configs
      source_glob: "nonexistent/*.yaml"
`
	refs, err := FindLocalFileReferences(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No matches is not an error — AIB handles allow_empty semantics
	if len(refs) != 0 {
		t.Fatalf("expected 0 refs for no-match glob, got %d", len(refs))
	}
}

func TestFindLocalFileReferences_SourceGlobParentDir(t *testing.T) {
	dir := t.TempDir()

	// Create files in parent directory relative to a subdir
	if err := os.WriteFile(filepath.Join(dir, "root.conf"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "manifests")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	manifest := `
content:
  add_files:
    - path: /etc/configs
      source_glob: "../*.conf"
`
	refs, err := FindLocalFileReferences(manifest, subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d: %v", len(refs), refs)
	}
	if refs[0]["source_path"] != "../root.conf" {
		t.Errorf("expected ../root.conf, got %q", refs[0]["source_path"])
	}
}

func TestFindLocalFileReferences_MixedSourceTypes(t *testing.T) {
	dir := t.TempDir()

	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "app.conf"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := `
content:
  add_files:
    - path: /usr/bin/app
      source_path: my-binary
    - path: /etc/configs
      source_glob: "conf/*.conf"
    - path: /etc/note.txt
      text: "hello"
    - path: /etc/data.json
      url: https://example.com/data.json
`
	refs, err := FindLocalFileReferences(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// source_path (1) + glob match (1) = 2 refs; text and url are skipped
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(refs), refs)
	}
	paths := map[string]bool{}
	for _, ref := range refs {
		paths[ref["source_path"]] = true
	}
	if !paths["my-binary"] {
		t.Errorf("expected my-binary in results, got %v", refs)
	}
	if !paths["conf/app.conf"] {
		t.Errorf("expected conf/app.conf in results, got %v", refs)
	}
}

func TestFindLocalFileReferences_QMSourceGlob(t *testing.T) {
	dir := t.TempDir()

	qmDir := filepath.Join(dir, "qm-files")
	if err := os.MkdirAll(qmDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qmDir, "policy.conf"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := `
qm:
  content:
    add_files:
      - path: /etc/qm
        source_glob: "qm-files/*.conf"
`
	refs, err := FindLocalFileReferences(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0]["source_path"] != "qm-files/policy.conf" {
		t.Errorf("expected qm-files/policy.conf, got %q", refs[0]["source_path"])
	}
}

func TestFindLocalFileReferences_RecursiveGlob(t *testing.T) {
	dir := t.TempDir()

	// Create a nested directory structure mimicking the CES2026 manifest
	for _, path := range []string{
		"files/root_fs/etc/lighttpd/lighttpd.conf",
		"files/root_fs/etc/lighttpd/conf.d/cgi.conf",
		"files/root_fs/etc/chrony.conf",
		"files/root_fs/usr/share/lighttpd/index.html",
		"files/root_fs/usr/share/lighttpd/css/styles.css",
		"files/root_fs/usr/lib/tmpfiles.d/lighttpd-webroot.conf",
	} {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	manifest := `
content:
  add_files:
    - source_glob: "files/root_fs/etc/**/*"
      path: /etc/
      preserve_path: true
    - source_glob: "files/root_fs/usr/**/*"
      path: /usr/
      preserve_path: true
`
	refs, err := FindLocalFileReferences(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// etc: lighttpd.conf, conf.d/cgi.conf, chrony.conf = 3
	// usr: index.html, css/styles.css, tmpfiles.d/lighttpd-webroot.conf = 3
	if len(refs) != 6 {
		t.Fatalf("expected 6 refs from recursive glob, got %d:", len(refs))
	}

	paths := map[string]bool{}
	for _, ref := range refs {
		paths[ref["source_path"]] = true
	}
	for _, expected := range []string{
		"files/root_fs/etc/lighttpd/lighttpd.conf",
		"files/root_fs/etc/lighttpd/conf.d/cgi.conf",
		"files/root_fs/etc/chrony.conf",
		"files/root_fs/usr/share/lighttpd/index.html",
		"files/root_fs/usr/share/lighttpd/css/styles.css",
		"files/root_fs/usr/lib/tmpfiles.d/lighttpd-webroot.conf",
	} {
		if !paths[expected] {
			t.Errorf("expected %q in results, got: %v", expected, paths)
		}
	}
}

func TestExpandSourceGlob_DoubleStarAllFiles(t *testing.T) {
	dir := t.TempDir()

	// Create nested structure
	for _, path := range []string{
		"a.txt",
		"sub/b.txt",
		"sub/deep/c.txt",
	} {
		full := filepath.Join(dir, "data", path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := expandSourceGlob("data/**/*", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files from **/* glob, got %d: %v", len(files), files)
	}
}

func TestExpandSourceGlob_DoubleStarWithExtension(t *testing.T) {
	dir := t.TempDir()

	for _, path := range []string{
		"a.yaml",
		"a.txt",
		"sub/b.yaml",
		"sub/b.txt",
	} {
		full := filepath.Join(dir, "conf", path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := expandSourceGlob("conf/**/*.yaml", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 .yaml files, got %d: %v", len(files), files)
	}
}

func TestExpandSourceGlob_DoubleStarNestedSubdir(t *testing.T) {
	dir := t.TempDir()

	for _, path := range []string{
		"a/b/nested/file.yaml",
		"nested/other.yaml",
		"top.yaml",
	} {
		full := filepath.Join(dir, "src", path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Pattern **/nested/*.yaml should match files inside any "nested" dir
	files, err := expandSourceGlob("src/**/nested/*.yaml", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files matching **/nested/*.yaml, got %d: %v", len(files), files)
	}

	paths := map[string]bool{}
	for _, f := range files {
		paths[f] = true
	}
	if !paths["src/a/b/nested/file.yaml"] {
		t.Error("expected src/a/b/nested/file.yaml")
	}
	if !paths["src/nested/other.yaml"] {
		t.Error("expected src/nested/other.yaml")
	}
	if paths["src/top.yaml"] {
		t.Error("src/top.yaml should not match **/nested/*.yaml")
	}
}

func TestExpandSourceGlob_InvalidPattern(t *testing.T) {
	_, err := expandSourceGlob("[invalid", t.TempDir())
	if err == nil {
		t.Fatal("expected error for invalid glob pattern")
	}
}

func TestExpandSourceGlob_AbsolutePattern(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "abs.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	pattern := filepath.Join(dir, "*.txt")
	files, err := expandSourceGlob(pattern, "/some/other/dir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if !filepath.IsAbs(files[0]) {
		t.Errorf("expected absolute path for absolute pattern, got %q", files[0])
	}
}

func TestFindLocalFileReferencesForWorkspaceBuild_SkipsClusterPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.bin"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := `
content:
  add_files:
    - path: /usr/bin/app
      source_path: /workspace/src/build/app
    - path: /usr/bin/local
      source_path: local.bin
    - dest: /etc/
      source_glob: /workspace/src/etc/**/*.conf
`
	refs, err := FindLocalFileReferencesForWorkspaceBuild(manifest, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 laptop ref, got %d: %v", len(refs), refs)
	}
	if refs[0]["source_path"] != "local.bin" {
		t.Errorf("source_path = %q, want local.bin", refs[0]["source_path"])
	}
}

func TestFindLocalFileReferences_DoesNotSkipWorkspaceWithoutFlag(t *testing.T) {
	manifest := `
content:
  add_files:
    - path: /usr/bin/app
      source_path: /workspace/src/build/app
`
	refs, err := FindLocalFileReferences(manifest, "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref when not excluding workspace paths, got %d", len(refs))
	}
}
