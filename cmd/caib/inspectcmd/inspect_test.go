package inspectcmd

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	testFormatJSON = "json"
	testFormatYAML = "yaml"
)

func TestSplitReference(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"tag", "quay.io/org/repo:v1", "quay.io/org/repo"},
		{"digest", "quay.io/org/repo@sha256:abc123", "quay.io/org/repo"},
		{"no tag or digest", "quay.io/org/repo", "quay.io/org/repo"},
		{"port with tag", "localhost:5000/repo:latest", "localhost:5000/repo"},
		{"port no tag", "localhost:5000/repo", "localhost:5000/repo"},
		{"digest with tag", "quay.io/org/repo:v1@sha256:abc", "quay.io/org/repo:v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitReference(tt.ref)
			if got != tt.want {
				t.Errorf("splitReference(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func fullAnnotations() map[string]string {
	return map[string]string{
		ociSpec.AnnotationPrefix + "distro":                   "autosd",
		ociSpec.AnnotationPrefix + "target":                   "qemu",
		ociSpec.AnnotationPrefix + "arch":                     "amd64",
		ociSpec.AnnotationPrefix + "automotive-image-builder": "quay.io/aib@sha256:abc",
		ociSpec.AnnotationPrefix + "builder-image":            "quay.io/builder@sha256:def",
		ociSpec.AnnotationPrefix + "aib-version":              "1.3.0",
		ociSpec.AnnotationPrefix + "task-bundle-ref":          "quay.io/tasks@sha256:789",
		ociSpec.AnnotationPrefix + "aib-command":              "aib build --distro autosd --target qemu",
	}
}

func TestBuildRebuildCommand_Bootc(t *testing.T) {
	annotations := fullAnnotations()
	referrerTypes := map[string]bool{
		"application/vnd.automotive.manifest.v1+yaml": true,
	}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	for _, want := range []string{
		"caib image build",
		"manifest.aib.yml",
		"--distro autosd",
		"--target qemu",
		"--arch amd64",
		"--aib-image quay.io/aib@sha256:abc",
		"--builder-image quay.io/builder@sha256:def",
		"--task-bundle-ref quay.io/tasks@sha256:789",
		"--secure",
		"--reproducible",
		"--push <registry>",
		"--push-disk <registry>",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("rebuild command missing %q\ngot: %s", want, cmd)
		}
	}
}

func TestBuildRebuildCommand_DevBuild(t *testing.T) {
	annotations := fullAnnotations()
	annotations[ociSpec.AnnotationPrefix+"aib-command"] = "aib-dev --verbose build --distro autosd"
	referrerTypes := map[string]bool{}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if !strings.Contains(cmd, "caib image build-dev") {
		t.Errorf("expected build-dev command, got: %s", cmd)
	}
	if !strings.Contains(cmd, "<manifest.aib.yml>") {
		t.Errorf("expected placeholder manifest (no referrer), got: %s", cmd)
	}
	if strings.Contains(cmd, "--push-disk") {
		t.Errorf("build-dev should not have --push-disk, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_NoSecure(t *testing.T) {
	annotations := fullAnnotations()
	delete(annotations, ociSpec.AnnotationPrefix+"task-bundle-ref")
	referrerTypes := map[string]bool{}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if strings.Contains(cmd, "--secure") {
		t.Errorf("should not have --secure without task-bundle-ref, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_CustomDefines(t *testing.T) {
	annotations := fullAnnotations()
	annotations[ociSpec.AnnotationPrefix+"custom-defines"] = "use_debug=true\nfoo=bar"
	referrerTypes := map[string]bool{}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if !strings.Contains(cmd, "--define use_debug=true") {
		t.Errorf("missing --define use_debug=true, got: %s", cmd)
	}
	if !strings.Contains(cmd, "--define foo=bar") {
		t.Errorf("missing --define foo=bar, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_ExtraArgs(t *testing.T) {
	annotations := fullAnnotations()
	annotations[ociSpec.AnnotationPrefix+"aib-extra-args"] = "--verbose\n--cache-max-size=unlimited"
	referrerTypes := map[string]bool{}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if !strings.Contains(cmd, "--extra-args --verbose") {
		t.Errorf("missing --extra-args --verbose, got: %s", cmd)
	}
	if !strings.Contains(cmd, "--extra-args --cache-max-size=unlimited") {
		t.Errorf("missing --extra-args --cache-max-size=unlimited, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_ExportFormat(t *testing.T) {
	annotations := fullAnnotations()
	annotations[ociSpec.AnnotationPrefix+"export-format"] = "simg"
	referrerTypes := map[string]bool{}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if !strings.Contains(cmd, "--format simg") {
		t.Errorf("missing --format simg, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_RestoreSources(t *testing.T) {
	annotations := fullAnnotations()
	referrerTypes := map[string]bool{
		"application/vnd.automotive.manifest.v1+yaml":    true,
		"application/vnd.automotive.sources.v1+tar+gzip": true,
	}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if !strings.Contains(cmd, "--restore-sources quay.io/org/repo@sha256:abc123") {
		t.Errorf("missing --restore-sources with image ref, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_NoRestoreSourcesWithoutReferrer(t *testing.T) {
	annotations := fullAnnotations()
	referrerTypes := map[string]bool{
		"application/vnd.automotive.manifest.v1+yaml": true,
	}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if strings.Contains(cmd, "--restore-sources") {
		t.Errorf("should not have --restore-sources without sources referrer, got: %s", cmd)
	}
}

func TestBuildRebuildCommand_NoBuilderImage(t *testing.T) {
	annotations := fullAnnotations()
	delete(annotations, ociSpec.AnnotationPrefix+"builder-image")
	referrerTypes := map[string]bool{}

	cmd := buildRebuildCommand("quay.io/org/repo:v1", "sha256:abc123", annotations, referrerTypes)

	if strings.Contains(cmd, "--builder-image") {
		t.Errorf("should not have --builder-image when not set, got: %s", cmd)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPrintStructured_JSON(t *testing.T) {
	format := testFormatJSON
	h := NewHandler(Options{OutputFormat: &format})

	annotations := fullAnnotations()
	referrers := []referrerInfo{
		{ArtifactType: "application/vnd.automotive.manifest.v1+yaml", Digest: "sha256:aaa"},
	}
	referrerTypes := map[string]bool{
		"application/vnd.automotive.manifest.v1+yaml": true,
	}

	out := captureStdout(t, func() {
		h.printStructured(testFormatJSON, "quay.io/org/repo:v1", "sha256:abc123", annotations, referrers, referrerTypes)
	})

	var parsed provenanceOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, out)
	}

	if parsed.Reference != "quay.io/org/repo:v1" {
		t.Errorf("reference = %q, want quay.io/org/repo:v1", parsed.Reference)
	}
	if parsed.Digest != "sha256:abc123" {
		t.Errorf("digest = %q, want sha256:abc123", parsed.Digest)
	}
	if parsed.Annotations["distro"] != "autosd" {
		t.Errorf("annotations[distro] = %q, want autosd", parsed.Annotations["distro"])
	}
	if _, ok := parsed.Annotations["automotive.sdv.cloud.redhat.com/distro"]; ok {
		t.Error("JSON annotations should have prefix stripped")
	}
	if len(parsed.Referrers) != 1 {
		t.Errorf("expected 1 referrer, got %d", len(parsed.Referrers))
	}
	if !strings.Contains(parsed.RebuildCmd, "--secure") {
		t.Error("rebuild command should contain --secure")
	}
}

func TestPrintStructured_YAML(t *testing.T) {
	format := testFormatYAML
	h := NewHandler(Options{OutputFormat: &format})

	annotations := fullAnnotations()
	referrers := []referrerInfo{
		{ArtifactType: "application/vnd.osbuild.manifest.v1+json", Digest: "sha256:bbb"},
	}
	referrerTypes := map[string]bool{
		"application/vnd.osbuild.manifest.v1+json": true,
	}

	out := captureStdout(t, func() {
		h.printStructured(testFormatYAML, "quay.io/org/repo:v1", "sha256:abc123", annotations, referrers, referrerTypes)
	})

	var parsed provenanceOutput
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid YAML output: %v\nraw: %s", err, out)
	}

	if parsed.Reference != "quay.io/org/repo:v1" {
		t.Errorf("reference = %q, want quay.io/org/repo:v1", parsed.Reference)
	}
	if parsed.Annotations["distro"] != "autosd" {
		t.Errorf("annotations[distro] = %q, want autosd", parsed.Annotations["distro"])
	}
}

func TestPrintProvenance_Table(t *testing.T) {
	h := NewHandler(Options{})

	annotations := fullAnnotations()
	referrerTypes := map[string]bool{
		"application/vnd.automotive.manifest.v1+yaml":    true,
		"application/vnd.automotive.sources.v1+tar+gzip": true,
	}

	out := captureStdout(t, func() {
		h.printProvenance("quay.io/org/repo:v1", "sha256:abc", annotations, nil, referrerTypes)
	})

	if !strings.Contains(out, "Build Provenance") {
		t.Error("missing Build Provenance header")
	}
	if !strings.Contains(out, "autosd") {
		t.Error("missing distro value")
	}
	if !strings.Contains(out, "quay.io/builder@sha256:def") {
		t.Error("missing builder-image value")
	}
}

func TestPrintProvenance_FullAIBCommand(t *testing.T) {
	h := NewHandler(Options{})

	longCmd := strings.Repeat("x", 200)
	annotations := map[string]string{
		ociSpec.AnnotationPrefix + "aib-command": longCmd,
	}
	referrerTypes := map[string]bool{}

	out := captureStdout(t, func() {
		h.printProvenance("ref", "dig", annotations, nil, referrerTypes)
	})

	if !strings.Contains(out, longCmd) {
		t.Error("aib-command should not be truncated")
	}
	if strings.Contains(out, "...") {
		t.Error("should not have truncation ellipsis")
	}
}

func TestPrintProvenance_NoAnnotations(t *testing.T) {
	h := NewHandler(Options{})
	annotations := map[string]string{}
	referrerTypes := map[string]bool{}

	out := captureStdout(t, func() {
		h.printProvenance("ref", "dig", annotations, nil, referrerTypes)
	})

	if !strings.Contains(out, "No automotive build annotations found") {
		t.Error("should show no-annotations message")
	}
}
