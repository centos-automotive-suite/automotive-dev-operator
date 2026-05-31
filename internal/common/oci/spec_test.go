package oci

import (
	"strings"
	"testing"
)

func TestSpecParses(t *testing.T) {
	s := Get()
	if s.AnnotationPrefix == "" {
		t.Fatal("annotationPrefix is empty")
	}
	if !strings.HasSuffix(s.AnnotationPrefix, "/") {
		t.Fatalf("annotationPrefix %q must end with /", s.AnnotationPrefix)
	}
	if len(s.Annotations.Manifest.Required) == 0 {
		t.Fatal("no required manifest annotations")
	}
	if len(s.Annotations.Manifest.Optional) == 0 {
		t.Fatal("no optional manifest annotations")
	}
	if len(s.Annotations.Layer.Custom) == 0 {
		t.Fatal("no custom layer annotations")
	}
	if len(s.MediaTypes.DiskFormats) == 0 {
		t.Fatal("no disk format media types")
	}
	if len(s.MediaTypes.CompressionSuffixes) == 0 {
		t.Fatal("no compression suffixes")
	}
	if len(s.MediaTypes.ContainerLayers) == 0 {
		t.Fatal("no container layer media types")
	}
	if len(s.ReferrerTypes) == 0 {
		t.Fatal("no referrer types")
	}
}

func TestAnnotationKey(t *testing.T) {
	s := Get()
	got := s.AnnotationKey("distro")
	want := "automotive.sdv.cloud.redhat.com/distro"
	if got != want {
		t.Fatalf("AnnotationKey(distro) = %q, want %q", got, want)
	}
}

func TestReferrerFileMap(t *testing.T) {
	m := Get().ReferrerFileMap()
	expected := map[string]string{
		"application/vnd.automotive.manifest.v1+yaml":    "manifest.aib.yml",
		"application/vnd.automotive.sources.v1+tar+gzip": "build-sources.tar.gz",
		"application/vnd.osbuild.manifest.v1+json":       "image.json",
	}
	for artType, filename := range expected {
		if m[artType] != filename {
			t.Errorf("ReferrerFileMap[%q] = %q, want %q", artType, m[artType], filename)
		}
	}
}

func TestAllManifestAnnotationKeys(t *testing.T) {
	keys := Get().AllManifestAnnotationKeys()
	required := map[string]bool{"distro": true, "target": true, "arch": true}
	optional := map[string]bool{
		"parts": true, "multi-layer": true, "default-partitions": true,
		"builder-image": true, "aib-version": true, "automotive-image-builder": true,
		"aib-command": true, "task-bundle-ref": true, "custom-defines": true,
		"aib-extra-args": true, "export-format": true,
	}

	for _, ak := range keys {
		if !required[ak.Key] && !optional[ak.Key] {
			t.Errorf("unexpected annotation key %q", ak.Key)
		}
		if ak.Var == "" {
			t.Errorf("annotation key %q has empty var name", ak.Key)
		}
	}
	for k := range required {
		found := false
		for _, ak := range keys {
			if ak.Key == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required annotation key %q", k)
		}
	}
}

func TestMediaTypeComposition(t *testing.T) {
	s := Get()
	cases := []struct {
		format      string
		compression string
		want        string
	}{
		{"raw", "gzip", "application/vnd.automotive.disk.raw+gzip"},
		{"raw", "lz4", "application/vnd.automotive.disk.raw+lz4"},
		{"raw", "xz", "application/vnd.automotive.disk.raw+xz"},
		{"qcow2", "gzip", "application/vnd.automotive.disk.qcow2+gzip"},
		{"qcow2", "lz4", "application/vnd.automotive.disk.qcow2+lz4"},
		{"qcow2", "xz", "application/vnd.automotive.disk.qcow2+xz"},
		{"simg", "gzip", "application/vnd.automotive.disk.simg+gzip"},
		{"simg", "lz4", "application/vnd.automotive.disk.simg+lz4"},
		{"simg", "xz", "application/vnd.automotive.disk.simg+xz"},
	}
	for _, tc := range cases {
		got := s.MediaTypes.DiskFormats[tc.format] + s.MediaTypes.CompressionSuffixes[tc.compression]
		if got != tc.want {
			t.Errorf("%s+%s = %q, want %q", tc.format, tc.compression, got, tc.want)
		}
	}
}

func TestShellVarsContainsExpectedAssignments(t *testing.T) {
	vars := Get().ShellVars()
	expected := []string{
		`OCI_ANNOTATION_PREFIX="automotive.sdv.cloud.redhat.com/"`,
		`OCI_ANN_DISTRO="automotive.sdv.cloud.redhat.com/distro"`,
		`OCI_ANN_MULTI_LAYER="automotive.sdv.cloud.redhat.com/multi-layer"`,
		`OCI_MEDIA_DISK_RAW="application/vnd.automotive.disk.raw"`,
		`OCI_MEDIA_DISK_QCOW2="application/vnd.automotive.disk.qcow2"`,
		`OCI_MEDIA_DISK_SIMG="application/vnd.automotive.disk.simg"`,
		`OCI_COMPRESS_SUFFIX_GZIP="+gzip"`,
		`OCI_MEDIA_LAYER_GZIP="application/vnd.oci.image.layer.v1.tar+gzip"`,
		`OCI_MEDIA_OCTETSTREAM="application/octet-stream"`,
		`OCI_LAYER_ANN_PARTITION="automotive.sdv.cloud.redhat.com/partition"`,
		`OCI_LAYER_ANN_ORG_OPENCONTAINERS_IMAGE_TITLE="org.opencontainers.image.title"`,
		`OCI_REFERRER_TYPE_AIB_MANIFEST="application/vnd.automotive.manifest.v1+yaml"`,
		`OCI_REFERRER_FILE_AIB_MANIFEST="manifest.aib.yml"`,
		`OCI_REFERRER_TYPE_BUILD_SOURCES="application/vnd.automotive.sources.v1+tar+gzip"`,
		`OCI_REFERRER_TYPE_OSBUILD_MANIFEST="application/vnd.osbuild.manifest.v1+json"`,
	}
	for _, e := range expected {
		if !strings.Contains(vars, e) {
			t.Errorf("ShellVars() missing: %s", e)
		}
	}
}

func TestShellVarsDeterministic(t *testing.T) {
	a := Get().ShellVars()
	b := Get().ShellVars()
	if a != b {
		t.Fatal("ShellVars() output is not deterministic")
	}
}
