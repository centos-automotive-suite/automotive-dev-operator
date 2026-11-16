package buildapi

import (
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestArtifactNameValidationAndSpec(t *testing.T) {
	request := func(name string) *buildcontract.BuildRequest {
		return &buildcontract.BuildRequest{Name: "test", Manifest: "name: test\n", Mode: buildcontract.ModeBootc, ArtifactName: name}
	}
	for _, name := range []string{"", "disk", "auto-osbuild-qemu-autosd10-qa-regular@debug-x86_64-1.abc", strings.Repeat("a", 200)} {
		req := request(name)
		if err := validateBuildRequest(req); err != nil {
			t.Fatalf("%q rejected: %v", name, err)
		}
		if got := buildExportSpec(req).ArtifactName; got != name {
			t.Fatalf("spec artifact name = %q, want %q", got, name)
		}
	}
	for _, name := range []string{"../disk", "a/b", "-disk", ".disk", "disk name", "disk$x", strings.Repeat("a", 201)} {
		if err := validateBuildRequest(request(name)); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}
