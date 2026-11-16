package workspaceagent

import (
	"strings"
	"testing"
)

// The serving certificate is issued for the Service, so its name must be a
// DNS label, and no build can be named into a workspace's Service or another
// build's.
func TestUploadServiceNameIsADNSLabelOfItsOwn(t *testing.T) {
	if got := UploadServiceName("my-build"); got != "imagebuild-my-build-upload" {
		t.Errorf("UploadServiceName(my-build) = %q", got)
	}
	long := strings.Repeat("b", 60)
	for _, build := range []string{long, "my.build", "other.build"} {
		name := UploadServiceName(build)
		if len(name) > 63 || strings.Contains(name, ".") || !strings.HasPrefix(name, "ib-") {
			t.Errorf("UploadServiceName(%q) = %q, want a digest label", build, name)
		}
	}
	if UploadServiceName("my.build") == UploadServiceName("other.build") {
		t.Error("two builds share an upload Service")
	}
	for _, build := range []string{"my-build", long} {
		for _, workspace := range []string{"my-build", long} {
			if UploadServiceName(build) == ServiceName(workspace) {
				t.Errorf("build %q and workspace %q share a Service", build, workspace)
			}
		}
	}
	if got := UploadTokenSecretName("my-build"); got != "imagebuild-my-build-upload-token" {
		t.Errorf("UploadTokenSecretName = %q", got)
	}
	if got := UploadTLSSecretName("my-build"); got != "imagebuild-my-build-upload-tls" {
		t.Errorf("UploadTLSSecretName = %q", got)
	}
}
