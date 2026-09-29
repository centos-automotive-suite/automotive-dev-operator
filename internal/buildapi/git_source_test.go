package buildapi

import (
	"context"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGitCredentialsOwnership(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "git-auth", Namespace: "test", Annotations: map[string]string{labels.RequestedBy: "alice", api.GitCredentialsHostAnnotation: "https://git.example.com"}}, Type: corev1.SecretTypeBasicAuth, Data: map[string][]byte{corev1.BasicAuthUsernameKey: []byte("alice"), corev1.BasicAuthPasswordKey: []byte("token")}}
	c := newFakeClient(secret)
	source := &api.GitSource{URL: "https://git.example.com/os.git", CredentialsSecretRef: secret.Name}
	for _, user := range []string{"alice", "bob", ""} {
		err := validateGitCredentials(context.Background(), c, "test", user, source)
		if (err == nil) != (user == "alice") {
			t.Fatalf("user=%q error=%v", user, err)
		}
	}
}

func TestGitSourceRequest(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mutate  func(*buildcontract.BuildRequest)
		invalid bool
	}{
		{"git", func(r *buildcontract.BuildRequest) {}, false},
		{"inline manifest", func(r *buildcontract.BuildRequest) { r.Manifest = "name: demo" }, true},
		{"local lockfile", func(r *buildcontract.BuildRequest) { r.Lockfile = `{"version":1}` }, true},
		{"upload", func(r *buildcontract.BuildRequest) { r.HasLocalFiles = true }, true},
		{"workspace", func(r *buildcontract.BuildRequest) { r.Workspace = "dev" }, true},
		{"disk", func(r *buildcontract.BuildRequest) { r.Mode = buildcontract.ModeDisk }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := buildcontract.BuildRequest{Name: "git-build", GitSource: &api.GitSource{URL: "https://git.example.com/os.git", ManifestPath: "images/demo.aib.yml"}}
			tt.mutate(&r)
			if err := validateBuildRequest(&r); (err != nil) != tt.invalid {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestGitSourceDefaultsDeferred(t *testing.T) {
	r := buildcontract.BuildRequest{GitSource: &api.GitSource{URL: "https://git.example.com/os.git", ManifestPath: "demo.aib.yml"}, ArchitectureFallback: "x86_64"}
	if err := applyBuildDefaults(&r); err != nil {
		t.Fatal(err)
	}
	if r.Target != "" || r.Architecture != "" || r.ArchitectureFallback != "amd64" || r.ExportFormat != "" {
		t.Fatalf("premature defaults: %+v", r)
	}
	r.Target = " "
	if err := applyBuildDefaults(&r); err == nil {
		t.Fatal("explicit whitespace target accepted")
	}
}

func TestGitArchitectureFallbackValidation(t *testing.T) {
	for _, tt := range []struct {
		name     string
		git      bool
		arch     buildcontract.Architecture
		fallback buildcontract.Architecture
		invalid  bool
	}{
		{name: "git fallback", git: true, fallback: "amd64"},
		{name: "non-git fallback", fallback: "amd64", invalid: true},
		{name: "explicit and fallback", git: true, arch: "arm64", fallback: "amd64", invalid: true},
		{name: "invalid fallback", git: true, fallback: "ppc64le", invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := buildcontract.BuildRequest{Name: "test", Manifest: "name: test", Architecture: tt.arch, ArchitectureFallback: tt.fallback}
			if tt.git {
				req.GitSource = &api.GitSource{URL: "https://git.example.com/os.git", ManifestPath: "demo.aib.yml"}
				req.Manifest = ""
			}
			err := validateBuildRequest(&req)
			if err == nil {
				err = applyBuildDefaults(&req)
			}
			if (err != nil) != tt.invalid {
				t.Fatalf("validation error = %v, request = %+v", err, req)
			}
		})
	}
}
