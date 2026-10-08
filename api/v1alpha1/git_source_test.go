package v1alpha1

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateGitSource(t *testing.T) {
	for _, tt := range []struct {
		name, url, revision, manifest string
		invalid                       bool
	}{
		{"branch", "https://git.example.com/team/os.git", "main", "images/demo.aib.yml", false},
		{"default", "https://git.example.com/team/os.git", "", "demo.mpp.yml", false},
		{"credentials", "https://user:token@git.example.com/os.git", "main", "demo.aib.yml", true},
		{"local", "file:///tmp/repo", "main", "demo.aib.yml", true},
		{"option", "https://git.example.com/os.git", "--upload-pack=evil", "demo.aib.yml", true},
		{"short SHA", "https://git.example.com/os.git", "a1b2c3d", "demo.aib.yml", true},
		{"parent", "https://git.example.com/os.git", "main", "../demo.aib.yml", true},
		{"absolute", "https://git.example.com/os.git", "main", "/demo.aib.yml", true},
		{"suffix", "https://git.example.com/os.git", "main", "demo.yaml", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGitSource(&GitSource{URL: tt.url, Revision: tt.revision, ManifestPath: tt.manifest})
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, invalid = %v", err, tt.invalid)
			}
		})
	}
}

func TestNormalizeGitArchitectureFallback(t *testing.T) {
	for _, tt := range []struct {
		value, want string
		invalid     bool
	}{
		{value: "", want: ""},
		{value: "x86_64", want: "amd64"},
		{value: "aarch64", want: "arm64"},
		{value: "amd64", want: "amd64"},
		{value: " ", invalid: true},
		{value: "ppc64le", invalid: true},
	} {
		got, err := NormalizeGitArchitectureFallback(tt.value)
		if (err != nil) != tt.invalid || got != tt.want {
			t.Fatalf("fallback %q: got %q, error %v", tt.value, got, err)
		}
	}
}

func TestValidateGitLockfilePath(t *testing.T) {
	for _, tt := range []struct {
		path    string
		invalid bool
	}{
		{"", false},
		{"images/demo.aib.lock", false},
		{"locks/release.json", false},
		{"../outside.lock", true},
		{"/absolute.lock", true},
		{"locks/../release.lock", true},
		{"locks\\release.lock", true},
		{".", true},
		{"..", true},
	} {
		source := &GitSource{URL: "https://git.example.com/os.git", ManifestPath: "demo.aib.yml", LockfilePath: tt.path}
		if err := ValidateGitSource(source); (err != nil) != tt.invalid {
			t.Fatalf("path %q: error=%v, invalid=%v", tt.path, err, tt.invalid)
		}
	}
}

func TestValidateGitCredentialsSecret(t *testing.T) {
	source := &GitSource{URL: "https://git.example.com/team/os.git"}
	secret := &corev1.Secret{
		Type:       corev1.SecretTypeBasicAuth,
		Data:       map[string][]byte{corev1.BasicAuthUsernameKey: []byte("user"), corev1.BasicAuthPasswordKey: []byte("token")},
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{GitCredentialsHostAnnotation: "https://git.example.com"}},
	}
	if err := ValidateGitCredentialsSecret(source, secret); err != nil {
		t.Fatal(err)
	}
	secret.Annotations[GitCredentialsHostAnnotation] = "https://other.example.com"
	if err := ValidateGitCredentialsSecret(source, secret); err == nil {
		t.Fatal("accepted credentials for another host")
	}
}

func TestValidateGitSourceSpec(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mutate  func(*ImageBuildSpec)
		invalid bool
	}{
		{"git", func(s *ImageBuildSpec) {}, false},
		{"OCI repository", func(s *ImageBuildSpec) { s.AIB.OCIRepoImages = []string{"quay.io/example/repo:latest"} }, false},
		{"cache PVC", func(s *ImageBuildSpec) { s.BuildCachePVC = "cache" }, true},
		{"workspace", func(s *ImageBuildSpec) { s.Workspace = "dev" }, true},
		{"manifest", func(s *ImageBuildSpec) { s.AIB.Manifest = "name: demo" }, true},
		{"lockfile", func(s *ImageBuildSpec) { s.AIB.Lockfile = `{"version":1}` }, true},
		{"uploads", func(s *ImageBuildSpec) { s.AIB.InputFilesServer = true }, true},
		{"disk", func(s *ImageBuildSpec) { s.AIB.Mode = "disk" }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec := &ImageBuildSpec{AIB: &AIBSpec{GitSource: &GitSource{URL: "https://git.example.com/os.git", ManifestPath: "demo.aib.yml"}, Mode: "package"}}
			tt.mutate(spec)
			if err := ValidateGitSourceSpec(spec); (err != nil) != tt.invalid {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
