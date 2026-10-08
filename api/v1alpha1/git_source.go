package v1alpha1

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const GitCredentialsHostAnnotation = "tekton.dev/git-0"

const (
	gitArchAMD64 = "amd64"
	gitArchARM64 = "arm64"
)

// NormalizeGitArchitectureFallback validates an optional architecture supplied
// before the Git manifest target is known.
func NormalizeGitArchitectureFallback(arch string) (string, error) {
	if arch == "" {
		return "", nil
	}
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case gitArchAMD64, "x86_64":
		return gitArchAMD64, nil
	case gitArchARM64, "aarch64":
		return gitArchARM64, nil
	default:
		return "", fmt.Errorf("invalid architecture fallback %q: must be amd64, arm64, x86_64, or aarch64", arch)
	}
}

// GitSource selects build inputs from one repository commit. A lockfile named
// after the manifest (for example, simple.aib.lock for simple.aib.yml) is used
// when present, unless LockfilePath selects another file in the same commit.
type GitSource struct {
	// +kubebuilder:validation:MaxLength=2048
	URL string `json:"url"`
	// Revision is a branch, tag, or commit. Empty selects the remote HEAD.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Revision string `json:"revision,omitempty"`
	// ManifestPath is relative to the repository root.
	// +kubebuilder:validation:MaxLength=1024
	ManifestPath string `json:"manifestPath"`
	// LockfilePath optionally selects a repository-relative lockfile. When set,
	// the file must exist in the selected commit.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	LockfilePath string `json:"lockfilePath,omitempty"`
	// CredentialsSecretRef references a kubernetes.io/basic-auth Secret.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	CredentialsSecretRef string `json:"credentialsSecretRef,omitempty"`
}

func ValidateGitSource(source *GitSource) error {
	if source == nil {
		return nil
	}
	u, err := url.Parse(source.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(source.URL) > 2048 {
		return fmt.Errorf("git source URL must be HTTPS without embedded credentials, query, or fragment")
	}
	if strings.ContainsAny(source.URL, "\r\n\x00") {
		return fmt.Errorf("invalid git source URL")
	}
	ref := source.Revision
	if len(ref) > 256 || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "~^:?*[\\") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.IndexFunc(ref, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("git revision must be a branch, tag, or full commit ID")
	}
	if len(ref) >= 7 && len(ref) < 40 && strings.IndexFunc(ref, func(r rune) bool { return !strings.ContainsRune("0123456789abcdefABCDEF", r) }) == -1 {
		return fmt.Errorf("git revision must use a full commit ID; qualify a hex-only branch or tag as refs/heads/<name> or refs/tags/<name>")
	}
	p := source.ManifestPath
	if !cleanGitRepositoryPath(p) || (!strings.HasSuffix(p, ".aib.yml") && !strings.HasSuffix(p, ".mpp.yml")) {
		return fmt.Errorf("git manifest path must be a clean repository-relative .aib.yml or .mpp.yml path")
	}
	if p := source.LockfilePath; p != "" && !cleanGitRepositoryPath(p) {
		return fmt.Errorf("git lockfile path must be clean and repository-relative")
	}
	if name := source.CredentialsSecretRef; name != "" && len(validation.IsDNS1123Subdomain(name)) != 0 {
		return fmt.Errorf("invalid git credentials Secret name")
	}
	return nil
}

func cleanGitRepositoryPath(p string) bool {
	return p != "" && p != "." && p != ".." && len(p) <= 1024 && !path.IsAbs(p) && path.Clean(p) == p && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\r\n\x00")
}

// ValidateGitSourceSpec checks Git input combinations for API and controller paths.
func ValidateGitSourceSpec(spec *ImageBuildSpec) error {
	if spec == nil || spec.GetGitSource() == nil {
		return nil
	}
	if err := ValidateGitSource(spec.GetGitSource()); err != nil {
		return err
	}
	if spec.GetMode() == "disk" || spec.GetManifest() != "" || spec.GetLockfile() != "" || spec.GetInputFilesServer() || spec.Workspace != "" || spec.BuildCachePVC != "" {
		return fmt.Errorf("git source cannot be combined with disk mode, inline inputs, uploads, workspace, or cache PVC")
	}
	return nil
}

// ValidateGitCredentialsSecret binds a basic-auth Secret to one HTTPS origin.
func ValidateGitCredentialsSecret(source *GitSource, secret *corev1.Secret) error {
	if secret.Type != corev1.SecretTypeBasicAuth || len(secret.Data[corev1.BasicAuthUsernameKey]) == 0 || len(secret.Data[corev1.BasicAuthPasswordKey]) == 0 {
		return fmt.Errorf("git credentials must be a kubernetes.io/basic-auth Secret with username and password")
	}
	allowed, err := url.Parse(secret.Annotations[GitCredentialsHostAnnotation])
	if err != nil || allowed.Scheme != "https" || allowed.Hostname() == "" || allowed.User != nil || allowed.RawQuery != "" || allowed.Fragment != "" || (allowed.Path != "" && allowed.Path != "/") {
		return fmt.Errorf("git credentials Secret requires %s: https://host", GitCredentialsHostAnnotation)
	}
	repository, err := url.Parse(source.URL)
	if err != nil || !strings.EqualFold(allowed.Host, repository.Host) {
		return fmt.Errorf("git credentials Secret is not authorized for the repository host")
	}
	return nil
}

func (s *ImageBuildSpec) GetGitSource() *GitSource {
	if s.AIB != nil {
		return s.AIB.GitSource
	}
	return nil
}
