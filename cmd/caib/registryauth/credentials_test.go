package registryauth

import (
	"path/filepath"
	"strings"
	"testing"
)

const authTypeDockerConfig = "docker-config"

func TestExtractRegistryCredentials_FromPrimaryRefAndEnv(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "user1")
	t.Setenv("REGISTRY_PASSWORD", "pass1")

	gotURL, gotUser, gotPass := ExtractRegistryCredentials("quay.io/org/image:latest", "")
	if gotURL != "quay.io" {
		t.Fatalf("registry URL = %q, want %q", gotURL, "quay.io")
	}
	if gotUser != "user1" || gotPass != "pass1" {
		t.Fatalf("unexpected credentials: user=%q pass=%q", gotUser, gotPass)
	}
}

func TestExtractRegistryCredentials_FromSecondaryRef(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "")
	t.Setenv("REGISTRY_PASSWORD", "")

	gotURL, _, _ := ExtractRegistryCredentials("", "ghcr.io/org/image:v1")
	if gotURL != "ghcr.io" {
		t.Fatalf("registry URL = %q, want %q", gotURL, "ghcr.io")
	}
}

func TestExtractRegistryCredentials_UnqualifiedRefDoesNotInferRegistry(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "")
	t.Setenv("REGISTRY_PASSWORD", "")

	gotURL, _, _ := ExtractRegistryCredentials("image:latest", "")
	if gotURL != "" {
		t.Fatalf("registry URL = %q, want empty", gotURL)
	}
}

func TestValidateRegistryCredentials_PartialCredentialsError(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		user    string
		pass    string
		wantErr bool
	}{
		{name: "both set", url: "quay.io", user: "u", pass: "p", wantErr: false},
		{name: "neither set", url: "quay.io", user: "", pass: "", wantErr: false},
		{name: "no registry URL", url: "", user: "u", pass: "", wantErr: false},
		{name: "username only", url: "quay.io", user: "u", pass: "", wantErr: true},
		{name: "password only", url: "quay.io", user: "", pass: "p", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegistryCredentials(tt.url, tt.user, tt.pass)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRegistryCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolveRegistryCredentials_ExplicitAuthFileOverridesEnv(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	writeAuthFile(t, authFile, map[string]map[string]string{
		"quay.io": {"auth": "from-file-token"},
	})

	creds, err := ResolveRegistryCredentials("quay.io", "env-user", "env-pass", authFile)
	if err != nil {
		t.Fatalf("ResolveRegistryCredentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
	if creds.AuthType != authTypeDockerConfig {
		t.Fatalf("authType = %q, want %s", creds.AuthType, authTypeDockerConfig)
	}
	if !strings.Contains(creds.DockerConfig, "from-file-token") {
		t.Fatalf("expected docker-config payload from explicit file")
	}
}

func TestResolveRegistryCredentials_ExplicitAuthFileWithEmptyRegistryURL(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	writeAuthFile(t, authFile, map[string]map[string]string{
		"quay.io": {"auth": "from-file-token"},
	})

	creds, err := ResolveRegistryCredentials("", "", "", authFile)
	if err != nil {
		t.Fatalf("ResolveRegistryCredentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
	if creds.AuthType != authTypeDockerConfig {
		t.Fatalf("authType = %q, want %s", creds.AuthType, authTypeDockerConfig)
	}
	if creds.RegistryURL != "" {
		t.Fatalf("registryURL = %q, want empty", creds.RegistryURL)
	}
	if !strings.Contains(creds.DockerConfig, "from-file-token") {
		t.Fatalf("expected docker-config payload from explicit file")
	}
}

func TestResolveRegistryCredentials_UsesEnvCredentialsWhenNoAuthFile(t *testing.T) {
	creds, err := ResolveRegistryCredentials("quay.io", "env-user", "env-pass", "")
	if err != nil {
		t.Fatalf("ResolveRegistryCredentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
	if creds.AuthType != "username-password" {
		t.Fatalf("authType = %q, want username-password", creds.AuthType)
	}
	if creds.Username != "env-user" || creds.Password != "env-pass" {
		t.Fatalf("unexpected username/password: user=%q pass=%q", creds.Username, creds.Password)
	}
}

func TestResolveRegistryCredentials_AutoDiscoversAuthJSONFallback(t *testing.T) {
	baseDir := t.TempDir()
	homeDir := filepath.Join(baseDir, "home")
	homeAuth := filepath.Join(homeDir, ".config", "containers", "auth.json")
	writeAuthFile(t, homeAuth, map[string]map[string]string{
		"fallback.test.local": {"auth": "from-home-authjson"},
	})

	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(baseDir, "runtime"))
	t.Setenv("HOME", homeDir)

	creds, err := ResolveRegistryCredentials("fallback.test.local", "", "", "")
	if err != nil {
		t.Fatalf("ResolveRegistryCredentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials from auth.json fallback")
	}
	if creds.AuthType != authTypeDockerConfig {
		t.Fatalf("authType = %q, want %s", creds.AuthType, authTypeDockerConfig)
	}
	if !strings.Contains(creds.DockerConfig, "from-home-authjson") {
		t.Fatalf("expected docker-config payload from discovered auth.json")
	}
}

func TestResolveRegistryCredentials_PartialCredentialsValidation(t *testing.T) {
	_, err := ResolveRegistryCredentials("quay.io", "user-only", "", "")
	if err == nil {
		t.Fatal("expected validation error for partial credentials")
	}
	if !strings.Contains(err.Error(), "REGISTRY_PASSWORD is set but REGISTRY_USERNAME is missing") &&
		!strings.Contains(err.Error(), "REGISTRY_USERNAME is set but REGISTRY_PASSWORD is missing") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
