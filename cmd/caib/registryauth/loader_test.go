package registryauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeAuthFile(t *testing.T, filePath string, auths map[string]map[string]string) {
	t.Helper()
	content, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		t.Fatalf("failed to marshal test auth file: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatalf("failed to create test auth dir: %v", err)
	}
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatalf("failed to write test auth file: %v", err)
	}
}

func TestLoadAuthFileForRegistry_ExplicitFileMatch(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	writeAuthFile(t, authFile, map[string]map[string]string{
		"quay.io": {"auth": "explicit-token"},
	})

	content, source, err := LoadAuthFileForRegistry("quay.io", authFile)
	if err != nil {
		t.Fatalf("LoadAuthFileForRegistry() error = %v", err)
	}
	if source != authFile {
		t.Fatalf("source = %q, want %q", source, authFile)
	}
	if !strings.Contains(content, "explicit-token") {
		t.Fatalf("returned content does not include explicit auth token")
	}
}

func TestLoadAuthFileForRegistry_ExplicitFileMissingRegistry(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	writeAuthFile(t, authFile, map[string]map[string]string{
		"ghcr.io": {"auth": "ghcr-token"},
	})

	_, _, err := LoadAuthFileForRegistry("quay.io", authFile)
	if err == nil {
		t.Fatal("expected error when explicit auth file does not contain registry")
	}
	if !strings.Contains(err.Error(), "does not contain credentials for registry") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAuthFileForRegistry_ExplicitFileAllowsEmptyRegistryURL(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	writeAuthFile(t, authFile, map[string]map[string]string{
		"quay.io": {"auth": "explicit-token"},
	})

	content, source, err := LoadAuthFileForRegistry("", authFile)
	if err != nil {
		t.Fatalf("LoadAuthFileForRegistry() error = %v", err)
	}
	if source != authFile {
		t.Fatalf("source = %q, want %q", source, authFile)
	}
	if !strings.Contains(content, "explicit-token") {
		t.Fatalf("returned content does not include explicit auth token")
	}
}

func TestLoadAuthFileForRegistry_AutoDiscoveryPrefersRegistryAuthFile(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("HOME", t.TempDir())

	baseDir := t.TempDir()
	explicit := filepath.Join(baseDir, "explicit.json")
	xdgAuth := filepath.Join(baseDir, "xdg", "containers", "auth.json")

	writeAuthFile(t, explicit, map[string]map[string]string{
		"preference.test.local": {"auth": "from-registry-auth-file"},
	})
	writeAuthFile(t, xdgAuth, map[string]map[string]string{
		"preference.test.local": {"auth": "from-xdg"},
	})

	t.Setenv("REGISTRY_AUTH_FILE", explicit)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(baseDir, "xdg"))

	content, source, err := LoadAuthFileForRegistry("preference.test.local", "")
	if err != nil {
		t.Fatalf("LoadAuthFileForRegistry() error = %v", err)
	}
	if source != explicit {
		t.Fatalf("source = %q, want %q", source, explicit)
	}
	if !strings.Contains(content, "from-registry-auth-file") {
		t.Fatalf("expected content from REGISTRY_AUTH_FILE, got: %s", content)
	}
}

func TestLoadAuthFileForRegistry_UsesXDGAuthJSONBeforeHome(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("DOCKER_CONFIG", "")

	baseDir := t.TempDir()
	xdgRuntime := filepath.Join(baseDir, "runtime")
	xdgAuth := filepath.Join(xdgRuntime, "containers", "auth.json")
	homeDir := filepath.Join(baseDir, "home")
	homeAuth := filepath.Join(homeDir, ".config", "containers", "auth.json")

	writeAuthFile(t, xdgAuth, map[string]map[string]string{
		"xdg-precedence.test.local": {"auth": "from-xdg"},
	})
	writeAuthFile(t, homeAuth, map[string]map[string]string{
		"xdg-precedence.test.local": {"auth": "from-home"},
	})

	t.Setenv("XDG_RUNTIME_DIR", xdgRuntime)
	t.Setenv("HOME", homeDir)

	content, source, err := LoadAuthFileForRegistry("xdg-precedence.test.local", "")
	if err != nil {
		t.Fatalf("LoadAuthFileForRegistry() error = %v", err)
	}
	if source != xdgAuth {
		t.Fatalf("source = %q, want %q", source, xdgAuth)
	}
	if !strings.Contains(content, "from-xdg") {
		t.Fatalf("expected content from XDG auth.json, got: %s", content)
	}
}

func TestLoadAuthFileForRegistry_DoesNotUseDockerConfigPath(t *testing.T) {
	baseDir := t.TempDir()
	dockerConfigDir := filepath.Join(baseDir, "docker-config")
	dockerConfigPath := filepath.Join(dockerConfigDir, "config.json")
	homeDir := filepath.Join(baseDir, "home")
	xdgRuntime := filepath.Join(baseDir, "runtime")

	writeAuthFile(t, dockerConfigPath, map[string]map[string]string{
		"authjson-only.test.local": {"auth": "docker-config-token"},
	})

	t.Setenv("DOCKER_CONFIG", dockerConfigDir)
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntime)
	t.Setenv("REGISTRY_AUTH_FILE", "")

	content, source, err := LoadAuthFileForRegistry("authjson-only.test.local", "")
	if err != nil {
		t.Fatalf("LoadAuthFileForRegistry() unexpected error = %v", err)
	}
	if content != "" || source != "" {
		t.Fatalf("expected no auth match from DOCKER_CONFIG/config.json, got source=%q content=%q", source, content)
	}
}

func TestLoadAuthFileForRegistry_IgnoresPermissionDeniedCandidates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod permission semantics differ on windows")
	}

	baseDir := t.TempDir()
	unreadable := filepath.Join(baseDir, "unreadable-auth.json")
	writeAuthFile(t, unreadable, map[string]map[string]string{
		"permission-denied.test.local": {"auth": "token"},
	})
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("failed to chmod unreadable auth file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })

	t.Setenv("REGISTRY_AUTH_FILE", unreadable)
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(baseDir, "runtime"))
	t.Setenv("HOME", filepath.Join(baseDir, "home"))

	content, source, err := LoadAuthFileForRegistry("permission-denied.test.local", "")
	if err != nil {
		t.Fatalf("LoadAuthFileForRegistry() unexpected error = %v", err)
	}
	if content != "" || source != "" {
		t.Fatalf("expected empty result when only candidate is unreadable, got source=%q content=%q", source, content)
	}
}

func TestLoadAuthFileForRegistry_StrictHostMatch(t *testing.T) {
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", t.TempDir())

	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "auth.json")
	writeAuthFile(t, authFile, map[string]map[string]string{
		"https://index.docker.io/v1/": {"auth": "dockerhub-token"},
	})

	_, _, err := LoadAuthFileForRegistry("docker.io", authFile)
	if err == nil {
		t.Fatal("expected strict host matching error for non-identical registry host")
	}
	if !strings.Contains(err.Error(), "does not contain credentials for registry") {
		t.Fatalf("unexpected error: %v", err)
	}
}
