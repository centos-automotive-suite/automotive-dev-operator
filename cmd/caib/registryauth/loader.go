// Package registryauth provides helpers for loading registry credentials from auth files.
package registryauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/registryutil"
)

type authConfigFile struct {
	Auths map[string]authConfigEntry `json:"auths"`
}

type authConfigEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

func authEntryHasCredentials(entry authConfigEntry) bool {
	if strings.TrimSpace(entry.Auth) != "" {
		return true
	}
	if strings.TrimSpace(entry.IdentityToken) != "" {
		return true
	}
	return strings.TrimSpace(entry.Username) != "" && strings.TrimSpace(entry.Password) != ""
}

func registryAuthKeyMatches(authKey, registryURL string) bool {
	return registryutil.RegistryHostMatches(authKey, registryURL)
}

func authFileHasRegistryAuth(content []byte, registryURL string) (bool, error) {
	var authFile authConfigFile
	if err := json.Unmarshal(content, &authFile); err != nil {
		return false, err
	}
	if len(authFile.Auths) == 0 {
		return false, nil
	}
	for authKey, entry := range authFile.Auths {
		if !authEntryHasCredentials(entry) {
			continue
		}
		if registryAuthKeyMatches(authKey, registryURL) {
			return true, nil
		}
	}
	return false, nil
}

func authFileHasAnyCredentials(content []byte) (bool, error) {
	var authFile authConfigFile
	if err := json.Unmarshal(content, &authFile); err != nil {
		return false, err
	}
	if len(authFile.Auths) == 0 {
		return false, nil
	}
	for _, entry := range authFile.Auths {
		if authEntryHasCredentials(entry) {
			return true, nil
		}
	}
	return false, nil
}

func registryAuthFileCandidates() []string {
	candidates := make([]string, 0, 4)
	seen := map[string]struct{}{}
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if _, exists := seen[path]; exists {
			return
		}
		seen[path] = struct{}{}
		candidates = append(candidates, path)
	}

	if authFile := os.Getenv("REGISTRY_AUTH_FILE"); authFile != "" {
		add(authFile)
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		add(filepath.Join(runtimeDir, "containers", "auth.json"))
	}
	add(filepath.Join("/run/containers", strconv.Itoa(os.Getuid()), "auth.json"))

	homeDir, err := os.UserHomeDir()
	if err == nil && homeDir != "" {
		add(filepath.Join(homeDir, ".config", "containers", "auth.json"))
	}
	return candidates
}

// LoadAuthFileForRegistry returns auth-file JSON content that has credentials for registryURL.
// If explicitAuthFile is set, it is required to exist, be valid JSON, and contain matching credentials.
func LoadAuthFileForRegistry(
	registryURL, explicitAuthFile string,
) (authFileContent, sourcePath string, readErr error) {
	explicitAuthFile = strings.TrimSpace(explicitAuthFile)
	if explicitAuthFile != "" {
		content, err := os.ReadFile(explicitAuthFile)
		if err != nil {
			return "", "", fmt.Errorf("failed to read --registry-auth-file %q: %w", explicitAuthFile, err)
		}
		if strings.TrimSpace(registryURL) == "" {
			hasCreds, err := authFileHasAnyCredentials(content)
			if err != nil {
				return "", "", fmt.Errorf("failed to parse --registry-auth-file %q: %w", explicitAuthFile, err)
			}
			if !hasCreds {
				return "", "", fmt.Errorf("--registry-auth-file %q does not contain usable credentials", explicitAuthFile)
			}
			return string(content), explicitAuthFile, nil
		}
		matched, err := authFileHasRegistryAuth(content, registryURL)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse --registry-auth-file %q: %w", explicitAuthFile, err)
		}
		if !matched {
			return "", "", fmt.Errorf(
				"--registry-auth-file %q does not contain credentials for registry %q",
				explicitAuthFile,
				registryURL,
			)
		}
		return string(content), explicitAuthFile, nil
	}

	var errs []string
	for _, candidate := range registryAuthFileCandidates() {
		content, err := os.ReadFile(candidate)
		if err != nil {
			if !os.IsNotExist(err) && !os.IsPermission(err) {
				errs = append(errs, fmt.Sprintf("%s: %v", candidate, err))
			}
			continue
		}

		matched, err := authFileHasRegistryAuth(content, registryURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}
		if matched {
			return string(content), candidate, nil
		}
	}

	if len(errs) > 0 {
		return "", "", fmt.Errorf("failed to inspect registry auth files: %s", strings.Join(errs, "; "))
	}
	return "", "", nil
}
