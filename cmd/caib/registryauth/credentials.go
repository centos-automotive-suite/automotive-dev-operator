package registryauth

import (
	"fmt"
	"os"
	"strings"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

// ExtractRegistryCredentials gets registry URL from image references and credentials from env vars.
func ExtractRegistryCredentials(primaryRef, secondaryRef string) (string, string, string) {
	username := os.Getenv("REGISTRY_USERNAME")
	password := os.Getenv("REGISTRY_PASSWORD")

	ref := primaryRef
	if ref == "" {
		ref = secondaryRef
	}
	if ref == "" {
		return "", username, password
	}

	if username == "" || password == "" {
		fmt.Println("Warning: No registry credentials provided via environment variables.")
		fmt.Println("Will attempt to use local auth.json files as fallback.")
	}

	parts := strings.SplitN(ref, "/", 2)
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		return parts[0], username, password
	}
	return "", username, password
}

// ValidateRegistryCredentials validates partial env credential configurations.
func ValidateRegistryCredentials(registryURL, username, password string) error {
	if registryURL == "" {
		return nil
	}
	if (username == "") != (password == "") {
		if username == "" {
			return fmt.Errorf("REGISTRY_PASSWORD is set but REGISTRY_USERNAME is missing")
		}
		return fmt.Errorf("REGISTRY_USERNAME is set but REGISTRY_PASSWORD is missing")
	}
	return nil
}

// ResolveRegistryCredentials resolves env or auth-file credentials into API payload format.
func ResolveRegistryCredentials(
	registryURL, username, password, explicitAuthFile string,
) (*buildapitypes.RegistryCredentials, error) {
	explicitAuthFile = strings.TrimSpace(explicitAuthFile)
	if explicitAuthFile != "" {
		authFileContent, sourcePath, err := LoadAuthFileForRegistry(registryURL, explicitAuthFile)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Using registry credentials from auth file: %s\n", sourcePath)
		return &buildapitypes.RegistryCredentials{
			Enabled:      true,
			AuthType:     "docker-config",
			RegistryURL:  registryURL,
			DockerConfig: authFileContent,
		}, nil
	}
	if registryURL == "" {
		return nil, nil
	}

	if err := ValidateRegistryCredentials(registryURL, username, password); err != nil {
		return nil, err
	}
	if username != "" && password != "" {
		return &buildapitypes.RegistryCredentials{
			Enabled:     true,
			AuthType:    "username-password",
			RegistryURL: registryURL,
			Username:    username,
			Password:    password,
		}, nil
	}

	authFileContent, sourcePath, err := LoadAuthFileForRegistry(registryURL, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}
	if authFileContent == "" {
		return nil, nil
	}

	fmt.Printf("Using registry credentials from auth file: %s\n", sourcePath)
	return &buildapitypes.RegistryCredentials{
		Enabled:      true,
		AuthType:     "docker-config",
		RegistryURL:  registryURL,
		DockerConfig: authFileContent,
	}, nil
}
