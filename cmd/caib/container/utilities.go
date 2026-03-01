/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package container

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"k8s.io/client-go/tools/clientcmd"
)

// handleError prints an error and exits
func handleError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

// executeWithReauth executes a function with authentication retry
func executeWithReauth(serverURL string, authToken *string, fn func(*buildapiclient.Client) error) error {
	ctx := context.Background()

	client, err := createBuildAPIClient(serverURL, authToken)
	if err != nil {
		return err
	}

	err = fn(client)
	if err == nil {
		return nil
	}

	if !auth.IsAuthError(err) {
		return err
	}

	// Auth error (401) - try re-authentication; token may be rejected, not necessarily expired
	fmt.Println("Authentication failed (401), re-authenticating...")

	newToken, _, err := auth.GetTokenWithReauth(ctx, serverURL, *authToken, insecureSkipTLS)
	if err != nil {
		return fmt.Errorf("re-authentication failed: %w", err)
	}

	*authToken = newToken
	// If re-auth returned no token (API says OIDC not configured), try kubeconfig before retrying
	if strings.TrimSpace(*authToken) == "" {
		if tok, kerr := loadTokenFromKubeconfig(); kerr == nil && strings.TrimSpace(tok) != "" {
			*authToken = tok
			client, err = createBuildAPIClient(serverURL, authToken)
			if err != nil {
				return err
			}
			fmt.Println("Using kubeconfig token, retrying...")
			return fn(client)
		}
	}

	client, err = createBuildAPIClient(serverURL, authToken)
	if err != nil {
		return err
	}

	fmt.Println("Retrying request...")
	err = fn(client)
	if err == nil {
		return nil
	}

	// Still 401 after OIDC re-auth (e.g. server OIDC broken, or wrong client/audience) - try kubeconfig fallback
	if !auth.IsAuthError(err) {
		return err
	}
	if tok, kerr := loadTokenFromKubeconfig(); kerr == nil && strings.TrimSpace(tok) != "" {
		*authToken = tok
		client, err = createBuildAPIClient(serverURL, authToken)
		if err != nil {
			return err
		}
		fmt.Println("Attempting kubeconfig fallback...")
		return fn(client)
	}

	return err
}

// createBuildAPIClient creates a build API client with authentication token from flags or kubeconfig
func createBuildAPIClient(serverURL string, authToken *string) (*buildapiclient.Client, error) {
	ctx := context.Background()

	explicitToken := strings.TrimSpace(*authToken) != "" || os.Getenv("CAIB_TOKEN") != ""

	// If no explicit token, try OIDC if config is available
	if !explicitToken {
		token, didAuth, err := auth.GetTokenWithReauth(ctx, serverURL, "", insecureSkipTLS)
		if err != nil {
			// OIDC is configured but failed - don't silently fall back to kubeconfig
			// This indicates a real authentication failure that should be reported
			// Falling back could authenticate with an unexpected identity
			oidcErr := err
			fmt.Printf("Error: OIDC authentication failed: %v\n", oidcErr)
			// Only try kubeconfig as last resort, but warn the user
			fmt.Println("Attempting kubeconfig fallback (this may use a different identity)")
			if tok, kerr := loadTokenFromKubeconfig(); kerr == nil && strings.TrimSpace(tok) != "" {
				*authToken = tok
			} else {
				// No kubeconfig available either - return error
				return nil, fmt.Errorf("OIDC authentication failed (%v) and no kubeconfig token available: %w", oidcErr, kerr)
			}
		} else if token != "" {
			// OIDC succeeded
			*authToken = token
			if didAuth {
				fmt.Println("OIDC authentication successful")
			}
		} else {
			// OIDC not configured in OperatorConfig
			if tok, err := loadTokenFromKubeconfig(); err == nil && strings.TrimSpace(tok) != "" {
				*authToken = tok
			}
		}
	} else {
		// Token was explicitly provided, use it (but still try kubeconfig if empty)
		if strings.TrimSpace(*authToken) == "" {
			if tok, err := loadTokenFromKubeconfig(); err == nil && strings.TrimSpace(tok) != "" {
				*authToken = tok
			}
		}
	}

	var opts []buildapiclient.Option
	if strings.TrimSpace(*authToken) != "" {
		opts = append(opts, buildapiclient.WithAuthToken(strings.TrimSpace(*authToken)))
	}

	// Configure TLS
	if insecureSkipTLS {
		opts = append(opts, buildapiclient.WithInsecureTLS())
	}
	// Check for custom CA certificate
	if caCertFile := os.Getenv("SSL_CERT_FILE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	} else if caCertFile := os.Getenv("REQUESTS_CA_BUNDLE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	}

	return buildapiclient.New(serverURL, opts...)
}

// loadTokenFromKubeconfig loads a bearer token from kubeconfig
func loadTokenFromKubeconfig() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	// First, ask client-go to build a client config. This will execute any exec credential plugins
	// (e.g., OpenShift login) and populate a usable BearerToken.
	deferred := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	if restCfg, err := deferred.ClientConfig(); err == nil && restCfg != nil {
		if t := strings.TrimSpace(restCfg.BearerToken); t != "" {
			return t, nil
		}
		if f := strings.TrimSpace(restCfg.BearerTokenFile); f != "" {
			if b, rerr := os.ReadFile(f); rerr == nil {
				if t := strings.TrimSpace(string(b)); t != "" {
					return t, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no token found in kubeconfig")
}

// sanitizeBuildName sanitizes a build name
func sanitizeBuildName(name string) string {
	// Replace invalid characters with dashes, lowercase, and truncate
	name = strings.ToLower(name)
	re := regexp.MustCompile(`[^a-z0-9-]`)
	sanitized := re.ReplaceAllString(name, "-")
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}
	sanitized = strings.Trim(sanitized, "-")
	if sanitized == "" {
		sanitized = "build"
	}
	return sanitized
}

// validateBuildName validates a build name
func validateBuildName(name string) {
	if name == "" {
		handleError(fmt.Errorf("build name cannot be empty"))
	}
	if len(name) > 63 {
		handleError(fmt.Errorf("build name cannot be longer than 63 characters"))
	}
	if !isValidKubernetesName(name) {
		handleError(fmt.Errorf("build name must be a valid Kubernetes resource name"))
	}
}

// isValidKubernetesName checks if a string is a valid Kubernetes resource name
func isValidKubernetesName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	re := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	return re.MatchString(name)
}
