package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type httpError struct {
	code    int
	message string
}

// resolveFlashTargetConfig resolves exporter selector and flash command from request and OperatorConfig.
func resolveFlashTargetConfig(req FlashRequest, operatorConfig *automotivev1alpha1.OperatorConfig) (string, string) {
	exporterSelector := req.ExporterSelector
	flashCmd := req.FlashCmd
	if req.Target != "" && exporterSelector == "" && operatorConfig.Spec.Jumpstarter != nil {
		if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[req.Target]; ok {
			exporterSelector = mapping.Selector
			if flashCmd == "" {
				flashCmd = mapping.FlashCmd
			}
		}
	}
	return exporterSelector, flashCmd
}

// createFlashClientConfigSecret creates the Jumpstarter client config secret for a standalone flash job.
func createFlashClientConfigSecret(
	ctx context.Context, clientset kubernetes.Interface, namespace string, req FlashRequest,
) (string, *corev1.Secret, *httpError) {
	clientConfigBytes, err := base64.StdEncoding.DecodeString(req.ClientConfig)
	if err != nil {
		return "", nil, &httpError{code: http.StatusBadRequest, message: "clientConfig must be base64 encoded"}
	}
	secretName := fmt.Sprintf("%s-jumpstarter-client", req.Name)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				flashTaskRunLabel:                               req.Name,
				"automotive.sdv.cloud.redhat.com/resource-type": "jumpstarter-client",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"client.yaml": clientConfigBytes,
		},
	}
	created, createErr := clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if createErr != nil {
		if k8serrors.IsAlreadyExists(createErr) {
			return "", nil, &httpError{code: http.StatusConflict, message: fmt.Sprintf("flash %s already exists", req.Name)}
		}
		return "", nil, &httpError{code: http.StatusInternalServerError, message: fmt.Sprintf("failed to create secret: %v", createErr)}
	}
	return secretName, created, nil
}

// createFlashOCIAuthSecret creates a Kubernetes secret with OCI credentials for flash image pull.
// Returns the secret name, the created secret (for owner ref setup), and an error if creation fails.
// Returns empty name and nil secret if no credentials are provided.
func createFlashOCIAuthSecret(
	ctx context.Context, clientset kubernetes.Interface, namespace, flashName string, creds *RegistryCredentials,
) (string, *corev1.Secret, *httpError) {
	if creds == nil || !creds.Enabled {
		return "", nil, nil
	}
	ociUsername, ociPassword, err := extractOCICredentials(creds)
	if err != nil {
		return "", nil, &httpError{code: http.StatusBadRequest, message: fmt.Sprintf("invalid registry credentials: %v", err)}
	}
	if ociUsername == "" || ociPassword == "" {
		return "", nil, nil
	}
	secretName := fmt.Sprintf("%s-flash-oci-auth", flashName)
	ociSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				flashTaskRunLabel:                               flashName,
				"automotive.sdv.cloud.redhat.com/transient":     "true",
				"automotive.sdv.cloud.redhat.com/resource-type": "flash-oci-auth",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte(ociUsername),
			"password": []byte(ociPassword),
		},
	}
	created, createErr := clientset.CoreV1().Secrets(namespace).Create(ctx, ociSecret, metav1.CreateOptions{})
	if createErr != nil {
		if !k8serrors.IsAlreadyExists(createErr) {
			return "", nil, &httpError{
				code:    http.StatusInternalServerError,
				message: fmt.Sprintf("failed to create flash OCI auth secret: %v", createErr),
			}
		}
	}
	return secretName, created, nil
}

// extractOCICredentials extracts username/password from RegistryCredentials.
// For docker-config auth, it prefers the entry matching RegistryURL, falling back to the first valid entry.
func extractOCICredentials(creds *RegistryCredentials) (string, string, error) {
	if creds == nil || !creds.Enabled {
		return "", "", nil
	}
	switch creds.AuthType {
	case authTypeUsernamePassword:
		return creds.Username, creds.Password, nil
	case authTypeDockerConfig:
		if creds.DockerConfig == "" {
			return "", "", fmt.Errorf("docker config is empty")
		}
		return decodeDockerConfigAuth(creds.DockerConfig, creds.RegistryURL)
	default:
		return "", "", fmt.Errorf("unsupported auth type for flash OCI credentials: %s", creds.AuthType)
	}
}

// decodeDockerConfigAuth parses a docker config JSON and extracts username/password.
// If registryURL is non-empty, it prefers the matching entry; otherwise takes the first valid one.
func decodeDockerConfigAuth(dockerConfig, registryURL string) (string, string, error) {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal([]byte(dockerConfig), &cfg); err != nil {
		return "", "", fmt.Errorf("failed to parse docker config: %w", err)
	}

	// Try matching the target registry first
	if registryURL != "" {
		for key, entry := range cfg.Auths {
			if !strings.Contains(key, registryURL) {
				continue
			}
			if user, pass, ok := decodeAuthField(entry.Auth); ok {
				return user, pass, nil
			}
		}
	}

	// Fall back to first valid entry
	for _, entry := range cfg.Auths {
		if user, pass, ok := decodeAuthField(entry.Auth); ok {
			return user, pass, nil
		}
	}
	return "", "", fmt.Errorf("no valid credentials found in docker config")
}

// decodeAuthField decodes a base64-encoded "user:password" auth field.
func decodeAuthField(auth string) (string, string, bool) {
	if auth == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
