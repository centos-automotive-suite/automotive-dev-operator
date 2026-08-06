package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/types"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/registryutil"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type httpError struct {
	code    int
	message string
}

// BuildLeaseTags merges OperatorConfig defaults, build name, and user-provided tags into a comma-separated string.
func BuildLeaseTags(operatorConfigDefaults, buildName, userTags string) string {
	parts := make([]string, 0, 3)
	if operatorConfigDefaults != "" {
		parts = append(parts, operatorConfigDefaults)
	}
	parts = append(parts, "build-name="+buildName)
	if userTags != "" {
		parts = append(parts, userTags)
	}
	return strings.Join(parts, ",")
}

// resolveFlashTargetConfig resolves exporter selector and flash command from request and OperatorConfig.
func resolveFlashTargetConfig(req FlashRequest, operatorConfig *automotivev1alpha1.OperatorConfig) (string, string) {
	exporterSelector := req.ExporterSelector
	flashCmd := req.FlashCmd
	if req.Target != "" && operatorConfig.Spec.Jumpstarter != nil {
		if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[req.Target]; ok {
			if exporterSelector == "" {
				exporterSelector = mapping.Selector
			}
			if flashCmd == "" {
				flashCmd = mapping.FlashCmd
			}
		}
	}
	return exporterSelector, flashCmd
}

// readImageAnnotationsFn reads OCI manifest annotations for a given image reference.
// Overridable for testing.
var readImageAnnotationsFn = readImageAnnotations

func readImageAnnotations(ctx context.Context, imageRef string, sysCtx *types.SystemContext) (map[string]string, error) {
	ref, err := docker.ParseReference("//" + imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse reference: %w", err)
	}

	if sysCtx == nil {
		sysCtx = &types.SystemContext{}
	}

	src, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, fmt.Errorf("open image source: %w", err)
	}
	defer func() { _ = src.Close() }()

	rawManifest, _, err := src.GetManifest(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}

	var parsed struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(rawManifest, &parsed); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return parsed.Annotations, nil
}

// systemContextFromCredentials builds a types.SystemContext with Docker auth
// from FlashRequest registry credentials. Returns nil if no credentials.
func systemContextFromCredentials(creds *RegistryCredentials) *types.SystemContext {
	if creds == nil || !creds.Enabled {
		return nil
	}
	username, password, err := extractOCICredentials(creds)
	if err != nil || username == "" {
		return nil
	}
	return &types.SystemContext{
		DockerAuthConfig: &types.DockerAuthConfig{
			Username: username,
			Password: password,
		},
	}
}

// resolveTargetFromImage inspects OCI image annotations and returns the target name if present.
func resolveTargetFromImage(ctx context.Context, imageRef string, creds *RegistryCredentials) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	sysCtx := systemContextFromCredentials(creds)
	annotations, err := readImageAnnotationsFn(ctx, imageRef, sysCtx)
	if err != nil {
		return ""
	}
	return annotations[oci.Get().AnnotationKey("target")]
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
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.FlashTaskRun: req.Name,
				labels.ResourceType: "jumpstarter-client",
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
		return "", nil, &httpError{code: http.StatusBadRequest, message: "registry credentials enabled but missing username or password"}
	}
	secretName := fmt.Sprintf("%s-flash-oci-auth", flashName)
	ociSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.FlashTaskRun: flashName,
				labels.Transient:    labels.ValueTrue,
				labels.ResourceType: "flash-oci-auth",
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
		if k8serrors.IsAlreadyExists(createErr) {
			return "", nil, &httpError{code: http.StatusConflict, message: fmt.Sprintf("flash OCI auth secret %s already exists", secretName)}
		}
		return "", nil, &httpError{
			code:    http.StatusInternalServerError,
			message: fmt.Sprintf("failed to create flash OCI auth secret: %v", createErr),
		}
	}
	return secretName, created, nil
}

// extractOCICredentials extracts username/password from RegistryCredentials.
// For docker-config auth, it returns the entry matching RegistryURL.
func extractOCICredentials(creds *RegistryCredentials) (string, string, error) {
	if creds == nil || !creds.Enabled {
		return "", "", nil
	}
	switch creds.AuthType {
	case authTypeUsernamePassword:
		if creds.Username == "" || creds.Password == "" {
			return "", "", fmt.Errorf("username-password auth enabled but missing username or password")
		}
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

// decodeDockerConfigAuth parses a docker config JSON and extracts username/password
// for the entry matching registryURL.
func decodeDockerConfigAuth(dockerConfig, registryURL string) (string, string, error) {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal([]byte(dockerConfig), &cfg); err != nil {
		return "", "", fmt.Errorf("failed to parse docker config: %w", err)
	}

	for key, entry := range cfg.Auths {
		if !registryutil.RegistryHostMatches(key, registryURL) {
			continue
		}
		if user, pass, ok := decodeAuthField(entry.Auth); ok {
			return user, pass, nil
		}
	}
	return "", "", fmt.Errorf("no credentials found for registry %s", registryURL)
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
