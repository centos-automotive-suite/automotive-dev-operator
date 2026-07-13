package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

const (
	authTypeUsernamePassword = "username-password"
	authTypeToken            = "token"
	authTypeDockerConfig     = "docker-config"
)

var errRegistryCredentialsRequiredForPush = errors.New("registry credentials are required when push repository is specified")

func setSecretOwnerRef(
	ctx context.Context,
	c client.Client,
	namespace, secretName string,
	owner *automotivev1alpha1.ImageBuild,
) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return err
	}
	secret.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(owner, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
	}
	return c.Update(ctx, secret)
}

// createFlashClientSecret creates a secret containing the Jumpstarter client config
func createFlashClientSecret(
	ctx context.Context,
	c client.Client,
	namespace, secretName, base64Config string,
) error {
	configBytes, err := base64.StdEncoding.DecodeString(base64Config)
	if err != nil {
		return fmt.Errorf("failed to decode client config: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy: labels.ValueBuildAPI,
				labels.PartOf:    labels.ValueAutomotiveDev,
				labels.Component: "jumpstarter-client",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"client.yaml": configBytes,
		},
	}

	return c.Create(ctx, secret)
}

func createRegistrySecret(
	ctx context.Context, k8sClient client.Client, namespace, buildName string, creds *RegistryCredentials,
) (string, error) {
	if creds == nil || !creds.Enabled {
		return "", nil
	}

	secretName := fmt.Sprintf("%s-external-registry-auth", buildName)
	secretData := make(map[string][]byte)

	switch creds.AuthType {
	case authTypeUsernamePassword:
		if creds.RegistryURL == "" || creds.Username == "" || creds.Password == "" {
			return "", fmt.Errorf("registry URL, username, and password are required for username-password authentication")
		}
		secretData["REGISTRY_URL"] = []byte(creds.RegistryURL)
		secretData["REGISTRY_USERNAME"] = []byte(creds.Username)
		secretData["REGISTRY_PASSWORD"] = []byte(creds.Password)

		// Also create dockerconfigjson format for tools that need it (oras, skopeo, etc.)
		auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		dockerConfig, err := json.Marshal(map[string]interface{}{
			"auths": map[string]interface{}{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to create docker config: %w", err)
		}
		secretData[".dockerconfigjson"] = dockerConfig
	case authTypeToken:
		if creds.RegistryURL == "" || creds.Token == "" {
			return "", fmt.Errorf("registry URL and token are required for token authentication")
		}
		secretData["REGISTRY_URL"] = []byte(creds.RegistryURL)
		secretData["REGISTRY_TOKEN"] = []byte(creds.Token)
	case authTypeDockerConfig:
		if creds.DockerConfig == "" {
			return "", fmt.Errorf("docker config is required for docker-config authentication")
		}
		secretData["REGISTRY_AUTH_FILE_CONTENT"] = []byte(creds.DockerConfig)
		secretData[".dockerconfigjson"] = []byte(creds.DockerConfig)
	default:
		return "", fmt.Errorf("unsupported authentication type: %s", creds.AuthType)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.CreatedBy:    labels.ValueBuildAPICreator,
				labels.ResourceType: "registry-auth",
				labels.BuildName:    buildName,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create registry secret: %w", err)
	}

	return secretName, nil
}

// createPushSecret creates a kubernetes.io/dockerconfigjson secret for pushing artifacts to a registry
func createPushSecret(
	ctx context.Context, k8sClient client.Client, namespace, buildName string, creds *RegistryCredentials,
) (string, error) {
	if creds == nil || !creds.Enabled {
		return "", fmt.Errorf("registry credentials are required for push")
	}

	secretName := fmt.Sprintf("%s-push-auth", buildName)

	var dockerConfigJSON []byte
	var err error

	switch creds.AuthType {
	case authTypeUsernamePassword:
		if creds.RegistryURL == "" || creds.Username == "" || creds.Password == "" {
			return "", fmt.Errorf("registry URL, username, and password are required for push")
		}
		auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		dockerConfigJSON, err = json.Marshal(map[string]interface{}{
			"auths": map[string]interface{}{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to marshal docker config: %w", err)
		}
	case authTypeToken:
		if creds.RegistryURL == "" || creds.Token == "" {
			return "", fmt.Errorf("registry URL and token are required for push with token auth")
		}
		auth := base64.StdEncoding.EncodeToString([]byte(":" + creds.Token))
		dockerConfigJSON, err = json.Marshal(map[string]interface{}{
			"auths": map[string]interface{}{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to marshal docker config: %w", err)
		}
	case authTypeDockerConfig:
		if creds.DockerConfig == "" {
			return "", fmt.Errorf("docker config is required for push with docker-config auth")
		}
		dockerConfigJSON = []byte(creds.DockerConfig)
	default:
		return "", fmt.Errorf("unsupported authentication type for push: %s", creds.AuthType)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.CreatedBy:    labels.ValueBuildAPICreator,
				labels.ResourceType: "push-auth",
				labels.BuildName:    buildName,
				labels.Transient:    labels.ValueTrue,
			},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": dockerConfigJSON,
		},
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create push secret: %w", err)
	}

	return secretName, nil
}

// setupBuildSecrets creates necessary secrets for the build
func setupBuildSecrets(
	ctx context.Context, k8sClient client.Client,
	namespace string, req *BuildRequest,
) (envSecretRef, pushSecretName string, err error) {
	if req.RegistryCredentials != nil && req.RegistryCredentials.Enabled {
		envSecretRef, err = createRegistrySecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
		if err != nil {
			return "", "", fmt.Errorf("error creating registry secret: %w", err)
		}
	}

	if req.PushRepository != "" || req.ExportOCI != "" {
		if req.RegistryCredentials == nil || !req.RegistryCredentials.Enabled {
			return "", "", errRegistryCredentialsRequiredForPush
		}
		pushSecretName, err = createPushSecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
		if err != nil {
			return "", "", fmt.Errorf("error creating push secret: %w", err)
		}
	}

	return envSecretRef, pushSecretName, nil
}

func resolveS3Credentials(
	ctx context.Context,
	k8sClient client.Client,
	req *BuildRequest,
	namespace string,
) (int, error) {
	if req.S3Bucket == "" {
		return 0, nil
	}
	if req.S3Credentials != nil && req.S3CredentialsSecretName != "" {
		return http.StatusBadRequest, fmt.Errorf("cannot specify both s3Credentials and s3CredentialsSecretName")
	}
	if req.S3Credentials != nil {
		if req.S3Credentials.AccessKeyID == "" || req.S3Credentials.SecretAccessKey == "" {
			return http.StatusBadRequest, fmt.Errorf("S3 access key ID and secret access key are required")
		}
		s3SecretName, err := createS3Secret(ctx, k8sClient, req.Name, namespace, req.S3Credentials)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("error creating S3 secret: %w", err)
		}
		req.S3CredentialsSecretName = s3SecretName
		return 0, nil
	}
	if req.S3CredentialsSecretName != "" {
		secret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      req.S3CredentialsSecretName,
			Namespace: namespace,
		}, secret); err != nil {
			return http.StatusBadRequest, fmt.Errorf("S3 credentials secret %s not found: %w", req.S3CredentialsSecretName, err)
		}
		return 0, nil
	}
	return 0, nil
}

// createS3Secret creates a secret containing S3 credentials
func createS3Secret(
	ctx context.Context,
	k8sClient client.Client,
	buildName, namespace string,
	creds *S3Credentials,
) (string, error) {
	if creds == nil {
		return "", nil
	}

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return "", fmt.Errorf("S3 access key ID and secret access key are required")
	}

	secretName := fmt.Sprintf("%s-s3-auth", buildName)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.CreatedBy:    labels.ValueBuildAPICreator,
				labels.ResourceType: "s3-auth",
				labels.BuildName:    buildName,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"access-key-id":     []byte(creds.AccessKeyID),
			"secret-access-key": []byte(creds.SecretAccessKey),
		},
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create S3 secret: %w", err)
	}

	return secretName, nil
}

// cleanupInlineS3Secret deletes an S3 secret that was generated from inline
// credentials. It is a best-effort operation used on failure paths to avoid
// orphaned secrets.
func cleanupInlineS3Secret(ctx context.Context, k8sClient client.Client, req *BuildRequest, namespace string) {
	if req.S3Credentials == nil || req.S3CredentialsSecretName == "" {
		return
	}
	orphan := &corev1.Secret{}
	orphan.Name = req.S3CredentialsSecretName
	orphan.Namespace = namespace
	if err := k8sClient.Delete(ctx, orphan); err != nil {
		log.Printf("WARNING: failed to clean up S3 secret %s: %v", req.S3CredentialsSecretName, err)
	}
}
