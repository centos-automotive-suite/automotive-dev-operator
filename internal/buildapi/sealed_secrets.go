package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/sealedsecrets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// sealedSecretRefs holds the resolved secret references for a sealed operation.
type sealedSecretRefs struct {
	secretRef            string
	keySecretRef         string
	keyPasswordSecretRef string
}

// sealedSecretLabels returns the labels for a transient Secret created for a
// sealed request. They match the label set build Secrets carry, plus the
// ImageReseal name so the sweep can tell which job a leftover Secret belongs to.
func sealedSecretLabels(job, resourceType string) map[string]string {
	return map[string]string{
		labels.ImageReseal:  job,
		labels.Transient:    labels.ValueTrue,
		labels.ManagedBy:    labels.ValueBuildAPI,
		labels.PartOf:       labels.ValueAutomotiveDev,
		labels.CreatedBy:    labels.ValueBuildAPICreator,
		labels.ResourceType: resourceType,
	}
}

// planSealedSecrets resolves which transient Secrets the request needs and the
// names they will carry. The names derive from the request, so the API can
// record them on the ImageReseal before creating the Secrets themselves.
func planSealedSecrets(req *buildcontract.SealedRequest) *sealedSecretRefs {
	refs := &sealedSecretRefs{
		keySecretRef:         req.KeySecretRef,
		keyPasswordSecretRef: req.KeyPasswordSecretRef,
	}
	if req.RegistryCredentials != nil && req.RegistryCredentials.Enabled {
		refs.secretRef = req.Name + sealedsecrets.RegistryAuthSuffix
	}
	if strings.TrimSpace(req.KeyContent) != "" && refs.keySecretRef == "" {
		refs.keySecretRef = req.Name + sealedsecrets.SealKeySuffix
		if strings.TrimSpace(req.KeyPassword) != "" {
			refs.keyPasswordSecretRef = req.Name + sealedsecrets.SealKeyPasswordSuffix
		}
	}
	return refs
}

// createSealedSecrets materializes the planned transient Secrets (registry
// auth, seal key, key password), each born with the job as its owner so
// garbage collection removes it even if the API dies mid-request. A ref the
// requester supplied is left for the job to mount as-is.
func createSealedSecrets(
	ctx context.Context,
	clientset kubernetes.Interface,
	namespace string,
	req *buildcontract.SealedRequest,
	refs *sealedSecretRefs,
	job *automotivev1alpha1.ImageReseal,
) error {
	owner := metav1.OwnerReference{
		APIVersion: automotivev1alpha1.GroupVersion.String(),
		Kind:       "ImageReseal",
		Name:       job.Name,
		UID:        job.UID,
	}
	create := func(name, resourceType string, data map[string][]byte) error {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       namespace,
				Labels:          sealedSecretLabels(job.Name, resourceType),
				OwnerReferences: []metav1.OwnerReference{owner},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}
		if _, err := clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create %s secret: %w", resourceType, err)
		}
		return nil
	}

	if refs.secretRef != "" {
		data, err := buildSealedRegistrySecretData(req.RegistryCredentials)
		if err != nil {
			return err
		}
		if err := create(refs.secretRef, "registry-auth", data); err != nil {
			return err
		}
	}
	if refs.keySecretRef != "" && refs.keySecretRef != req.KeySecretRef {
		if err := create(refs.keySecretRef, "seal-key", map[string][]byte{
			"private-key": []byte(req.KeyContent),
		}); err != nil {
			return err
		}
	}
	if refs.keyPasswordSecretRef != "" && refs.keyPasswordSecretRef != req.KeyPasswordSecretRef {
		if err := create(refs.keyPasswordSecretRef, "seal-key-password", map[string][]byte{
			"password": []byte(req.KeyPassword),
		}); err != nil {
			return err
		}
	}
	return nil
}

func buildSealedRegistrySecretData(creds *buildcontract.RegistryCredentials) (map[string][]byte, error) {
	secretData := make(map[string][]byte)

	switch creds.AuthType {
	case authTypeUsernamePassword:
		if creds.RegistryURL == "" || creds.Username == "" || creds.Password == "" {
			return nil, fmt.Errorf("registry URL, username, and password are required for username-password authentication")
		}
		secretData["REGISTRY_URL"] = []byte(creds.RegistryURL)
		secretData["REGISTRY_USERNAME"] = []byte(creds.Username)
		secretData["REGISTRY_PASSWORD"] = []byte(creds.Password)

		auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		dockerConfig, err := json.Marshal(map[string]any{
			"auths": map[string]any{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create docker config: %w", err)
		}
		secretData[".dockerconfigjson"] = dockerConfig
	case authTypeToken:
		if creds.RegistryURL == "" || creds.Token == "" {
			return nil, fmt.Errorf("registry URL and token are required for token authentication")
		}
		secretData["REGISTRY_URL"] = []byte(creds.RegistryURL)
		secretData["REGISTRY_TOKEN"] = []byte(creds.Token)
	case authTypeDockerConfig:
		if creds.DockerConfig == "" {
			return nil, fmt.Errorf("docker config is required for docker-config authentication")
		}
		secretData["REGISTRY_AUTH_FILE_CONTENT"] = []byte(creds.DockerConfig)
		secretData[".dockerconfigjson"] = []byte(creds.DockerConfig)
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", creds.AuthType)
	}

	return secretData, nil
}

// cleanupSealedSecrets removes transient secrets that were created for a sealed operation.
func cleanupSealedSecrets(ctx context.Context, clientset kubernetes.Interface, namespace string, req *buildcontract.SealedRequest, refs *sealedSecretRefs) {
	if refs.secretRef != "" {
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, refs.secretRef, metav1.DeleteOptions{})
	}
	if refs.keySecretRef != "" && refs.keySecretRef != req.KeySecretRef {
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, refs.keySecretRef, metav1.DeleteOptions{})
	}
	if refs.keyPasswordSecretRef != "" && refs.keyPasswordSecretRef != req.KeyPasswordSecretRef {
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, refs.keyPasswordSecretRef, metav1.DeleteOptions{})
	}
}
