package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

// sealedSecretRefs holds the resolved secret references for a sealed operation.
type sealedSecretRefs struct {
	secretRef            string
	keySecretRef         string
	keyPasswordSecretRef string
}

// createSealedSecrets creates any transient secrets needed for a sealed operation (registry auth, seal key, key password).
func createSealedSecrets(ctx context.Context, clientset kubernetes.Interface, namespace string, req *SealedRequest) (*sealedSecretRefs, error) {
	refs := &sealedSecretRefs{
		keySecretRef:         req.KeySecretRef,
		keyPasswordSecretRef: req.KeyPasswordSecretRef,
	}

	if req.RegistryCredentials != nil && req.RegistryCredentials.Enabled {
		creds := req.RegistryCredentials
		secretName := req.Name + "-registry-auth"
		secretData, err := buildSealedRegistrySecretData(creds)
		if err != nil {
			return nil, err
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels: map[string]string{
					labels.ImageReseal: req.Name,
					labels.Transient:   labels.ValueTrue,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: secretData,
		}
		if _, err := clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return nil, fmt.Errorf("failed to create registry secret: %w", err)
		}
		refs.secretRef = secretName
	}

	if strings.TrimSpace(req.KeyContent) != "" && refs.keySecretRef == "" {
		keySecretName := req.Name + "-seal-key"
		keySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      keySecretName,
				Namespace: namespace,
				Labels: map[string]string{
					labels.ImageReseal: req.Name,
					labels.Transient:   labels.ValueTrue,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"private-key": []byte(req.KeyContent),
			},
		}
		if _, err := clientset.CoreV1().Secrets(namespace).Create(ctx, keySecret, metav1.CreateOptions{}); err != nil {
			cleanupSealedSecrets(ctx, clientset, namespace, req, refs)
			return nil, fmt.Errorf("failed to create seal-key secret: %w", err)
		}
		refs.keySecretRef = keySecretName

		if strings.TrimSpace(req.KeyPassword) != "" {
			keyPwSecretName := req.Name + "-seal-key-password"
			keyPwSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      keyPwSecretName,
					Namespace: namespace,
					Labels: map[string]string{
						labels.ImageReseal: req.Name,
						labels.Transient:   labels.ValueTrue,
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"password": []byte(req.KeyPassword),
				},
			}
			if _, err := clientset.CoreV1().Secrets(namespace).Create(ctx, keyPwSecret, metav1.CreateOptions{}); err != nil {
				cleanupSealedSecrets(ctx, clientset, namespace, req, refs)
				return nil, fmt.Errorf("failed to create seal-key-password secret: %w", err)
			}
			refs.keyPasswordSecretRef = keyPwSecretName
		}
	}

	return refs, nil
}

func buildSealedRegistrySecretData(creds *RegistryCredentials) (map[string][]byte, error) {
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
func cleanupSealedSecrets(ctx context.Context, clientset kubernetes.Interface, namespace string, req *SealedRequest, refs *sealedSecretRefs) {
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

func transientSealedSecretRefs(req *SealedRequest, refs *sealedSecretRefs) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, exists := seen[name]; exists {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	add(refs.secretRef)
	if refs.keySecretRef != "" && refs.keySecretRef != req.KeySecretRef {
		add(refs.keySecretRef)
	}
	if refs.keyPasswordSecretRef != "" && refs.keyPasswordSecretRef != req.KeyPasswordSecretRef {
		add(refs.keyPasswordSecretRef)
	}
	return out
}

func setImageResealSecretOwnerRef(
	ctx context.Context,
	clientset kubernetes.Interface,
	namespace, secretName string,
	imageSealed *automotivev1alpha1.ImageReseal,
) error {
	createdSecret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	createdSecret.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: automotivev1alpha1.GroupVersion.String(),
		Kind:       "ImageReseal",
		Name:       imageSealed.Name,
		UID:        imageSealed.UID,
	}}
	_, err = clientset.CoreV1().Secrets(namespace).Update(ctx, createdSecret, metav1.UpdateOptions{})
	return err
}
