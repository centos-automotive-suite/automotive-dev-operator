package secrets

import (
	"context"
	"crypto/rand"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// EnsureOAuthSecrets ensures that OAuth proxy secrets exist with random cookie secrets
func EnsureOAuthSecrets(ctx context.Context, c client.Client, namespace string) error {
	logger := log.FromContext(ctx)

	secrets := []struct {
		name   string
		labels map[string]string
	}{
		{
			name: "ado-build-api-oauth-proxy",
			labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
			},
		},
	}

	for _, s := range secrets {
		secret := &corev1.Secret{}
		err := c.Get(ctx, types.NamespacedName{Name: s.name, Namespace: namespace}, secret)

		if errors.IsNotFound(err) {
			// Secret doesn't exist, create it
			cookieSecret, err := generateRandomSecret(32)
			if err != nil {
				return fmt.Errorf("failed to generate cookie secret for %s: %w", s.name, err)
			}

			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.name,
					Namespace: namespace,
					Labels:    s.labels,
				},
				Type: corev1.SecretTypeOpaque,
				StringData: map[string]string{
					"cookie-secret": cookieSecret,
				},
			}

			if err := c.Create(ctx, secret); err != nil {
				return fmt.Errorf("failed to create secret %s: %w", s.name, err)
			}
			logger.Info("Created OAuth secret with random cookie-secret", "secret", s.name)
		} else if err != nil {
			return fmt.Errorf("failed to get secret %s: %w", s.name, err)
		} else {
			if cookieSecret, ok := secret.Data["cookie-secret"]; !ok || len(cookieSecret) == 0 {
				newCookieSecret, err := generateRandomSecret(32)
				if err != nil {
					return fmt.Errorf("failed to generate cookie secret for %s: %w", s.name, err)
				}

				if secret.StringData == nil {
					secret.StringData = make(map[string]string)
				}
				secret.StringData["cookie-secret"] = newCookieSecret

				if err := c.Update(ctx, secret); err != nil {
					return fmt.Errorf("failed to update secret %s: %w", s.name, err)
				}
				logger.Info("Updated OAuth secret with random cookie-secret", "secret", s.name)
			} else {
				logger.V(1).Info("OAuth secret already exists with cookie-secret", "secret", s.name)
			}
		}
	}

	return nil
}

func generateRandomSecret(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}
