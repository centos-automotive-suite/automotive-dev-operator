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

package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	setupLog = ctrl.Log.WithName("init-secrets")
)

func main() {
	var namespace string
	flag.StringVar(&namespace, "namespace", "automotive-dev-operator-system", "The namespace to create secrets in")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog.Info("Starting OAuth secrets initialization", "namespace", namespace)

	if envNamespace := os.Getenv("POD_NAMESPACE"); envNamespace != "" {
		namespace = envNamespace
	}

	config := ctrl.GetConfigOrDie()
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		setupLog.Error(err, "unable to create Kubernetes client")
		os.Exit(1)
	}

	ctx := context.Background()

	secretsToEnsure := []string{
		"ado-build-api-oauth-proxy",
	}

	for _, secretName := range secretsToEnsure {
		if err := ensureOAuthSecret(ctx, clientset, namespace, secretName); err != nil {
			setupLog.Error(err, "failed to ensure OAuth secret", "secret", secretName)
			os.Exit(1)
		}
		setupLog.Info("OAuth secret ready", "secret", secretName)
	}

	setupLog.Info("OAuth secrets initialization completed successfully")
}

func ensureOAuthSecret(ctx context.Context, clientset *kubernetes.Clientset, namespace, secretName string) error {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get secret: %w", err)
		}

		cookieSecret, err := generateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("failed to generate cookie secret: %w", err)
		}

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"cookie-secret": cookieSecret,
			},
		}

		_, err = clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
		setupLog.Info("Created OAuth secret with random cookie-secret", "secret", secretName)
		return nil
	}

	if cookieSecret, ok := secret.Data["cookie-secret"]; !ok || len(cookieSecret) == 0 {
		newCookieSecret, err := generateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("failed to generate cookie secret: %w", err)
		}

		if secret.StringData == nil {
			secret.StringData = make(map[string]string)
		}
		secret.StringData["cookie-secret"] = newCookieSecret

		_, err = clientset.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
		setupLog.Info("Updated OAuth secret with random cookie-secret", "secret", secretName)
	} else {
		setupLog.V(1).Info("OAuth secret already has cookie-secret", "secret", secretName)
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
