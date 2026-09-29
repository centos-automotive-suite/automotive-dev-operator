package imagebuild

import (
	"context"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	routev1 "github.com/openshift/api/route/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ImageBuildReconciler) clusterRegistryRoute(ctx context.Context, config *automotivev1alpha1.OperatorConfig) (string, error) {
	if config.Spec.OSBuilds != nil && config.Spec.OSBuilds.ClusterRegistryRoute != "" {
		return config.Spec.OSBuilds.ClusterRegistryRoute, nil
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	route := &routev1.Route{}
	key := types.NamespacedName{Name: "default-route", Namespace: "openshift-image-registry"}
	if err := reader.Get(ctx, key, route); err != nil {
		if errors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to look up cluster registry route %s: %w", key, err)
	}
	r.Log.Info("Auto-detected cluster registry route", "route", route.Spec.Host)
	return route.Spec.Host, nil
}

func flashOCIAuthSecret(build *automotivev1alpha1.ImageBuild, username, password []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      build.Name + "-flash-oci-auth",
			Namespace: build.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "automotive-dev-operator",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				"automotive.sdv.cloud.redhat.com/build-name":    build.Name,
				"automotive.sdv.cloud.redhat.com/transient":     "true",
				"automotive.sdv.cloud.redhat.com/resource-type": "flash-oci-auth",
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(build, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"username": username, "password": password},
	}
}

func (r *ImageBuildReconciler) ensureFlashOCIAuth(ctx context.Context, build *automotivev1alpha1.ImageBuild, flash *flashTarget) (string, error) {
	if flash == nil || flash.imageRef == "" {
		return "", nil
	}
	var username, password []byte
	if build.Spec.GetUseServiceAccountAuth() {
		expiry := int64(4 * 3600)
		request := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &expiry}}
		account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name: automotivev1alpha1.BuildServiceAccountName, Namespace: build.Namespace,
		}}
		if err := r.SubResource("token").Create(ctx, account, request); err != nil {
			return "", fmt.Errorf("failed to create SA token for flash OCI credentials: %w", err)
		}
		username, password = []byte("serviceaccount"), []byte(request.Status.Token)
	} else if build.Spec.SecretRef != "" {
		registrySecret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: build.Namespace, Name: build.Spec.SecretRef}, registrySecret); err != nil {
			return "", fmt.Errorf("failed to read registry secret %q for flash OCI credentials: %w", build.Spec.SecretRef, err)
		}
		username, password = extractFlashCredentials(registrySecret, flash.imageRef, r.buildLogger(build))
		if len(username) == 0 && len(password) == 0 {
			r.buildLogger(build).Info("No usable credentials found in registry secret for flash OCI auth", "secret", build.Spec.SecretRef)
			return "", nil
		}
	}
	if len(username) == 0 || len(password) == 0 {
		return "", nil
	}
	desired := flashOCIAuthSecret(build, username, password)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: desired.Name, Namespace: desired.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Labels == nil {
			secret.Labels = make(map[string]string, len(desired.Labels))
		}
		for key, value := range desired.Labels {
			secret.Labels[key] = value
		}
		if len(secret.OwnerReferences) == 0 {
			secret.OwnerReferences = desired.OwnerReferences
		}
		secret.Type = desired.Type
		secret.Data = desired.Data
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to create/update flash OCI auth secret: %w", err)
	}
	return desired.Name, nil
}
