package buildapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

// defaultInternalRegistryURL is an alias for the shared constant.
const defaultInternalRegistryURL = tasks.DefaultInternalRegistryURL

func generateRegistryImageRef(host, namespace, imageName, tag string) string {
	return fmt.Sprintf("%s/%s/%s:%s", host, namespace, imageName, tag)
}

func translateToExternalURL(internalURL, externalRouteHost string) string {
	return strings.Replace(internalURL, defaultInternalRegistryURL, externalRouteHost, 1)
}

func getExternalRegistryRoute(ctx context.Context, k8sClient client.Client, namespace string) (string, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err != nil {
		if !k8serrors.IsNotFound(err) {
			return "", fmt.Errorf("error reading OperatorConfig: %w", err)
		}
		// OperatorConfig not found, fall through to auto-detection
	} else if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.ClusterRegistryRoute != "" {
		return operatorConfig.Spec.OSBuilds.ClusterRegistryRoute, nil
	}

	// Auto-detect from OpenShift Route
	route := &unstructured.Unstructured{}
	route.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "route.openshift.io",
		Version: "v1",
		Kind:    "Route",
	})
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "default-route",
		Namespace: "openshift-image-registry",
	}, route); err != nil {
		if k8serrors.IsNotFound(err) || apimeta.IsNoMatchError(err) {
			return "", fmt.Errorf("cannot determine external registry route: set clusterRegistryRoute in OperatorConfig or expose default-route in openshift-image-registry")
		}
		return "", fmt.Errorf("cannot determine external registry route: %w", err)
	}

	host, _, _ := unstructured.NestedString(route.Object, "spec", "host")
	if host == "" {
		return "", fmt.Errorf("default-route exists but has no host")
	}
	return host, nil
}

// resolveTokenLifetime loads the registry token lifetime from OperatorConfig.
func resolveTokenLifetime(ctx context.Context, k8sClient client.Client, namespace string) int64 {
	operatorCfg, err := loadOperatorConfigFn(ctx, k8sClient, namespace)
	if err != nil || operatorCfg == nil || operatorCfg.Spec.OSBuilds == nil {
		return automotivev1alpha1.DefaultRegistryTokenLifetimeSeconds
	}
	return operatorCfg.Spec.OSBuilds.GetRegistryTokenLifetimeSeconds()
}

func createInternalRegistrySecret(ctx context.Context, restCfg *rest.Config, namespace, buildName string, tokenLifetimeSeconds int64) (string, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", fmt.Errorf("error creating clientset: %w", err)
	}

	expSeconds := tokenLifetimeSeconds
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			ExpirationSeconds: &expSeconds,
		},
	}
	tokenResp, err := clientset.CoreV1().ServiceAccounts(namespace).
		CreateToken(ctx, automotivev1alpha1.BuildServiceAccountName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("error creating SA token: %w", err)
	}

	// Build dockerconfigjson
	auth := base64.StdEncoding.EncodeToString([]byte("serviceaccount:" + tokenResp.Status.Token))
	dockerConfig := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"}}}`, defaultInternalRegistryURL, auth)

	secretName := buildName + "-registry-auth"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.ResourceType: "registry-auth",
				labels.BuildName:    buildName,
				labels.Transient:    labels.ValueTrue,
			},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": []byte(dockerConfig),
		},
	}

	if _, err := clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("error creating internal registry secret: %w", err)
	}
	return secretName, nil
}

// ensureImageStream creates an ImageStream if it doesn't already exist.
// The OpenShift internal registry requires an ImageStream before oras can push to it.
func ensureImageStream(ctx context.Context, k8sClient client.Client, namespace, name string) (bool, error) {
	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})

	// Check if it already exists
	err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, is)
	if err == nil {
		return false, nil // already exists
	}
	if apimeta.IsNoMatchError(err) {
		return false, nil // not an OpenShift cluster; ImageStreams are not needed
	}
	if !k8serrors.IsNotFound(err) {
		return false, fmt.Errorf("error checking ImageStream %s: %w", name, err)
	}

	// Create it
	newIS := &unstructured.Unstructured{}
	newIS.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})
	newIS.SetName(name)
	newIS.SetNamespace(namespace)
	newIS.SetLabels(map[string]string{
		labels.ManagedBy: labels.ValueBuildAPI,
		labels.PartOf:    labels.ValueAutomotiveDev,
		labels.Transient: labels.ValueTrue,
	})

	if err := k8sClient.Create(ctx, newIS); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return false, nil
		}
		return false, fmt.Errorf("error creating ImageStream %s: %w", name, err)
	}
	return true, nil
}

func deleteImageStream(ctx context.Context, k8sClient client.Client, namespace, name string) error {
	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})
	is.SetName(name)
	is.SetNamespace(namespace)
	return k8sClient.Delete(ctx, is)
}

func deleteImageStreamTag(ctx context.Context, k8sClient client.Client, namespace, stream, tag string) error {
	ist := &unstructured.Unstructured{}
	ist.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStreamTag",
	})
	ist.SetName(stream + ":" + tag)
	ist.SetNamespace(namespace)
	return k8sClient.Delete(ctx, ist)
}

// imageStreamHasTags checks whether an ImageStream still has any tags.
func imageStreamHasTags(ctx context.Context, k8sClient client.Client, namespace, name string) (bool, error) {
	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, is); err != nil {
		return false, err
	}
	tags, _, _ := unstructured.NestedSlice(is.Object, "status", "tags")
	return len(tags) > 0, nil
}

// mintRegistryToken creates a fresh short-lived token for the pipeline SA
// so the caller can pull images from the internal registry.
func (a *APIServer) mintRegistryToken(ctx context.Context, c *gin.Context, namespace string, tokenLifetimeSeconds int64) (string, metav1.Time, error) {
	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		return "", metav1.Time{}, fmt.Errorf("error getting REST config for token mint: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", metav1.Time{}, fmt.Errorf("error creating clientset for token mint: %w", err)
	}
	expSeconds := tokenLifetimeSeconds
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			ExpirationSeconds: &expSeconds,
		},
	}
	tokenResp, err := clientset.CoreV1().ServiceAccounts(namespace).
		CreateToken(ctx, automotivev1alpha1.BuildServiceAccountName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", metav1.Time{}, fmt.Errorf("error creating token for SA %s in %s: %w", automotivev1alpha1.BuildServiceAccountName, namespace, err)
	}
	return tokenResp.Status.Token, tokenResp.Status.ExpirationTimestamp, nil
}

// resolveImageStreamRefs extracts the ImageStream name and the set of tags
// this build pushed to from its internal registry URLs.
// URL pattern: image-registry.openshift-image-registry.svc:5000/{namespace}/{stream}:{tag}
func resolveImageStreamRefs(build *automotivev1alpha1.ImageBuild) (string, []string) {
	prefix := defaultInternalRegistryURL + "/"
	var streamName string
	var tags []string
	for _, ref := range []string{build.Spec.GetContainerPush(), build.Spec.GetExportOCI()} {
		after, ok := strings.CutPrefix(ref, prefix)
		if !ok {
			continue
		}
		// "ns/name:tag" -> ["ns", "name:tag"]
		parts := strings.SplitN(after, "/", 2)
		if len(parts) < 2 {
			continue
		}
		// "name:tag" -> name, tag
		nameTag := strings.SplitN(parts[1], ":", 2)
		name := nameTag[0]
		if name == "" {
			continue
		}
		streamName = name
		if len(nameTag) == 2 && nameTag[1] != "" {
			tags = append(tags, nameTag[1])
		}
	}
	return streamName, tags
}
