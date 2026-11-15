package buildapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/imagestream"
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
func (a *APIServer) resolveTokenLifetime(ctx context.Context, k8sClient client.Client, namespace string) int64 {
	operatorCfg, err := a.deps.loadOperatorConfig(ctx, k8sClient, namespace)
	if err != nil || operatorCfg == nil || operatorCfg.Spec.OSBuilds == nil {
		return automotivev1alpha1.DefaultRegistryTokenLifetimeSeconds
	}
	return operatorCfg.Spec.OSBuilds.GetRegistryTokenLifetimeSeconds()
}

// createInternalRegistrySecret stores a registry SA token for the build's pods.
// The token is bound to the Secret holding it, so it stops working when the
// build's transient Secrets are cleaned up rather than at the end of its lifetime.
func createInternalRegistrySecret(ctx context.Context, restCfg *rest.Config, namespace, buildName string, tokenLifetimeSeconds int64) (string, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", fmt.Errorf("error creating clientset: %w", err)
	}

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
		// The token can only be bound to a Secret that exists, so start empty.
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`),
		},
	}
	secrets := clientset.CoreV1().Secrets(namespace)
	created, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("error creating internal registry secret: %w", err)
	}
	// Don't leave a Secret behind that a build would mount without working
	// credentials, or that makes a retry with this build name hit AlreadyExists.
	// The request may already be canceled, so clean up on a context of our own.
	fail := func(err error) (string, error) {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if delErr := secrets.Delete(cleanupCtx, created.Name, metav1.DeleteOptions{}); delErr != nil && !k8serrors.IsNotFound(delErr) {
			return "", fmt.Errorf("%w (deleting secret %s also failed: %v)", err, created.Name, delErr)
		}
		return "", err
	}

	expSeconds := tokenLifetimeSeconds
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			ExpirationSeconds: &expSeconds,
			BoundObjectRef: &authnv1.BoundObjectReference{
				Kind: "Secret", APIVersion: "v1", Name: created.Name, UID: created.UID,
			},
		},
	}
	tokenResp, err := clientset.CoreV1().ServiceAccounts(namespace).
		CreateToken(ctx, automotivev1alpha1.RegistryServiceAccountName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		return fail(fmt.Errorf("error creating registry SA token: %w", err))
	}
	auth := base64.StdEncoding.EncodeToString([]byte("serviceaccount:" + tokenResp.Status.Token))
	created.Data[corev1.DockerConfigJsonKey] = fmt.Appendf(nil, `{"auths":{"%s":{"auth":"%s"}}}`, defaultInternalRegistryURL, auth)
	if _, err := secrets.Update(ctx, created, metav1.UpdateOptions{}); err != nil {
		return fail(fmt.Errorf("error storing registry SA token: %w", err))
	}
	return secretName, nil
}

// ensureImageStream creates an ImageStream if it doesn't already exist.
// The OpenShift internal registry requires an ImageStream before oras can push to it.
// internalImageStreamName returns the ImageStream that ref pushes to when it
// points at namespace in the internal registry, and "" for any other ref.
func internalImageStreamName(ref, namespace string) string {
	path, ok := strings.CutPrefix(ref, defaultInternalRegistryURL+"/"+namespace+"/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(path, "@")
	name, _, _ = strings.Cut(name, ":")
	if name == "" || strings.Contains(name, "/") {
		return ""
	}
	return name
}

// imageStreamErrorStatus maps an imagestream.Ensure or CheckOwner error to the
// response status: naming another user's stream is the caller's fault.
func imageStreamErrorStatus(err error) int {
	if errors.Is(err, imagestream.ErrNotOwned) {
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
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

// Recorded artifacts survive flash failures and expiry, but may no longer be pullable.
func buildRegistryTokenEligible(build *automotivev1alpha1.ImageBuild, requester string) bool {
	if requester != build.Annotations[labels.RequestedBy] ||
		!build.Spec.GetUseServiceAccountAuth() || !isTerminalPhase(build.Status.Phase) {
		return false
	}
	container, disk := storedArtifactURLs(build)
	return container != "" || disk != ""
}

// mintRegistryToken creates a fresh short-lived token for the pull-only
// registry SA, for users to pull images from the internal registry. Callers
// fetch it after the build's transient Secrets are gone, so only its lifetime
// bounds it.
func (a *APIServer) mintRegistryToken(ctx context.Context, c *gin.Context, namespace string, tokenLifetimeSeconds int64) (string, metav1.Time, error) {
	restCfg, err := a.deps.getRESTConfigFromRequest(c)
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
		CreateToken(ctx, automotivev1alpha1.RegistryPullServiceAccountName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", metav1.Time{}, fmt.Errorf("error creating token for SA %s in %s: %w", automotivev1alpha1.RegistryPullServiceAccountName, namespace, err)
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
