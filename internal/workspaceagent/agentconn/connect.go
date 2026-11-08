// Package agentconn connects the build API and the controllers to an agent:
// a workspace's, or the one in a build's upload pod. It is separate from workspaceagent so the agent binary
// doesn't link the Kubernetes client.
package agentconn

import (
	"context"
	"crypto/x509"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CABundleConfigMap receives OpenShift's service CA bundle, which signs
	// the agents' serving certificates.
	CABundleConfigMap = "ado-service-ca"
	// InjectCABundleAnn asks OpenShift to fill a ConfigMap with the bundle.
	InjectCABundleAnn = "service.beta.openshift.io/inject-cabundle"
	// ServingCertAnn asks OpenShift's service CA to issue a certificate for
	// a Service into the named Secret, and to rotate it.
	ServingCertAnn = "service.beta.openshift.io/serving-cert-secret-name"
	caBundleKey    = "service-ca.crt"
)

// Connect returns a client for ws's agent: its Service over TLS, trusting the
// service CA, with the bearer token from the workspace's token Secret.
func Connect(ctx context.Context, kube client.Reader, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
	return connect(ctx, kube, ws.Namespace, workspaceagent.ServiceName(ws.Name), workspaceagent.TokenSecretName(ws.Name))
}

// ConnectUpload returns a client for the agent in build's upload pod, as
// Connect does for a workspace's.
func ConnectUpload(ctx context.Context, kube client.Reader, build *automotivev1alpha1.ImageBuild) (*workspaceagent.Client, error) {
	return connect(ctx, kube, build.Namespace, workspaceagent.UploadServiceName(build.Name), workspaceagent.UploadTokenSecretName(build.Name))
}

func connect(ctx context.Context, kube client.Reader, namespace, service, tokenSecret string) (*workspaceagent.Client, error) {
	secret := &corev1.Secret{}
	if err := kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: tokenSecret}, secret); err != nil {
		return nil, fmt.Errorf("reading the agent token %s: %w", tokenSecret, err)
	}
	token := secret.Data[workspaceagent.TokenKey]
	if len(token) == 0 {
		return nil, fmt.Errorf("agent token %s is empty", secret.Name)
	}
	bundle := &corev1.ConfigMap{}
	if err := kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: CABundleConfigMap}, bundle); err != nil {
		return nil, fmt.Errorf("reading the service CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.Data[caBundleKey])) {
		return nil, fmt.Errorf("service CA bundle %s has no certificates yet", CABundleConfigMap)
	}
	url := fmt.Sprintf("https://%s.%s.svc:%d", service, namespace, workspaceagent.APIPort)
	return workspaceagent.NewClient(url, string(token), roots), nil
}
