// Package agentconn connects the build API and the workspace controller to a
// workspace's agent. It is separate from workspaceagent so the agent binary
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
	caBundleKey       = "service-ca.crt"
)

// Connect returns a client for ws's agent: its Service over TLS, trusting the
// service CA, with the bearer token from the workspace's token Secret.
func Connect(ctx context.Context, kube client.Reader, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
	secret := &corev1.Secret{}
	if err := kube.Get(ctx, client.ObjectKey{Namespace: ws.Namespace, Name: workspaceagent.TokenSecretName(ws.Name)}, secret); err != nil {
		return nil, fmt.Errorf("reading the workspace agent token: %w", err)
	}
	token := secret.Data[workspaceagent.TokenKey]
	if len(token) == 0 {
		return nil, fmt.Errorf("workspace agent token %s is empty", secret.Name)
	}
	bundle := &corev1.ConfigMap{}
	if err := kube.Get(ctx, client.ObjectKey{Namespace: ws.Namespace, Name: CABundleConfigMap}, bundle); err != nil {
		return nil, fmt.Errorf("reading the service CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.Data[caBundleKey])) {
		return nil, fmt.Errorf("service CA bundle %s has no certificates yet", CABundleConfigMap)
	}
	url := fmt.Sprintf("https://%s.%s.svc:%d", workspaceagent.ServiceName(ws.Name), ws.Namespace, workspaceagent.APIPort)
	return workspaceagent.NewClient(url, string(token), roots), nil
}
