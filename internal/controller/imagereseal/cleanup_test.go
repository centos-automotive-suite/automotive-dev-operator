package imagereseal

import (
	"context"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Terminal cleanup deletes the Secrets the API created but never a Secret the
// requester supplied via keySecretRef, matching ImageBuild's ownership rules.
func TestCleanupTransientSecretsKeepsUserProvided(t *testing.T) {
	scheme := newTestScheme()
	transient := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      "job-registry-auth",
		Namespace: "test-ns",
		Labels: map[string]string{
			labels.Transient:   labels.ValueTrue,
			labels.ImageReseal: "job",
		},
	}}
	userProvided := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:        "user-seal-key",
		Namespace:   "test-ns",
		Annotations: map[string]string{labels.RequestedBy: "user"},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(transient, userProvided).Build()
	r := &Reconciler{Client: c, Scheme: scheme, Log: logr.Discard()}

	sealed := &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "test-ns"},
		Spec: automotivev1alpha1.ImageResealSpec{
			SecretRef:    transient.Name,
			KeySecretRef: userProvided.Name,
		},
	}
	if err := r.cleanupTransientSecrets(context.Background(), sealed, logr.Discard()); err != nil {
		t.Fatalf("cleanupTransientSecrets returned error: %v", err)
	}

	if err := c.Get(context.Background(), client.ObjectKeyFromObject(transient), &corev1.Secret{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("transient Secret was not deleted: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(userProvided), &corev1.Secret{}); err != nil {
		t.Fatalf("user-provided Secret was deleted: %v", err)
	}
}
