package imagereseal

import (
	"context"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Start is registered as a manager Runnable, so it must sweep on startup and
// stop when the manager's context is cancelled.
func TestStartSweepsOrphanedSecrets(t *testing.T) {
	scheme := newTestScheme()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job-registry-auth",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			Labels: map[string]string{
				labels.Transient:   labels.ValueTrue,
				labels.ImageReseal: "job",
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	r := &Reconciler{Client: c, Scheme: scheme, Log: logr.Discard()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	err := wait.PollUntilContextTimeout(context.Background(), 10*time.Millisecond, 3*time.Second, true,
		func(ctx context.Context) (bool, error) {
			err := c.Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{})
			return k8serrors.IsNotFound(err), nil
		})
	if err != nil {
		t.Fatalf("orphaned Secret was not swept at startup: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}
}

// A deleted ImageReseal produces a NotFound reconcile; that path also sweeps,
// so cleanup does not wait for the next timer tick.
func TestReconcileSweepsOrphanAfterResealDeleted(t *testing.T) {
	scheme := newTestScheme()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job-seal-key",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			Labels: map[string]string{
				labels.Transient:   labels.ValueTrue,
				labels.ImageReseal: "job",
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	r := &Reconciler{Client: c, Scheme: scheme, Log: logr.Discard()}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "job"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if err := c.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("orphaned Secret was not swept by the NotFound reconcile: %v", err)
	}
}
