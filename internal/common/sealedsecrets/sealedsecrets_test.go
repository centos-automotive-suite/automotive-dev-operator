package sealedsecrets

import (
	"context"
	"errors"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "test-ns"

func newTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func newTestClientWithInterceptor(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

// transientSecret builds a Secret the way the build API does, with an explicit
// creation time so the sweep's age check is deterministic.
func transientSecret(job, suffix string, created time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              job + suffix,
			Namespace:         testNamespace,
			CreationTimestamp: metav1.NewTime(created),
			Labels: map[string]string{
				labels.Transient:   labels.ValueTrue,
				labels.ImageReseal: job,
			},
		},
	}
}

func reseal(job string) *automotivev1alpha1.ImageReseal {
	return &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: job, Namespace: testNamespace},
	}
}

func getSecret(t *testing.T, c client.Client, name string) (*corev1.Secret, error) {
	t.Helper()
	secret := &corev1.Secret{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: name}, secret)
	return secret, err
}

func TestSweepOrphanedDeletesSecretWithoutReseal(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	secret := transientSecret("job", RegistryAuthSuffix, old)
	c := newTestClient(t, secret)

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), 0)
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 1", deleted)
	}
	if _, err := getSecret(t, c, secret.Name); err == nil {
		t.Fatalf("orphaned Secret %s was not deleted", secret.Name)
	}
}

func TestSweepOrphanedKeepsSecretWhileResealExists(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	secret := transientSecret("job", SealKeySuffix, old)
	c := newTestClient(t, secret, reseal("job"))

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), 0)
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 0", deleted)
	}
	if _, err := getSecret(t, c, secret.Name); err != nil {
		t.Fatalf("active Secret %s was deleted: %v", secret.Name, err)
	}
}

// The API creates the Secrets before the ImageReseal, so a Secret without a
// job is not proof of an orphan until it is older than the grace period.
func TestSweepOrphanedKeepsRecentSecret(t *testing.T) {
	secret := transientSecret("job", RegistryAuthSuffix, time.Now())
	c := newTestClient(t, secret)

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), time.Hour)
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 0", deleted)
	}
	if _, err := getSecret(t, c, secret.Name); err != nil {
		t.Fatalf("recent Secret %s was deleted: %v", secret.Name, err)
	}
}

func TestSweepOrphanedKeepsUserAndUnrelatedSecrets(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	objs := []client.Object{
		// A Secret the requester supplied through keySecretRef.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "user-key", Namespace: testNamespace,
			Annotations: map[string]string{labels.RequestedBy: "user"},
		}},
		// A transient Secret belonging to an ImageBuild, not a sealed request.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "build-secret", Namespace: testNamespace,
			Labels: map[string]string{labels.Transient: labels.ValueTrue, labels.BuildName: "build"},
		}},
		// Labelled like a sealed request but not a name the API creates.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "not-a-derived-name", Namespace: testNamespace,
			CreationTimestamp: metav1.NewTime(old),
			Labels: map[string]string{
				labels.Transient:   labels.ValueTrue,
				labels.ImageReseal: "job",
			},
		}},
		// A user Secret named like ours but not created by the API.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "job" + SealKeySuffix, Namespace: testNamespace,
			CreationTimestamp: metav1.NewTime(old),
			Labels:            map[string]string{labels.ImageReseal: "job"},
		}},
	}
	c := newTestClient(t, objs...)

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), 0)
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 0", deleted)
	}
	for _, obj := range objs {
		if _, err := getSecret(t, c, obj.GetName()); err != nil {
			t.Fatalf("Secret %s was deleted: %v", obj.GetName(), err)
		}
	}
}

// A failed delete must not be forgotten: the next sweep removes the orphan.
func TestSweepOrphanedRetriesAfterDeleteFailure(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	secret := transientSecret("job", RegistryAuthSuffix, old)
	failures := 1
	c := newTestClientWithInterceptor(t, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if failures > 0 {
				failures--
				return errors.New("delete failed")
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, secret)

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), 0)
	if err == nil {
		t.Fatal("SweepOrphaned returned no error while deletes failed")
	}
	if deleted != 0 {
		t.Fatalf("SweepOrphaned deleted %d Secrets while the delete failed, want 0", deleted)
	}
	if _, err := getSecret(t, c, secret.Name); err != nil {
		t.Fatalf("Secret %s was deleted despite the delete failure: %v", secret.Name, err)
	}

	deleted, err = SweepOrphaned(context.Background(), c, logr.Discard(), 0)
	if err != nil {
		t.Fatalf("retry returned error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("retry deleted %d Secrets, want 1", deleted)
	}
	if _, err := getSecret(t, c, secret.Name); err == nil {
		t.Fatalf("orphaned Secret %s was not deleted on retry", secret.Name)
	}
}

// Losing the ImageReseal after the Secret exists makes it an orphan that the
// next sweep removes.
func TestSweepOrphanedRemovesSecretAfterResealIsDeleted(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	secret := transientSecret("job", SealKeyPasswordSuffix, old)
	job := reseal("job")
	c := newTestClient(t, secret, job)

	if deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), 0); err != nil || deleted != 0 {
		t.Fatalf("sweep with the job present = (%d, %v), want (0, nil)", deleted, err)
	}
	if err := c.Delete(context.Background(), job); err != nil {
		t.Fatalf("delete ImageReseal: %v", err)
	}

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard(), 0)
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 1", deleted)
	}
	if _, err := getSecret(t, c, secret.Name); err == nil {
		t.Fatalf("orphaned Secret %s was not deleted", secret.Name)
	}
}
