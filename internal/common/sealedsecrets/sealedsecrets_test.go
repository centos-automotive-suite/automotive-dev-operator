package sealedsecrets

import (
	"context"
	"errors"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	testNamespace = "test-ns"
	testJob       = "job"
)

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

// transientSecret builds a Secret the way the build API does.
func transientSecret(suffix string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testJob + suffix,
			Namespace: testNamespace,
			Labels: map[string]string{
				labels.Transient:   labels.ValueTrue,
				labels.ImageReseal: testJob,
			},
		},
	}
}

func reseal() *automotivev1alpha1.ImageReseal {
	return &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: testJob, Namespace: testNamespace},
	}
}

func getSecret(t *testing.T, c client.Client, name string) error {
	t.Helper()
	return c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: name}, &corev1.Secret{})
}

func TestSweepOrphaned(t *testing.T) {
	for _, tc := range []struct {
		name        string
		objs        []client.Object
		wantDeleted int
		wantKept    []string
	}{
		{name: "orphaned transient Secret", objs: []client.Object{transientSecret(RegistryAuthSuffix)}, wantDeleted: 1},
		{name: "Secret with its job", objs: []client.Object{transientSecret(SealKeySuffix), reseal()}, wantKept: []string{testJob + SealKeySuffix}},
		// A Secret the requester supplied through keySecretRef.
		{name: "user-provided Secret", objs: []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:        "user-key",
			Namespace:   testNamespace,
			Annotations: map[string]string{labels.RequestedBy: "user"},
		}}}, wantKept: []string{"user-key"}},
		// A transient Secret belonging to an ImageBuild, not a sealed request.
		{name: "transient Secret of another type", objs: []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      "build-secret",
			Namespace: testNamespace,
			Labels:    map[string]string{labels.Transient: labels.ValueTrue, labels.BuildName: "build"},
		}}}, wantKept: []string{"build-secret"}},
		// Labelled like a sealed request but not a name the API creates.
		{name: "sealed labels, foreign name", objs: []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      "not-a-derived-name",
			Namespace: testNamespace,
			Labels: map[string]string{
				labels.Transient:   labels.ValueTrue,
				labels.ImageReseal: testJob,
			},
		}}}, wantKept: []string{"not-a-derived-name"}},
		// A user Secret named like ours but not created by the API.
		{name: "derived name, no transient label", objs: []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      testJob + SealKeySuffix,
			Namespace: testNamespace,
			Labels:    map[string]string{labels.ImageReseal: testJob},
		}}}, wantKept: []string{testJob + SealKeySuffix}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, tc.objs...)
			deleted, err := SweepOrphaned(context.Background(), c, logr.Discard())
			if err != nil {
				t.Fatalf("SweepOrphaned returned error: %v", err)
			}
			if deleted != tc.wantDeleted {
				t.Fatalf("SweepOrphaned deleted %d Secrets, want %d", deleted, tc.wantDeleted)
			}
			for _, name := range tc.wantKept {
				if err := getSecret(t, c, name); err != nil {
					t.Fatalf("Secret %s was deleted: %v", name, err)
				}
			}
		})
	}
}

// A failed delete must not be forgotten: the next sweep removes the orphan.
func TestSweepOrphanedRetriesAfterDeleteFailure(t *testing.T) {
	secret := transientSecret(RegistryAuthSuffix)
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

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard())
	if err == nil {
		t.Fatal("SweepOrphaned returned no error while deletes failed")
	}
	if deleted != 0 {
		t.Fatalf("SweepOrphaned deleted %d Secrets while the delete failed, want 0", deleted)
	}
	if err := getSecret(t, c, secret.Name); err != nil {
		t.Fatalf("Secret %s was deleted despite the delete failure: %v", secret.Name, err)
	}

	deleted, err = SweepOrphaned(context.Background(), c, logr.Discard())
	if err != nil {
		t.Fatalf("retry returned error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("retry deleted %d Secrets, want 1", deleted)
	}
	if err := getSecret(t, c, secret.Name); err == nil {
		t.Fatalf("orphaned Secret %s was not deleted on retry", secret.Name)
	}
}

// Losing the ImageReseal after the Secret exists makes it an orphan that the
// next sweep removes.
func TestSweepOrphanedRemovesSecretAfterResealIsDeleted(t *testing.T) {
	secret := transientSecret(SealKeyPasswordSuffix)
	job := reseal()
	c := newTestClient(t, secret, job)

	if deleted, err := SweepOrphaned(context.Background(), c, logr.Discard()); err != nil || deleted != 0 {
		t.Fatalf("sweep with the job present = (%d, %v), want (0, nil)", deleted, err)
	}
	if err := c.Delete(context.Background(), job); err != nil {
		t.Fatalf("delete ImageReseal: %v", err)
	}

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard())
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 1", deleted)
	}
	if err := getSecret(t, c, secret.Name); err == nil {
		t.Fatalf("orphaned Secret %s was not deleted", secret.Name)
	}
}

// The delete must be pinned to the UID the sweep listed, not just the name.
func TestSweepOrphanedDeletesWithUIDPrecondition(t *testing.T) {
	secret := transientSecret(RegistryAuthSuffix)
	secret.UID = "listed-uid"
	seen := false
	c := newTestClientWithInterceptor(t, interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			var del client.DeleteOptions
			del.ApplyOptions(opts)
			switch {
			case del.Preconditions == nil || del.Preconditions.UID == nil:
				t.Error("sweep deleted without a UID precondition")
			case *del.Preconditions.UID != secret.UID:
				t.Errorf("precondition UID = %q, want %q", *del.Preconditions.UID, secret.UID)
			default:
				seen = true
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, secret)

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard())
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 1", deleted)
	}
	if !seen {
		t.Fatal("sweep did not delete with the listed UID")
	}
}

// If the name is reused after the sweep listed the old Secret, the delete
// conflicts and the replacement (an active Secret) survives.
func TestSweepOrphanedLeavesReplacementSecret(t *testing.T) {
	replacement := transientSecret(RegistryAuthSuffix)
	replacement.UID = "new-uid"
	c := newTestClientWithInterceptor(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}
			// Hand the sweep a snapshot from before the replacement.
			if secrets, ok := list.(*corev1.SecretList); ok {
				for i := range secrets.Items {
					if secrets.Items[i].Name == replacement.Name {
						secrets.Items[i].UID = "old-uid"
					}
				}
			}
			return nil
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			var del client.DeleteOptions
			del.ApplyOptions(opts)
			current := &corev1.Secret{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
				return err
			}
			if del.Preconditions == nil || del.Preconditions.UID == nil || *del.Preconditions.UID != current.UID {
				return k8serrors.NewConflict(corev1.Resource("secrets"), obj.GetName(), errors.New("the object has been modified"))
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, replacement)

	deleted, err := SweepOrphaned(context.Background(), c, logr.Discard())
	if err != nil {
		t.Fatalf("SweepOrphaned returned error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("SweepOrphaned deleted %d Secrets, want 0", deleted)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(replacement), &corev1.Secret{}); err != nil {
		t.Fatalf("replacement Secret was deleted: %v", err)
	}
}
