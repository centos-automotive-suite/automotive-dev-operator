package imagereseal

import (
	"context"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func cleanupClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&automotivev1alpha1.ImageReseal{}).
		WithObjects(objs...).
		Build()
}

func reconcile(t *testing.T, c client.Client, name string) (ctrl.Result, error) {
	t.Helper()
	r := &Reconciler{Client: c, Scheme: newTestScheme(), Log: logr.Discard()}
	return r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: name}})
}

// Terminal cleanup deletes the Secrets the API created but never a Secret the
// requester supplied via keySecretRef, matching ImageBuild's ownership rules.
func TestReconcileFailedJobCleansUpTransientSecrets(t *testing.T) {
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
	job := &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "test-ns"},
		Spec: automotivev1alpha1.ImageResealSpec{
			Operation:    "reseal",
			SecretRef:    transient.Name,
			KeySecretRef: userProvided.Name,
		},
		Status: automotivev1alpha1.ImageResealStatus{
			Phase:          phaseFailed,
			CompletionTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
		},
	}
	c := cleanupClient(t, transient, userProvided, job)

	if result, err := reconcile(t, c, "job"); err != nil || result.RequeueAfter != 0 {
		t.Fatalf("reconcile = (%v, %v), want no error and no requeue", result, err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(transient), &corev1.Secret{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("transient Secret was not deleted: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(userProvided), &corev1.Secret{}); err != nil {
		t.Fatalf("user-provided Secret was deleted: %v", err)
	}
}

// The API creates the job before its transient Secrets, so a just-admitted job
// can be reconciled before they land. The run must not start until they exist.
func TestReconcilePendingJobWaitsForSetupSecrets(t *testing.T) {
	job := &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "test-ns"},
		Spec: automotivev1alpha1.ImageResealSpec{
			Operation:    "reseal",
			Architecture: "amd64", // skip the source-image inspection
			SecretRef:    "job-registry-auth",
		},
	}
	c := cleanupClient(t, &automotivev1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{
		Name:      "config",
		Namespace: controllerutils.OperatorNamespace(),
	}}, job)

	if _, err := reconcile(t, c, "job"); err == nil {
		t.Fatal("reconcile of a job whose setup Secret is missing = nil error, want a retry")
	}
	// No run started while the Secret was missing.
	runs := &tektonv1.TaskRunList{}
	if err := c.List(context.Background(), runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("%d TaskRuns created before the setup Secret existed", len(runs.Items))
	}

	// The Secret lands; the job now starts.
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      "job-registry-auth",
		Namespace: "test-ns",
		Labels: map[string]string{
			labels.Transient:   labels.ValueTrue,
			labels.ImageReseal: "job",
		},
	}}
	if err := c.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcile(t, c, "job"); err != nil {
		t.Fatalf("reconcile after the Secret landed: %v", err)
	}
	updated := &automotivev1alpha1.ImageReseal{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "job", Namespace: "test-ns"}, updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Phase != phaseRunning {
		t.Fatalf("phase = %q, want Running once the setup Secret exists", updated.Status.Phase)
	}
}
