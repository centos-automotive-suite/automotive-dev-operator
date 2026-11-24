package imagereseal

import (
	"context"
	stderrors "errors"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// pendingJobName is the name every pending-path test uses; each test builds its
// own client, so one name per test is enough.
const pendingJobName = "job-1"

// pendingResealJob builds an un-started job. Its architecture is set so the
// controller never tries to inspect the source image over the network.
func pendingResealJob(stages ...string) *automotivev1alpha1.ImageReseal {
	spec := automotivev1alpha1.ImageResealSpec{
		InputRef:     "quay.io/test/bootc:seal",
		OutputRef:    "quay.io/test/bootc:resealed",
		BuilderImage: "quay.io/test/builder:latest",
		Architecture: "amd64",
	}
	if len(stages) == 1 {
		spec.Operation = stages[0]
	} else {
		spec.Stages = stages
	}
	return &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: pendingJobName, Namespace: "ns", UID: types.UID(pendingJobName)},
		Spec:       spec,
	}
}

func pendingTestReconciler(t *testing.T, objs []client.Object, funcs interceptor.Funcs) (client.Client, *Reconciler) {
	t.Helper()
	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&automotivev1alpha1.ImageReseal{}).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
	return c, &Reconciler{Client: c, Scheme: scheme, Log: logr.Discard()}
}

func reconcilePending(t *testing.T, r *Reconciler) error {
	t.Helper()
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: pendingJobName}})
	return err
}

func getPendingJob(t *testing.T, c client.Client) *automotivev1alpha1.ImageReseal {
	t.Helper()
	job := &automotivev1alpha1.ImageReseal{}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: pendingJobName}, job); err != nil {
		t.Fatal(err)
	}
	return job
}

func assertJobNotFailed(t *testing.T, c client.Client) {
	t.Helper()
	if job := getPendingJob(t, c); job.Status.Phase == phaseFailed {
		t.Fatalf("phase = Failed (%q); a transient error must leave the job retryable", job.Status.Message)
	}
}

// A transient API error reading the OperatorConfig must be returned so the
// reconcile retries, not turned into a final Failed phase.
func TestPendingRetriesOperatorConfigReadError(t *testing.T) {
	job := pendingResealJob("reseal")
	apiErr := apierrors.NewServiceUnavailable("apiserver unavailable")
	c, r := pendingTestReconciler(t, []client.Object{job}, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*automotivev1alpha1.OperatorConfig); ok {
				return apiErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	err := reconcilePending(t, r)
	if !stderrors.Is(err, apiErr) {
		t.Fatalf("Reconcile error = %v, want the transient OperatorConfig error returned", err)
	}
	assertJobNotFailed(t, c)
}

// A conflict updating the sealed Tasks is transient: the reconcile must retry
// instead of failing the job.
func TestPendingRetriesSealedTaskUpdateConflict(t *testing.T) {
	job := pendingResealJob("reseal")
	existing := tasks.GenerateSealedTaskForOperation("ns", tasks.SealedOperationNames[0])
	conflict := apierrors.NewConflict(
		schema.GroupResource{Group: "tekton.dev", Resource: "tasks"}, existing.Name, stderrors.New("the object has been modified"))

	c, r := pendingTestReconciler(t, []client.Object{job, existing}, interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*tektonv1.Task); ok {
				return conflict
			}
			return c.Update(ctx, obj, opts...)
		},
	})

	err := reconcilePending(t, r)
	if !stderrors.Is(err, conflict) {
		t.Fatalf("Reconcile error = %v, want the update conflict returned", err)
	}
	assertJobNotFailed(t, c)
}

// A transient error creating the TaskRun or PipelineRun must be retried too.
func TestPendingRetriesRunCreateError(t *testing.T) {
	tests := []struct {
		name   string
		stages []string
		create func(client.Object) bool
	}{
		{
			name:   "taskrun",
			stages: []string{"reseal"},
			create: func(obj client.Object) bool { _, ok := obj.(*tektonv1.TaskRun); return ok },
		},
		{
			name:   "pipelinerun",
			stages: []string{"prepare-reseal", "reseal"},
			create: func(obj client.Object) bool { _, ok := obj.(*tektonv1.PipelineRun); return ok },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			job := pendingResealJob(tc.stages...)
			apiErr := apierrors.NewServiceUnavailable("apiserver unavailable")
			c, r := pendingTestReconciler(t, []client.Object{job}, interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if tc.create(obj) {
						return apiErr
					}
					return c.Create(ctx, obj, opts...)
				},
			})

			err := reconcilePending(t, r)
			if !stderrors.Is(err, apiErr) {
				t.Fatalf("Reconcile error = %v, want the transient create error returned", err)
			}
			assertJobNotFailed(t, c)
		})
	}
}

// Validation problems a retry cannot fix still fail the job.
func TestPendingFailsJobForInvalidSpec(t *testing.T) {
	tests := []struct {
		name   string
		stages []string
	}{
		{name: "no stages"},
		{name: "unknown stage", stages: []string{"bogus-op"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, r := pendingTestReconciler(t, []client.Object{pendingResealJob(tc.stages...)}, interceptor.Funcs{})

			if err := reconcilePending(t, r); err != nil {
				t.Fatalf("Reconcile returned error: %v", err)
			}

			job := getPendingJob(t, c)
			if job.Status.Phase != phaseFailed {
				t.Fatalf("phase = %q, want Failed for an invalid spec", job.Status.Phase)
			}
		})
	}
}

// The OperatorConfig is read once per reconcile. A missing config is accepted
// (defaults are used) rather than failing the job.
func TestPendingReadsOperatorConfigOnce(t *testing.T) {
	tests := []struct {
		name   string
		config bool
	}{
		{name: "missing config"},
		{name: "present config", config: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{pendingResealJob("reseal")}
			if tc.config {
				objs = append(objs, &automotivev1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
				})
			}

			gets := 0
			c, r := pendingTestReconciler(t, objs, interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*automotivev1alpha1.OperatorConfig); ok {
						gets++
					}
					return c.Get(ctx, key, obj, opts...)
				},
			})

			if err := reconcilePending(t, r); err != nil {
				t.Fatalf("Reconcile returned error: %v", err)
			}
			if gets != 1 {
				t.Fatalf("OperatorConfig read %d times, want 1", gets)
			}

			job := getPendingJob(t, c)
			if job.Status.Phase != phaseRunning {
				t.Fatalf("phase = %q (%q), want Running", job.Status.Phase, job.Status.Message)
			}
		})
	}
}

// The values derived from the OperatorConfig reach task generation and the run
// params, and a nil config degrades to defaults.
func TestOperatorConfigValuesPropagate(t *testing.T) {
	if got := insecureRegistryValue(nil); got != "false" {
		t.Fatalf("insecureRegistryValue(nil) = %q, want false", got)
	}
	if bc := buildConfigFromOperatorConfig(nil); bc == nil || bc.AutomotiveImageBuilderImage != "" {
		t.Fatalf("buildConfigFromOperatorConfig(nil) = %+v, want an empty config", bc)
	}

	config := &automotivev1alpha1.OperatorConfig{
		Spec: automotivev1alpha1.OperatorConfigSpec{
			Images:   &automotivev1alpha1.ImagesConfig{AutomotiveImageBuilder: "quay.io/test/aib:pinned"},
			OSBuilds: &automotivev1alpha1.OSBuildsConfig{InsecureRegistry: true},
		},
	}
	if got := insecureRegistryValue(config); got != "true" {
		t.Fatalf("insecureRegistryValue() = %q, want true", got)
	}
	if got := buildConfigFromOperatorConfig(config).AutomotiveImageBuilderImage; got != "quay.io/test/aib:pinned" {
		t.Fatalf("AutomotiveImageBuilderImage = %q, want the configured image", got)
	}
}
