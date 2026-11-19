package imagereseal

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const outputRef = tasks.DefaultInternalRegistryURL + "/ns/resealed:v1"

// resealJob builds a job whose grace period has already elapsed, so terminal
// cleanup acts at once. Its UID mirrors its name so it matches the owner
// reference it puts on its output stream. Tests that need a just-failed job set
// CompletionTime themselves.
func resealJob(name, phase string) *automotivev1alpha1.ImageReseal {
	job := &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name)},
		Spec:       automotivev1alpha1.ImageResealSpec{Operation: "reseal", OutputRef: outputRef},
		Status:     automotivev1alpha1.ImageResealStatus{Phase: phase},
	}
	if isTerminalPhase(phase) {
		job.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-time.Hour)}
	}
	return job
}

// pendingJob builds job-1, which the API accepted for alice and has not
// started yet. The architecture is pinned so the controller skips inspecting
// the source image.
func pendingJob() *automotivev1alpha1.ImageReseal {
	job := resealJob("job-1", phasePending)
	job.Annotations = map[string]string{labels.RequestedBy: "alice"}
	job.Spec.Architecture = "amd64"
	return job
}

// runningJob builds a job the API accepted for alice whose run is in flight,
// like one upgraded in flight from before the operator recorded output-stream
// ownership. Tests add the claim marker themselves when they need a job that
// already settled its claim.
func runningJob() *automotivev1alpha1.ImageReseal {
	job := pendingJob()
	job.Status.Phase = phaseRunning
	job.Status.TaskRunName = "job-1"
	return job
}

// runningTaskRun is the in-flight run of the running job, so its reconcile
// proceeds past the run lookup.
func runningTaskRun() *tektonv1.TaskRun {
	return &tektonv1.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: "job-1", Namespace: "ns"}}
}

// operatorConfig is the cluster configuration createSealedTaskRun requires.
func operatorConfig() *automotivev1alpha1.OperatorConfig {
	return &automotivev1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{
		Name:      "config",
		Namespace: controllerutils.OperatorNamespace(),
	}}
}

// streamOwner is the owner reference a reseal job of the given name puts on its
// output stream.
func streamOwner(name string) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: automotivev1alpha1.GroupVersion.String(),
		Kind:       "ImageReseal",
		Name:       name,
		UID:        types.UID(name),
	}
}

// unsettledStream is the output stream the API creates for a reseal job, owned by
// the named jobs. The registry adds status.tags once something is pushed to it.
func unsettledStream(owners ...string) *unstructured.Unstructured {
	stream := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "image.openshift.io/v1",
		"kind":       "ImageStream",
		"metadata": map[string]any{
			"name":      "resealed",
			"namespace": "ns",
			"labels": map[string]any{
				labels.ManagedBy: labels.ValueBuildAPI,
				labels.Transient: labels.ValueTrue,
			},
			"annotations": map[string]any{
				labels.RequestedBy: "alice",
			},
		},
	}}
	stream.SetGroupVersionKind(schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"})
	refs := make([]metav1.OwnerReference, 0, len(owners))
	for _, name := range owners {
		refs = append(refs, streamOwner(name))
	}
	stream.SetOwnerReferences(refs)
	return stream
}

func newResealClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&automotivev1alpha1.ImageReseal{}).
		WithObjects(objs...).
		Build()
}

// reconcileReseal reconciles job-1, the job every test in this file acts on.
func reconcileReseal(t *testing.T, c client.Client) ctrl.Result {
	t.Helper()
	r := &Reconciler{Client: c, Scheme: newTestScheme(), Log: logr.Discard()}
	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "job-1"}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func getStream(t *testing.T, c client.Client) *unstructured.Unstructured {
	t.Helper()
	stream := &unstructured.Unstructured{}
	stream.SetGroupVersionKind(schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"})
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "resealed"}, stream); err != nil {
		t.Fatal(err)
	}
	return stream
}

// getJob fetches job-1, the job every test in this file acts on.
func getJob(t *testing.T, c client.Client) *automotivev1alpha1.ImageReseal {
	t.Helper()
	job := &automotivev1alpha1.ImageReseal{}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "job-1"}, job); err != nil {
		t.Fatal(err)
	}
	return job
}

func ownerNames(stream *unstructured.Unstructured) []string {
	var names []string
	for _, ref := range stream.GetOwnerReferences() {
		names = append(names, ref.Name)
	}
	return names
}

func assertStreamGone(t *testing.T, c client.Client) {
	t.Helper()
	stream := &unstructured.Unstructured{}
	stream.SetGroupVersionKind(schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"})
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "resealed"}, stream); err == nil {
		t.Fatal("unused output ImageStream was not deleted")
	}
}

// A pending job claims its output stream before the run starts: reseal pods
// push as ado-build, which can push to an ImageStream but not create one. The
// job becomes an owner of the stream, so Kubernetes garbage-collects it once
// the last owning job is gone.
func TestReconcilePendingJobClaimsOutputStream(t *testing.T) {
	c := newResealClient(t, operatorConfig(), pendingJob())
	reconcileReseal(t, c)
	stream := getStream(t, c)
	if owners := ownerNames(stream); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want the job to own its output stream", owners)
	}
	if got := stream.GetAnnotations()[labels.RequestedBy]; got != "alice" {
		t.Errorf("requestedBy = %q, want the requesting user alice", got)
	}
	if got := getJob(t, c).Annotations[outputStreamClaimAnnotation]; got != claimStateClaimed {
		t.Errorf("claim marker = %q, want settled when the job starts", got)
	}
	if phase := getJob(t, c).Status.Phase; phase != phaseRunning {
		t.Errorf("phase = %q, want Running once the job started", phase)
	}
}

// A job that started before the operator recorded output-stream ownership —
// upgraded in flight, say — uses its stream with no owner reference, so a
// failed job sharing the output name could delete the stream out from under
// it. Its reconcile backfills the claim.
func TestReconcileRunningJobBackfillsOutputStreamClaim(t *testing.T) {
	c := newResealClient(t, operatorConfig(), runningJob(), runningTaskRun(), unsettledStream())
	reconcileReseal(t, c)
	if owners := ownerNames(getStream(t, c)); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want the running job's claim backfilled", owners)
	}
	if got := getJob(t, c).Annotations[outputStreamClaimAnnotation]; got != claimStateClaimed {
		t.Errorf("claim marker = %q, want the backfill settled", got)
	}
}

// Once the claim is settled, a running job's periodic reconciles leave the
// stream alone: the backfill runs once, not every ten seconds.
func TestReconcileRunningJobSkipsSettledClaim(t *testing.T) {
	job := runningJob()
	job.Annotations[outputStreamClaimAnnotation] = claimStateClaimed
	c := newResealClient(t, operatorConfig(), job, runningTaskRun(), unsettledStream())
	reconcileReseal(t, c)
	if owners := ownerNames(getStream(t, c)); len(owners) != 0 {
		t.Errorf("owners = %v, want none added to a settled claim", owners)
	}
}

// A stream replaced under the output name by another user's request can never
// be claimed: the backfill records the rejection without an owner reference and
// the job keeps running — its push fails either way — rather than retrying
// forever.
func TestReconcileRunningJobSettlesUnclaimableStream(t *testing.T) {
	stream := unsettledStream() // requested by bob, owned by nobody
	stream.SetAnnotations(map[string]string{labels.RequestedBy: "bob"})
	c := newResealClient(t, operatorConfig(), runningJob(), runningTaskRun(), stream)
	reconcileReseal(t, c)
	if phase := getJob(t, c).Status.Phase; phase != phaseRunning {
		t.Errorf("phase = %q, want Running: the backfill does not fail a running job", phase)
	}
	if got := getJob(t, c).Annotations[outputStreamClaimAnnotation]; got != claimStateRejected {
		t.Errorf("claim marker = %q, want the rejection recorded without retrying", got)
	}
	if owners := ownerNames(getStream(t, c)); len(owners) != 0 {
		t.Errorf("owners = %v, want another user's stream untouched", owners)
	}
}

// A stream replaced under the output name by another user's request since the
// API accepted the job cannot be claimed; the job fails rather than pushing
// into it, and the rejection is recorded so a later reconcile reports it
// again instead of skipping the check.
func TestReconcilePendingJobFailsOnAnotherUsersStream(t *testing.T) {
	stream := unsettledStream() // owned by nobody, but requested by bob
	stream.SetAnnotations(map[string]string{labels.RequestedBy: "bob"})
	c := newResealClient(t, operatorConfig(), pendingJob(), stream)
	reconcileReseal(t, c)
	if phase := getJob(t, c).Status.Phase; phase != phaseFailed {
		t.Errorf("phase = %q, want Failed on another user's stream", phase)
	}
	if got := getJob(t, c).Annotations[outputStreamClaimAnnotation]; got != claimStateRejected {
		t.Errorf("claim marker = %q, want the rejection recorded", got)
	}
	if owners := ownerNames(getStream(t, c)); len(owners) != 0 {
		t.Errorf("owners = %v, want another user's stream left untouched", owners)
	}
}

// A rejection must survive a failed status write. The write that fails the job
// can hit a conflict or a transient error, leaving the job Pending with the
// rejection already recorded. The retry must see the rejection again — not a
// settled claim — so the job fails instead of starting against another user's
// stream.
func TestReconcilePendingJobReReportsRejectedClaimAfterStatusWriteFailure(t *testing.T) {
	stream := unsettledStream() // owned by nobody, but requested by bob
	stream.SetAnnotations(map[string]string{labels.RequestedBy: "bob"})
	statusWrites := 0
	c := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&automotivev1alpha1.ImageReseal{}).
		WithObjects(operatorConfig(), pendingJob(), stream).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if subResourceName == "status" {
					statusWrites++
					if statusWrites == 1 {
						return errors.New("transient status write failure")
					}
				}
				return cl.SubResource(subResourceName).Update(ctx, obj, opts...)
			},
		}).
		Build()
	r := &Reconciler{Client: c, Scheme: newTestScheme(), Log: logr.Discard()}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "job-1"}}
	if _, err := r.Reconcile(t.Context(), req); err == nil {
		t.Fatal("first reconcile = nil error, want the failed status write reported")
	}
	// The retry succeeds at writing the status; the recorded rejection must
	// make the job fail, not start.
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	job := getJob(t, c)
	if job.Status.Phase != phaseFailed {
		t.Fatalf("phase = %q, want Failed on the retry — not Running against another user's stream", job.Status.Phase)
	}
	if got := job.Annotations[outputStreamClaimAnnotation]; got != claimStateRejected {
		t.Errorf("claim marker = %q, want the rejection kept", got)
	}
	if owners := ownerNames(getStream(t, c)); len(owners) != 0 {
		t.Errorf("owners = %v, want another user's stream left untouched", owners)
	}
}

// A completed job keeps its output: the stream may hold the published image, and
// its owner reference ties the stream's lifetime to the job.
func TestReconcileCompletedJobKeepsOutputStream(t *testing.T) {
	c := newResealClient(t, resealJob("job-1", phaseCompleted), unsettledStream("job-1"))
	reconcileReseal(t, c)
	stream := getStream(t, c)
	if owners := ownerNames(stream); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want the completed job to keep owning its stream", owners)
	}
}

// A job that has only just failed must not have its stream deleted yet: a push
// landing just before the failure reaches status.tags only after the registry
// processes it. The controller requeues and keeps the owner reference meanwhile,
// so a concurrent job cannot delete the stream out from under it.
func TestReconcileFreshlyFailedJobDefersDeletion(t *testing.T) {
	job := resealJob("job-1", phaseFailed)
	job.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	c := newResealClient(t, job, unsettledStream("job-1"))
	result := reconcileReseal(t, c)
	if result.RequeueAfter <= 0 || result.RequeueAfter > outputStreamDeleteGrace {
		t.Fatalf("RequeueAfter = %v, want a positive delay within the grace period", result.RequeueAfter)
	}
	if owners := ownerNames(getStream(t, c)); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want the owner reference kept during the grace period", owners)
	}
}

// A retry with the same output name also owns the stream, so the failed job must
// leave it for the retry. The failed job's reference lingers until its CR is
// deleted (then garbage-collected), so what matters is that the stream survives
// and the retry still owns it.
func TestReconcileFailedJobKeepsSharedOutputStream(t *testing.T) {
	c := newResealClient(t,
		resealJob("job-1", phaseFailed),
		resealJob("job-2", phaseRunning),
		unsettledStream("job-1", "job-2"),
	)
	reconcileReseal(t, c)
	if owners := ownerNames(getStream(t, c)); !slices.Contains(owners, "job-2") {
		t.Fatalf("owners = %v, want the running retry job-2 to still own the stream", owners)
	}
}

// Once the grace period has elapsed with the stream still empty and solely
// owned, the controller deletes it.
func TestReconcileFailedJobDeletesAfterGrace(t *testing.T) {
	job := resealJob("job-1", phaseFailed)
	job.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	c := newResealClient(t, job, unsettledStream("job-1"))
	result := reconcileReseal(t, c)
	if result.RequeueAfter != 0 {
		t.Fatalf("RequeueAfter = %v, want no requeue once the stream is gone", result.RequeueAfter)
	}
	assertStreamGone(t, c)
}

// A run that disappears is marked Failed without a run completion time. The
// controller must stamp CompletionTime then, so the next reconcile measures the
// delete grace from the failure rather than from the job's creation.
func TestReconcileMissingTaskRunStampsCompletionTime(t *testing.T) {
	job := resealJob("job-1", phaseRunning)
	job.CreationTimestamp = metav1.Time{Time: time.Now().Add(-time.Hour)}
	job.Status.TaskRunName = "gone"
	c := newResealClient(t, job, unsettledStream("job-1"))
	reconcileReseal(t, c)

	updated := getJob(t, c)
	if updated.Status.Phase != phaseFailed {
		t.Fatalf("phase = %q, want Failed", updated.Status.Phase)
	}
	if updated.Status.CompletionTime == nil {
		t.Fatal("CompletionTime not set on a failure detected without a run finishing")
	}
	// The next reconcile sees a fresh failure and waits out the grace instead of
	// deleting on the old creation time.
	result := reconcileReseal(t, c)
	if result.RequeueAfter <= 0 || result.RequeueAfter > outputStreamDeleteGrace {
		t.Fatalf("RequeueAfter = %v, want a delay within the grace period", result.RequeueAfter)
	}
}
