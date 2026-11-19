package imagereseal

import (
	"slices"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
	if phase == phaseCompleted || phase == phaseFailed {
		job.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-time.Hour)}
	}
	return job
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

func reconcileReseal(t *testing.T, c client.Client, name string) ctrl.Result {
	t.Helper()
	r := &Reconciler{Client: c, DirectClient: c, Scheme: newTestScheme(), Log: logr.Discard()}
	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: name}})
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

// A job that fails before pushing leaves an empty stream it solely owns. The
// controller drops its owner reference and deletes the now-unowned stream.
func TestReconcileFailedJobDeletesUnusedOutputStream(t *testing.T) {
	c := newResealClient(t, resealJob("job-1", phaseFailed), unsettledStream("job-1"))
	reconcileReseal(t, c, "job-1")
	assertStreamGone(t, c)
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
	reconcileReseal(t, c, "job-1")
	if owners := ownerNames(getStream(t, c)); !slices.Contains(owners, "job-2") {
		t.Fatalf("owners = %v, want the running retry job-2 to still own the stream", owners)
	}
}

// A failed job may have pushed a tag before a later stage failed; the image
// stays pullable, so the stream keeps its published data and its owner reference
// (so it is garbage-collected when the job is deleted rather than orphaned).
func TestReconcileFailedJobKeepsPublishedOutputStream(t *testing.T) {
	stream := unsettledStream("job-1")
	stream.Object["status"] = map[string]any{
		"tags": []any{map[string]any{"tag": "v1"}},
	}
	c := newResealClient(t, resealJob("job-1", phaseFailed), stream)
	reconcileReseal(t, c, "job-1")
	published := getStream(t, c)
	if tags, _, _ := unstructured.NestedSlice(published.Object, "status", "tags"); len(tags) != 1 {
		t.Fatalf("published tags = %v, want the pushed image kept", tags)
	}
	if owners := ownerNames(published); !slices.Contains(owners, "job-1") {
		t.Errorf("owners = %v, want the stream still owned so it is not orphaned", owners)
	}
}

// A completed job keeps its output: the stream may hold the published image, and
// its owner reference ties the stream's lifetime to the job.
func TestReconcileCompletedJobKeepsOutputStream(t *testing.T) {
	c := newResealClient(t, resealJob("job-1", phaseCompleted), unsettledStream("job-1"))
	reconcileReseal(t, c, "job-1")
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
	result := reconcileReseal(t, c, "job-1")
	if result.RequeueAfter <= 0 || result.RequeueAfter > outputStreamDeleteGrace {
		t.Fatalf("RequeueAfter = %v, want a positive delay within the grace period", result.RequeueAfter)
	}
	if owners := ownerNames(getStream(t, c)); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want the owner reference kept during the grace period", owners)
	}
}

// A second failed retry sharing the output name keeps the stream alive while it
// is still inside its grace period, so the other failed job's reconcile cannot
// delete an image the retry may have pushed.
func TestReconcileFailedJobKeepsStreamOwnedByAnotherFailedJobInGrace(t *testing.T) {
	pushed := resealJob("job-1", phaseFailed)
	pushed.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	other := resealJob("job-2", phaseFailed)
	other.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	c := newResealClient(t, pushed, other, unsettledStream("job-1", "job-2"))
	reconcileReseal(t, c, "job-2") // job-2's grace has elapsed
	if owners := ownerNames(getStream(t, c)); !slices.Contains(owners, "job-1") {
		t.Fatalf("owners = %v, want job-1 to keep the shared stream alive", owners)
	}
}

// A job and its retry both fail on the same empty output. Each reconcile drops
// only its own reference, so once both have run past the grace period the stream
// is unowned and deleted rather than lingering until the CRs are removed.
func TestReconcileConcurrentFailedJobsDeleteSharedStream(t *testing.T) {
	job1 := resealJob("job-1", phaseFailed)
	job1.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	job2 := resealJob("job-2", phaseFailed)
	job2.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	c := newResealClient(t, job1, job2, unsettledStream("job-1", "job-2"))
	reconcileReseal(t, c, "job-1") // drops job-1's reference, job-2 still owns it
	reconcileReseal(t, c, "job-2") // now unowned and empty
	assertStreamGone(t, c)
}

// Once the grace period has elapsed with the stream still empty and unowned, the
// controller deletes it.
func TestReconcileFailedJobDeletesAfterGrace(t *testing.T) {
	job := resealJob("job-1", phaseFailed)
	job.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	c := newResealClient(t, job, unsettledStream("job-1"))
	result := reconcileReseal(t, c, "job-1")
	if result.RequeueAfter != 0 {
		t.Fatalf("RequeueAfter = %v, want no requeue once the stream is gone", result.RequeueAfter)
	}
	assertStreamGone(t, c)
}

// Output refs outside the internal registry have no ImageStream to manage.
func TestReconcileExternalOutputRefNeedsNoStream(t *testing.T) {
	job := resealJob("job-1", phaseFailed)
	job.Spec.OutputRef = "quay.io/example/resealed:v1"
	c := newResealClient(t, job)
	reconcileReseal(t, c, "job-1")
}

// A stream that does not carry the job's owner reference is not its instance: it
// may be a replacement under the same name, or a stream a directly applied job
// (which never records ownership) is using. The failed job must leave it alone.
func TestReconcileFailedJobLeavesStreamItDoesNotOwn(t *testing.T) {
	job := resealJob("job-1", phaseFailed)
	job.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	c := newResealClient(t, job, unsettledStream()) // no owner references
	reconcileReseal(t, c, "job-1")
	if getStream(t, c) == nil {
		t.Fatal("stream not owned by the job was deleted")
	}
}

// A job that targets the stream without an owner reference (applied directly, or
// created before the API recorded ownership) still uses it. The failed job must
// release only its own reference and leave the stream for that job.
func TestReconcileFailedJobKeepsStreamUsedByUnreferencedJob(t *testing.T) {
	job := resealJob("job-1", phaseFailed)
	job.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * outputStreamDeleteGrace)}
	running := resealJob("job-2", phaseRunning) // no owner reference on the stream
	c := newResealClient(t, job, running, unsettledStream("job-1"))
	reconcileReseal(t, c, "job-1")
	stream := &unstructured.Unstructured{}
	stream.SetGroupVersionKind(schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"})
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "resealed"}, stream); err != nil {
		t.Fatalf("stream used by an unreferenced running job was deleted: %v", err)
	}
	if owners := ownerNames(stream); len(owners) != 0 {
		t.Errorf("owners = %v, want the failed job's reference released", owners)
	}
}

// A run that disappears is marked Failed without a run completion time. The
// controller must stamp CompletionTime then, so the next reconcile measures the
// delete grace from the failure rather than from the job's creation.
func TestReconcileMissingTaskRunStampsCompletionTime(t *testing.T) {
	job := resealJob("job-1", phaseRunning)
	job.CreationTimestamp = metav1.Time{Time: time.Now().Add(-time.Hour)}
	job.Status.TaskRunName = "gone"
	c := newResealClient(t, job, unsettledStream("job-1"))
	reconcileReseal(t, c, "job-1")

	updated := &automotivev1alpha1.ImageReseal{}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "job-1"}, updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Phase != phaseFailed {
		t.Fatalf("phase = %q, want Failed", updated.Status.Phase)
	}
	if updated.Status.CompletionTime == nil {
		t.Fatal("CompletionTime not set on a failure detected without a run finishing")
	}
	// The next reconcile sees a fresh failure and waits out the grace instead of
	// deleting on the old creation time.
	result := reconcileReseal(t, c, "job-1")
	if result.RequeueAfter <= 0 || result.RequeueAfter > outputStreamDeleteGrace {
		t.Fatalf("RequeueAfter = %v, want a delay within the grace period", result.RequeueAfter)
	}
}
