package imagestream

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// resealOwner is the owner reference a reseal job of the given name puts on its
// output stream; the UID mirrors the name so tests can reference it.
func resealOwner(name string) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
		Kind:       "ImageReseal",
		Name:       name,
		UID:        types.UID(name),
	}
}

func streamOwnedBy(owner string) *unstructured.Unstructured {
	stream := object("ImageStream", "ns", "demo")
	if owner != "" {
		stream.SetAnnotations(map[string]string{labels.RequestedBy: owner})
	}
	return stream
}

// transientStream is a stream the API created for owner, carrying the given job
// owner references.
func transientStream(owner string, owners ...metav1.OwnerReference) *unstructured.Unstructured {
	stream := object("ImageStream", "ns", "demo")
	stream.SetLabels(map[string]string{
		labels.ManagedBy: labels.ValueBuildAPI,
		labels.Transient: labels.ValueTrue,
	})
	stream.SetAnnotations(map[string]string{labels.RequestedBy: owner})
	if len(owners) > 0 {
		stream.SetOwnerReferences(owners)
	}
	return stream
}

// unmanagedStream is a stream the operator does not manage (no transient
// label), requested by owner and carrying the given job owner references.
func unmanagedStream(owner string, owners ...metav1.OwnerReference) *unstructured.Unstructured {
	stream := transientStream(owner, owners...)
	stream.SetLabels(map[string]string{labels.ManagedBy: labels.ValueBuildAPI})
	return stream
}

func ownerNames(stream *unstructured.Unstructured) []string {
	var names []string
	for _, ref := range stream.GetOwnerReferences() {
		names = append(names, ref.Name)
	}
	return names
}

func newClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(objs...).Build()
}

func TestEnsureCreatesStreamForOwner(t *testing.T) {
	c := newClient()
	created, err := Ensure(t.Context(), c, "ns", "demo", "alice")
	if err != nil || !created {
		t.Fatalf("Ensure() = %t, %v; want created", created, err)
	}
	stream := object("ImageStream", "", "")
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "demo"}, stream); err != nil {
		t.Fatal(err)
	}
	if owner := stream.GetAnnotations()[labels.RequestedBy]; owner != "alice" {
		t.Errorf("owner = %q, want alice", owner)
	}
	if stream.GetLabels()[labels.ManagedBy] != labels.ValueBuildAPI || stream.GetLabels()[labels.Transient] != labels.ValueTrue {
		t.Errorf("labels = %v", stream.GetLabels())
	}
}

func TestEnsureExistingStream(t *testing.T) {
	for _, tc := range []struct {
		owner   string
		wantErr bool
	}{
		{owner: "alice"},
		{owner: "bob", wantErr: true},
		{owner: "", wantErr: true},
	} {
		t.Run("owner="+tc.owner, func(t *testing.T) {
			created, err := Ensure(t.Context(), newClient(streamOwnedBy(tc.owner)), "ns", "demo", "alice")
			if created {
				t.Fatal("Ensure() created a stream that already existed")
			}
			if gotErr := errors.Is(err, ErrNotOwned); gotErr != tc.wantErr {
				t.Fatalf("Ensure() err = %v, want ErrNotOwned: %t", err, tc.wantErr)
			}
		})
	}
}

func TestRemoveTagsDeletesEmptiedStream(t *testing.T) {
	c := newClient(streamOwnedBy("alice"), object("ImageStreamTag", "ns", "demo:disk"))
	if err := RemoveTags(t.Context(), c, "ns", "demo", "alice", []string{"disk"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "demo:disk"}, object("ImageStreamTag", "", "")); err == nil {
		t.Error("removed tag still exists")
	}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "ns", Name: "demo"}, object("ImageStream", "", "")); err == nil {
		t.Error("emptied stream still exists")
	}
}

func TestRemoveTagsMissingStream(t *testing.T) {
	if err := RemoveTags(t.Context(), newClient(), "ns", "gone", "alice", []string{"disk"}); err != nil {
		t.Fatalf("RemoveTags() on a missing stream = %v, want nil", err)
	}
}

func TestNameFromRef(t *testing.T) {
	prefix := tasks.DefaultInternalRegistryURL + "/"
	for _, tc := range []struct{ name, ref, want string }{
		{name: "tag", ref: prefix + "test-ns/resealed:v1", want: "resealed"},
		{name: "digest", ref: prefix + "test-ns/resealed@sha256:" + strings.Repeat("a", 64), want: "resealed"},
		{name: "no tag", ref: prefix + "test-ns/resealed", want: "resealed"},
		{name: "other namespace", ref: prefix + "other-ns/resealed:v1"},
		{name: "external registry", ref: "quay.io/test-ns/resealed:v1"},
		{name: "nested path", ref: prefix + "test-ns/a/b:v1"},
		{name: "empty", ref: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NameFromRef(tc.ref, "test-ns"); got != tc.want {
				t.Fatalf("NameFromRef(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

func TestEnsureOwned(t *testing.T) {
	// published is a stream that holds a pushed image, owned by the given jobs.
	published := func(owner string, owners ...metav1.OwnerReference) *unstructured.Unstructured {
		stream := transientStream(owner, owners...)
		stream.Object["status"] = map[string]any{"tags": []any{map[string]any{"tag": "v1"}}}
		return stream
	}
	for _, tc := range []struct {
		name        string
		stream      *unstructured.Unstructured // nil: no stream yet
		requestedBy string
		job         string
		wantErr     bool
		wantOwners  []string
	}{
		{name: "creates stream with owner", requestedBy: "alice", job: "job-1", wantOwners: []string{"job-1"}},
		{name: "adds owner to existing stream", stream: transientStream("alice", resealOwner("job-1")), requestedBy: "alice", job: "job-2", wantOwners: []string{"job-1", "job-2"}},
		// A stream recreated for another owner after the caller's ownership check
		// is not adopted.
		{name: "rejects another owner's stream", stream: transientStream("bob", resealOwner("job-1")), requestedBy: "alice", job: "job-2", wantErr: true, wantOwners: []string{"job-1"}},
		// Reusing a published stream that no job owns must not take ownership of
		// it: owning it would let deleting this job garbage-collect an image that
		// is not its to remove.
		{name: "skips unowned published stream", stream: published("alice"), requestedBy: "alice", job: "job-1"},
		// A retry reusing a published stream that completed jobs already own must
		// become an owner too, so deleting those jobs cannot garbage-collect the
		// stream while the retry still runs.
		{name: "adopts published stream with owners", stream: published("alice", resealOwner("job-1")), requestedBy: "alice", job: "job-2", wantOwners: []string{"job-1", "job-2"}},
		// A stream the operator does not manage is reused without taking
		// ownership: deleting the job must not garbage-collect it.
		{name: "skips non-transient stream", stream: unmanagedStream("alice"), requestedBy: "alice", job: "job-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var objs []client.Object
			if tc.stream != nil {
				objs = append(objs, tc.stream)
			}
			c := newClient(objs...)
			err := EnsureOwned(t.Context(), c, "ns", "demo", tc.requestedBy, resealOwner(tc.job))
			if gotErr := errors.Is(err, ErrNotOwned); gotErr != tc.wantErr {
				t.Fatalf("EnsureOwned() err = %v, want ErrNotOwned: %t", err, tc.wantErr)
			}
			if err != nil && !tc.wantErr {
				t.Fatal(err)
			}
			if owners := ownerNames(getStreamForTest(t, c)); !slices.Equal(owners, tc.wantOwners) {
				t.Errorf("owners = %v, want %v", owners, tc.wantOwners)
			}
		})
	}
}

// A concurrent cleanup can delete the stream between the AlreadyExists result
// and the claim. EnsureOwned must then create it again rather than failing the
// request.
func TestEnsureOwnedRecreatesStreamDeletedDuringClaim(t *testing.T) {
	gets := 0
	c := fake.NewClientBuilder().
		WithScheme(runtime.NewScheme()).
		WithObjects(transientStream("alice")).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*unstructured.Unstructured); ok {
					gets++
					if gets == 1 { // addOwnerRef's read
						_ = c.Delete(ctx, obj)
					}
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	if err := EnsureOwned(t.Context(), c, "ns", "demo", "alice", resealOwner("job-1")); err != nil {
		t.Fatalf("EnsureOwned() err = %v, want the stream recreated", err)
	}
	if owners := ownerNames(getStreamForTest(t, c)); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want [job-1]", owners)
	}
}

func getStreamForTest(t *testing.T, c client.Client) *unstructured.Unstructured {
	t.Helper()
	stream, err := get(t.Context(), c, "ns", "demo")
	if err != nil || stream == nil {
		t.Fatalf("stream = %v, err = %v", stream, err)
	}
	return stream
}

func TestReleaseOwnerAndDeleteIfUnused(t *testing.T) {
	published := transientStream("alice", resealOwner("job-1"))
	published.Object["status"] = map[string]any{
		"tags": []any{map[string]any{"tag": "v1"}},
	}
	for _, tc := range []struct {
		name       string
		stream     *unstructured.Unstructured
		owner      types.UID
		wantDelete bool
		wantOwners []string
	}{
		{name: "sole owner, empty", stream: transientStream("alice", resealOwner("job-1")), owner: "job-1", wantDelete: true},
		// Not this job's instance: it may be a replacement under the same name, or
		// a stream used by a job that never recorded ownership.
		{name: "no reference from this job", stream: transientStream("alice")},
		{name: "owned by another job only", stream: transientStream("alice", resealOwner("job-2")), wantOwners: []string{"job-2"}},
		{name: "another owner present", stream: transientStream("alice", resealOwner("job-1"), resealOwner("job-2")), owner: "job-1", wantOwners: []string{"job-2"}},
		{name: "published kept with owner", stream: published, owner: "job-1", wantOwners: []string{"job-1"}},
		{name: "not transient", stream: unmanagedStream("alice", resealOwner("job-1")), owner: "job-1", wantOwners: []string{"job-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(tc.stream)
			if err := ReleaseOwnerAndDeleteIfUnused(t.Context(), c, "ns", "demo", tc.owner); err != nil {
				t.Fatal(err)
			}
			stream, err := get(t.Context(), c, "ns", "demo")
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantDelete {
				if stream != nil {
					t.Fatal("stream was not deleted")
				}
				return
			}
			if owners := ownerNames(stream); len(owners) != len(tc.wantOwners) {
				t.Fatalf("owners = %v, want %v", owners, tc.wantOwners)
			}
		})
	}
}

func TestReleaseOwnerAndDeleteIfUnusedMissingStream(t *testing.T) {
	if err := ReleaseOwnerAndDeleteIfUnused(t.Context(), newClient(), "ns", "gone", "job-1"); err != nil {
		t.Fatalf("ReleaseOwnerAndDeleteIfUnused() on a missing stream err = %v, want nil", err)
	}
}

// A push landing after the check must make the delete fail rather than discard
// the stream it lands in.
func TestReleaseOwnerAndDeleteIfUnusedKeepsStreamChangedAfterCheck(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(runtime.NewScheme()).
		WithObjects(transientStream("alice", resealOwner("job-1"))).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				current, err := get(ctx, c, "ns", "demo")
				if err != nil || current == nil {
					return err
				}
				current.SetOwnerReferences([]metav1.OwnerReference{resealOwner("job-1"), resealOwner("job-2")})
				if err := c.Update(ctx, current); err != nil {
					return err
				}
				return c.Delete(ctx, obj, opts...)
			},
		}).
		Build()
	if err := ReleaseOwnerAndDeleteIfUnused(t.Context(), c, "ns", "demo", "job-1"); err != nil {
		t.Fatalf("ReleaseOwnerAndDeleteIfUnused() err = %v, want nil after a concurrent owner", err)
	}
	// get returns (nil, nil) for a missing stream, so check the stream itself:
	// the concurrent owner must have kept it alive.
	stream, err := get(t.Context(), c, "ns", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if stream == nil {
		t.Fatal("stream was deleted despite the concurrent owner")
	}
	if owners := ownerNames(stream); len(owners) != 1 || owners[0] != "job-2" {
		t.Errorf("owners = %v, want only the concurrent job-2", owners)
	}
}
