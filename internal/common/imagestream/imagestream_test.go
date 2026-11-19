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

func TestEnsureOwnedCreatesStreamWithOwner(t *testing.T) {
	c := newClient()
	created, err := EnsureOwned(t.Context(), c, "ns", "demo", "alice", resealOwner("job-1"))
	if err != nil || !created {
		t.Fatalf("EnsureOwned() = %t, %v; want created", created, err)
	}
	stream, err := get(t.Context(), c, "ns", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if owners := ownerNames(stream); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want [job-1]", owners)
	}
}

func TestEnsureOwnedAddsOwnerToExistingStream(t *testing.T) {
	c := newClient(transientStream("alice", resealOwner("job-1")))
	if created, err := EnsureOwned(t.Context(), c, "ns", "demo", "alice", resealOwner("job-2")); err != nil || created {
		t.Fatalf("EnsureOwned() = %t, %v; want existing", created, err)
	}
	stream, err := get(t.Context(), c, "ns", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if owners := ownerNames(stream); len(owners) != 2 {
		t.Errorf("owners = %v, want job-1 and job-2", owners)
	}
}

func TestEnsureOwnedRejectsAnotherOwnersStream(t *testing.T) {
	c := newClient(transientStream("bob", resealOwner("job-1")))
	_, err := EnsureOwned(t.Context(), c, "ns", "demo", "alice", resealOwner("job-2"))
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("EnsureOwned() err = %v, want ErrNotOwned", err)
	}
	stream, err := get(t.Context(), c, "ns", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if owners := ownerNames(stream); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want only the existing job-1", owners)
	}
}

// AddOwnerRef rechecks ownership on its own read, so a stream recreated for
// another owner after the caller's ownership check is not adopted.
func TestAddOwnerRefRejectsAnotherOwnersStream(t *testing.T) {
	c := newClient(transientStream("bob"))
	if err := AddOwnerRef(t.Context(), c, "ns", "demo", "alice", resealOwner("job-1")); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("AddOwnerRef() err = %v, want ErrNotOwned", err)
	}
	stream, err := get(t.Context(), c, "ns", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if owners := ownerNames(stream); len(owners) != 0 {
		t.Errorf("owners = %v, want none on another owner's stream", owners)
	}
}

// A stream that has vanished cannot be adopted: the caller must not accept a job
// with no stream to push to.
func TestAddOwnerRefMissingStream(t *testing.T) {
	if err := AddOwnerRef(t.Context(), newClient(), "ns", "gone", "alice", resealOwner("job-1")); err == nil {
		t.Fatal("AddOwnerRef() on a missing stream = nil, want an error")
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
					if gets == 2 { // AddOwnerRef's read, after CheckOwner's
						_ = c.Delete(ctx, obj)
					}
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	created, err := EnsureOwned(t.Context(), c, "ns", "demo", "alice", resealOwner("job-1"))
	if err != nil || !created {
		t.Fatalf("EnsureOwned() = %t, %v; want the stream recreated", created, err)
	}
	if owners := ownerNames(getStreamForTest(t, c)); len(owners) != 1 || owners[0] != "job-1" {
		t.Errorf("owners = %v, want [job-1]", owners)
	}
}

// Reusing a published stream that no job owns must not take ownership of it:
// owning it would let deleting this job garbage-collect an image that is not
// its to remove.
func TestAddOwnerRefSkipsUnownedPublishedStream(t *testing.T) {
	published := transientStream("alice")
	published.Object["status"] = map[string]any{"tags": []any{map[string]any{"tag": "v1"}}}
	c := newClient(published)
	if err := AddOwnerRef(t.Context(), c, "ns", "demo", "alice", resealOwner("job-1")); err != nil {
		t.Fatal(err)
	}
	if owners := ownerNames(getStreamForTest(t, c)); len(owners) != 0 {
		t.Errorf("owners = %v, want none added to an unowned published stream", owners)
	}
}

// A retry reusing a published stream that completed jobs already own must become
// an owner too, so deleting those jobs cannot garbage-collect the stream while
// the retry still runs.
func TestAddOwnerRefAdoptsPublishedStreamWithOwners(t *testing.T) {
	published := transientStream("alice", resealOwner("job-1"))
	published.Object["status"] = map[string]any{"tags": []any{map[string]any{"tag": "v1"}}}
	c := newClient(published)
	if err := AddOwnerRef(t.Context(), c, "ns", "demo", "alice", resealOwner("job-2")); err != nil {
		t.Fatal(err)
	}
	owners := ownerNames(getStreamForTest(t, c))
	if len(owners) != 2 || !slices.Contains(owners, "job-1") || !slices.Contains(owners, "job-2") {
		t.Errorf("owners = %v, want both jobs", owners)
	}
}

// A stream the operator does not manage is reused without taking ownership:
// deleting the job must not garbage-collect it.
func TestAddOwnerRefSkipsNonTransientStream(t *testing.T) {
	c := newClient(streamOwnedBy("alice"))
	if err := AddOwnerRef(t.Context(), c, "ns", "demo", "alice", resealOwner("job-1")); err != nil {
		t.Fatal(err)
	}
	if owners := ownerNames(getStreamForTest(t, c)); len(owners) != 0 {
		t.Errorf("owners = %v, want none added to a non-transient stream", owners)
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
		inUse      bool
		wantDelete bool
		wantOwners []string
	}{
		{name: "sole owner, empty", stream: transientStream("alice", resealOwner("job-1")), owner: "job-1", wantDelete: true},
		// Not this job's instance: it may be a replacement under the same name, or
		// a stream used by a job that never recorded ownership.
		{name: "no reference from this job", stream: transientStream("alice")},
		{name: "owned by another job only", stream: transientStream("alice", resealOwner("job-2")), wantOwners: []string{"job-2"}},
		{name: "another owner present", stream: transientStream("alice", resealOwner("job-1"), resealOwner("job-2")), owner: "job-1", wantOwners: []string{"job-2"}},
		// A job without an owner reference still targets the stream: release ours,
		// keep the stream for it.
		{name: "in use by unreferenced job", stream: transientStream("alice", resealOwner("job-1")), owner: "job-1", inUse: true},
		{name: "published kept with owner", stream: published, owner: "job-1", wantOwners: []string{"job-1"}},
		{name: "not transient", stream: streamOwnedBy("alice"), owner: "job-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(tc.stream)
			deleted, err := ReleaseOwnerAndDeleteIfUnused(t.Context(), c, "ns", "demo", tc.owner, tc.inUse)
			if err != nil {
				t.Fatal(err)
			}
			if deleted != tc.wantDelete {
				t.Fatalf("ReleaseOwnerAndDeleteIfUnused() = %t, want %t", deleted, tc.wantDelete)
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
	deleted, err := ReleaseOwnerAndDeleteIfUnused(t.Context(), newClient(), "ns", "gone", "job-1", false)
	if err != nil || deleted {
		t.Fatalf("ReleaseOwnerAndDeleteIfUnused() on a missing stream = %t, %v; want false, nil", deleted, err)
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
	deleted, err := ReleaseOwnerAndDeleteIfUnused(t.Context(), c, "ns", "demo", "job-1", false)
	if err != nil || deleted {
		t.Fatalf("ReleaseOwnerAndDeleteIfUnused() = %t, %v; want false, nil after a concurrent owner", deleted, err)
	}
	if _, err := get(t.Context(), c, "ns", "demo"); err != nil {
		t.Fatal(err)
	}
}
