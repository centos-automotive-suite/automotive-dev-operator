package imagestream

import (
	"errors"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func streamOwnedBy(name, owner string) *unstructured.Unstructured {
	stream := object("ImageStream", "ns", name)
	if owner != "" {
		stream.SetAnnotations(map[string]string{labels.RequestedBy: owner})
	}
	return stream
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
			created, err := Ensure(t.Context(), newClient(streamOwnedBy("demo", tc.owner)), "ns", "demo", "alice")
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
	c := newClient(streamOwnedBy("demo", "alice"), object("ImageStreamTag", "ns", "demo:disk"))
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
