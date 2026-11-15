package imagebuild

import (
	"context"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Several builds can push to one ImageStream (caib --image-name), so an
// expired build removes only its own tags, and only from a stream its
// requester owns.
func TestHandleExpiredState_RemovesOnlyOwnTags(t *testing.T) {
	for _, tc := range []struct {
		streamOwner string
		wantDeleted bool
	}{
		{streamOwner: "alice", wantDeleted: true},
		{streamOwner: "bob"},
	} {
		t.Run(tc.streamOwner, func(t *testing.T) {
			ib := newTestImageBuild("demo", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
			ib.Annotations = map[string]string{labels.RequestedBy: "alice"}
			ib.Spec.Export = &automotivev1alpha1.ExportSpec{
				UseServiceAccountAuth: true,
				Disk:                  &automotivev1alpha1.DiskExport{OCI: tasks.DefaultInternalRegistryURL + "/test-ns/shared:disk"},
			}
			r := newExpiryReconciler(ib)
			ctx := context.Background()

			stream := imageStreamObject("ImageStream", "shared")
			stream.SetAnnotations(map[string]string{labels.RequestedBy: tc.streamOwner})
			// Another build's tag keeps the stream in use.
			tags := []any{map[string]any{"tag": "disk"}, map[string]any{"tag": "other"}}
			if err := unstructured.SetNestedSlice(stream.Object, tags, "status", "tags"); err != nil {
				t.Fatal(err)
			}
			for _, obj := range []*unstructured.Unstructured{
				stream, imageStreamObject("ImageStreamTag", "shared:disk"), imageStreamObject("ImageStreamTag", "shared:other"),
			} {
				if err := r.Create(ctx, obj); err != nil {
					t.Fatal(err)
				}
			}

			r.handleExpiredState(ctx, &ib) //nolint:errcheck

			key := func(name string) types.NamespacedName { return types.NamespacedName{Namespace: "test-ns", Name: name} }
			if err := r.Get(ctx, key("shared"), imageStreamObject("ImageStream", "")); err != nil {
				t.Fatalf("stream another build still uses was deleted: %v", err)
			}
			if err := r.Get(ctx, key("shared:other"), imageStreamObject("ImageStreamTag", "")); err != nil {
				t.Fatalf("another build's tag was deleted: %v", err)
			}
			err := r.Get(ctx, key("shared:disk"), imageStreamObject("ImageStreamTag", ""))
			if deleted := errors.IsNotFound(err); deleted != tc.wantDeleted {
				t.Fatalf("own tag deleted=%t (err=%v), want %t", deleted, err, tc.wantDeleted)
			}
		})
	}
}

func imageStreamObject(kind, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: kind})
	obj.SetName(name)
	obj.SetNamespace("test-ns")
	return obj
}
