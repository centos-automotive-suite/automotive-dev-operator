// Package imagestream manages the OpenShift ImageStreams that builds push to
// in the internal registry. Requests name the stream, so each stream records
// the user it was created for, and only that user's requests may push to it or
// delete its tags.
package imagestream

import (
	"context"
	"errors"
	"fmt"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrNotOwned reports an ImageStream that was not created for the caller.
var ErrNotOwned = errors.New("ImageStream belongs to another user")

func object(kind, namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: kind})
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

// Ensure creates the named stream for owner, or confirms that an existing one
// is theirs. It reports whether it created the stream. Without the ImageStream
// API (not OpenShift) there is nothing to create.
func Ensure(ctx context.Context, c client.Client, namespace, name, owner string) (bool, error) {
	stream := object("ImageStream", namespace, name)
	stream.SetLabels(map[string]string{
		labels.ManagedBy: labels.ValueBuildAPI,
		labels.PartOf:    labels.ValueAutomotiveDev,
		labels.Transient: labels.ValueTrue,
	})
	stream.SetAnnotations(map[string]string{labels.RequestedBy: owner})
	err := c.Create(ctx, stream)
	switch {
	case err == nil:
		return true, nil
	case apimeta.IsNoMatchError(err):
		return false, nil
	case k8serrors.IsAlreadyExists(err):
		return false, CheckOwner(ctx, c, namespace, name, owner)
	}
	return false, fmt.Errorf("error creating ImageStream %s: %w", name, err)
}

// get returns the named stream, or nil if there is none.
func get(ctx context.Context, c client.Client, namespace, name string) (*unstructured.Unstructured, error) {
	stream := object("ImageStream", namespace, name)
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, stream); err != nil {
		if k8serrors.IsNotFound(err) || apimeta.IsNoMatchError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("error checking ImageStream %s: %w", name, err)
	}
	return stream, nil
}

func checkOwned(stream *unstructured.Unstructured, owner string) error {
	if stream.GetAnnotations()[labels.RequestedBy] != owner {
		return fmt.Errorf("%w: %s", ErrNotOwned, stream.GetName())
	}
	return nil
}

// CheckOwner returns ErrNotOwned if the named stream exists and was not
// created for owner. A missing stream is free for owner to create.
func CheckOwner(ctx context.Context, c client.Client, namespace, name, owner string) error {
	stream, err := get(ctx, c, namespace, name)
	if err != nil || stream == nil {
		return err
	}
	return checkOwned(stream, owner)
}

// RemoveTags deletes tags from the named stream, then the stream itself once
// no tags remain; other builds may still use the rest. It returns ErrNotOwned,
// and deletes nothing, if the stream was not created for owner: the stream a
// build pushed to may since have been deleted and recreated by someone else.
func RemoveTags(ctx context.Context, c client.Client, namespace, name, owner string, tags []string) error {
	stream, err := get(ctx, c, namespace, name)
	if err != nil || stream == nil {
		return err
	}
	if err := checkOwned(stream, owner); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := c.Delete(ctx, object("ImageStreamTag", namespace, name+":"+tag)); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("error deleting ImageStreamTag %s:%s: %w", name, tag, err)
		}
	}

	current, err := get(ctx, c, namespace, name)
	if err != nil || current == nil {
		return err
	}
	if remaining, _, _ := unstructured.NestedSlice(current.Object, "status", "tags"); len(remaining) > 0 {
		return nil
	}
	// Only delete the stream whose owner was checked, not one recreated since.
	uid := stream.GetUID()
	if err := c.Delete(ctx, current, client.Preconditions{UID: &uid}); err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("error deleting ImageStream %s: %w", name, err)
	}
	return nil
}
