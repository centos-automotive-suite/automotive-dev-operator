// Package imagestream manages the OpenShift ImageStreams that builds push to
// in the internal registry. Requests name the stream, so each stream records
// the user it was created for, and only that user's requests may push to it or
// delete its tags.
package imagestream

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrNotOwned reports an ImageStream that was not created for the caller.
var ErrNotOwned = errors.New("ImageStream belongs to another user")

// NameFromRef returns the ImageStream that ref pushes to when it names
// namespace in the internal registry, and "" for any other ref.
func NameFromRef(ref, namespace string) string {
	path, ok := strings.CutPrefix(ref, tasks.DefaultInternalRegistryURL+"/"+namespace+"/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(path, "@")
	name, _, _ = strings.Cut(name, ":")
	if name == "" || strings.Contains(name, "/") {
		return ""
	}
	return name
}

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

// EnsureOwned creates the named stream for requestedBy with owner among its
// owner references, or confirms an existing one is theirs and adds owner to its
// references. Several jobs can own one stream; Kubernetes garbage-collects it
// once the last owner is deleted, so a deleted job needs no explicit release.
// It reports whether it created the stream. Without the ImageStream API (not
// OpenShift) there is nothing to create.
func EnsureOwned(ctx context.Context, c client.Client, namespace, name, requestedBy string, owner metav1.OwnerReference) (bool, error) {
	// Claiming an existing stream can lose it to a concurrent cleanup between the
	// AlreadyExists check and the claim. When that happens the stream is gone, so
	// try to create it again rather than failing the request.
	for range 3 {
		stream := object("ImageStream", namespace, name)
		stream.SetLabels(map[string]string{
			labels.ManagedBy: labels.ValueBuildAPI,
			labels.PartOf:    labels.ValueAutomotiveDev,
			labels.Transient: labels.ValueTrue,
		})
		stream.SetAnnotations(map[string]string{labels.RequestedBy: requestedBy})
		stream.SetOwnerReferences([]metav1.OwnerReference{owner})
		err := c.Create(ctx, stream)
		switch {
		case err == nil:
			return true, nil
		case apimeta.IsNoMatchError(err):
			return false, nil
		case k8serrors.IsAlreadyExists(err):
			if err := CheckOwner(ctx, c, namespace, name, requestedBy); err != nil {
				return false, err
			}
			err := AddOwnerRef(ctx, c, namespace, name, requestedBy, owner)
			if k8serrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
			return false, nil
		default:
			return false, fmt.Errorf("error creating ImageStream %s: %w", name, err)
		}
	}
	return false, fmt.Errorf("error creating ImageStream %s: it kept disappearing while claiming it", name)
}

// AddOwnerRef adds owner to the named stream's owner references. Streams can
// have several owners, so conflicting updates are retried. It re-reads the
// stream on each attempt and rechecks that it still belongs to requestedBy, so
// a stream deleted and recreated for someone else between the caller's ownership
// check and this write is not adopted.
//
// It does not take ownership of a stream the operator does not manage (no
// transient label), nor of a published stream that has no owners yet: adopting
// either would let deleting this job garbage-collect data that was never its to
// remove. A published stream that other jobs already own is adopted, so a retry
// running against it keeps the stream alive when those jobs are deleted. A
// stream that has gone missing is an error: the caller must not accept a job
// with no stream to push to.
func AddOwnerRef(ctx context.Context, c client.Client, namespace, name, requestedBy string, owner metav1.OwnerReference) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		stream, err := get(ctx, c, namespace, name)
		if err != nil {
			return err
		}
		if stream == nil {
			return k8serrors.NewNotFound(schema.GroupResource{Group: "image.openshift.io", Resource: "imagestreams"}, name)
		}
		if err := checkOwned(stream, requestedBy); err != nil {
			return err
		}
		if stream.GetLabels()[labels.Transient] != labels.ValueTrue {
			return nil
		}
		refs := stream.GetOwnerReferences()
		if hasPublishedTags(stream) && len(refs) == 0 {
			return nil
		}
		if containsOwnerRef(refs, owner.UID) {
			return nil
		}
		stream.SetOwnerReferences(append(refs, owner))
		return c.Update(ctx, stream)
	})
	if err != nil {
		return fmt.Errorf("error adding owner to ImageStream %s: %w", name, err)
	}
	return nil
}

// ReleaseOwnerAndDeleteIfUnused drops owner from the named stream and, if that
// leaves it with no owners and nothing published, deletes it. It reports whether
// it deleted the stream. It acts only on a stream that still carries owner in
// its owner references: a stream without it is not the instance this job owned
// (it may have been replaced under the same name), so nothing is touched. That
// also keeps the operator from deleting a stream used by a job that never
// recorded ownership. A stream holding published tags is left untouched, owner
// reference included, so the image is preserved and the stream is garbage-
// collected only when its owning jobs are deleted. A stream another job still
// owns, or one inUse reports another job still targets, is kept, with just
// owner's reference removed: inUse covers a job that pushes to the stream without
// an owner reference, e.g. one applied before the controller recorded ownership.
// Only transient streams the API creates are deleted. The owner-reference update
// and the delete carry the stream's resource version, so a push or a new owner
// landing in between fails with a conflict and is retried against the stream's
// current state.
func ReleaseOwnerAndDeleteIfUnused(ctx context.Context, c client.Client, namespace, name string, owner types.UID, inUse bool) (bool, error) {
	deleted := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		deleted = false
		stream, err := get(ctx, c, namespace, name)
		if err != nil || stream == nil {
			return err
		}
		if !containsOwnerRef(stream.GetOwnerReferences(), owner) {
			return nil
		}
		if stream.GetLabels()[labels.Transient] != labels.ValueTrue || hasPublishedTags(stream) {
			return nil
		}
		if inUse || ownedByOther(stream, owner) {
			return removeOwnerRef(ctx, c, stream, owner)
		}
		uid, resourceVersion := stream.GetUID(), stream.GetResourceVersion()
		delErr := c.Delete(ctx, stream, client.Preconditions{UID: &uid, ResourceVersion: &resourceVersion})
		if delErr == nil {
			deleted = true
			return nil
		}
		if k8serrors.IsNotFound(delErr) {
			// Already gone; nothing left to delete.
			return nil
		}
		// A conflict falls through to RetryOnConflict, which re-runs the closure
		// against the stream's current state.
		return delErr
	})
	if err != nil {
		return false, fmt.Errorf("error releasing ImageStream %s: %w", name, err)
	}
	return deleted, nil
}

// removeOwnerRef drops owner from the stream's references and persists it.
func removeOwnerRef(ctx context.Context, c client.Client, stream *unstructured.Unstructured, owner types.UID) error {
	refs := stream.GetOwnerReferences()
	kept := make([]metav1.OwnerReference, 0, len(refs))
	for _, ref := range refs {
		if ref.UID != owner {
			kept = append(kept, ref)
		}
	}
	if len(kept) == len(refs) {
		return nil
	}
	stream.SetOwnerReferences(kept)
	return c.Update(ctx, stream)
}

func hasPublishedTags(stream *unstructured.Unstructured) bool {
	tags, _, _ := unstructured.NestedSlice(stream.Object, "status", "tags")
	return len(tags) > 0
}

func containsOwnerRef(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, ref := range refs {
		if ref.UID == uid {
			return true
		}
	}
	return false
}

// ownedByOther reports whether the stream has an owner reference other than
// disregard, i.e. a job besides the caller still owns it.
func ownedByOther(stream *unstructured.Unstructured, disregard types.UID) bool {
	for _, ref := range stream.GetOwnerReferences() {
		if ref.UID != disregard {
			return true
		}
	}
	return false
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
