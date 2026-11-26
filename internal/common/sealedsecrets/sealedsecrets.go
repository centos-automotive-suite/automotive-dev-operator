// Package sealedsecrets defines the transient Secrets the build API creates for
// sealed-image (ImageReseal) requests and removes the ones left behind when
// their ImageReseal no longer exists.
package sealedsecrets

import (
	"context"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Suffixes of the transient Secrets the build API creates for a sealed
// request. The Secret name is the ImageReseal name plus one of these, so the
// sweep can tell them apart from any other labelled Secret in the namespace.
const (
	RegistryAuthSuffix    = "-registry-auth"
	SealKeySuffix         = "-seal-key"
	SealKeyPasswordSuffix = "-seal-key-password"
)

var transientSuffixes = []string{RegistryAuthSuffix, SealKeySuffix, SealKeyPasswordSuffix}

// ImageResealName reports the ImageReseal a Secret belongs to, and whether the
// Secret is one the build API created for a sealed request. User-provided
// Secrets and transient Secrets of other resource types are not reported.
func ImageResealName(secret *corev1.Secret) (string, bool) {
	if secret.Labels[labels.Transient] != labels.ValueTrue {
		return "", false
	}
	job := secret.Labels[labels.ImageReseal]
	if job == "" {
		return "", false
	}
	for _, suffix := range transientSuffixes {
		if secret.Name == job+suffix {
			return job, true
		}
	}
	return "", false
}

// SweepOrphaned deletes transient Secrets created for sealed requests whose
// ImageReseal no longer exists. The API creates a job's Secrets owned by it,
// so garbage collection normally removes them with the job; this sweep covers
// the ones it cannot reach — left behind before Secrets were born owned, or by
// any failure that strips the owner.
//
// Secrets are left alone while their ImageReseal exists, including while the
// job is still running: the controller cleans them up when the job finishes.
// User-provided Secrets carry none of the sealed-secret labels and are never
// considered. Deletion is pinned to the listed Secret's UID, so a name reused
// by a new request between the list and the delete is not removed.
//
// It returns the number of Secrets deleted and the first error encountered, so
// callers can retry the ones that failed.
func SweepOrphaned(ctx context.Context, c client.Client, logger logr.Logger) (int, error) {
	secrets := &corev1.SecretList{}
	if err := c.List(ctx, secrets, client.MatchingLabels{labels.Transient: labels.ValueTrue}); err != nil {
		return 0, fmt.Errorf("list transient Secrets: %w", err)
	}

	deleted := 0
	var firstErr error
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		job, ok := ImageResealName(secret)
		if !ok {
			continue
		}

		reseal := &automotivev1alpha1.ImageReseal{}
		err := c.Get(ctx, client.ObjectKey{Namespace: secret.Namespace, Name: job}, reseal)
		switch {
		case err == nil:
			// The job still exists and owns (or will clean up) its Secrets.
			continue
		case !k8serrors.IsNotFound(err):
			logger.Error(err, "Failed to check ImageReseal for transient Secret", "secret", secret.Name, "job", job)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		// Pin the delete to the Secret we listed. If another cleanup removed it
		// and a new request reused the name, the API server reports a conflict
		// and the replacement is left for the next sweep to evaluate.
		err = c.Delete(ctx, secret, client.Preconditions{UID: &secret.UID})
		switch {
		case err == nil:
		case k8serrors.IsNotFound(err):
			// Already gone; nothing left to remove.
		case k8serrors.IsConflict(err):
			logger.V(1).Info("Transient Secret was replaced during the sweep; leaving it", "secret", secret.Name, "job", job)
			continue
		default:
			logger.Error(err, "Failed to delete orphaned transient Secret; will retry", "secret", secret.Name, "job", job)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		deleted++
		logger.Info("Deleted orphaned transient Secret", "secret", secret.Name, "job", job)
	}
	return deleted, firstErr
}
