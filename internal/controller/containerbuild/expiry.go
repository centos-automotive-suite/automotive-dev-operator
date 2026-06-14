package containerbuild

import (
	"context"
	"fmt"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	shipwrightv1beta1 "github.com/shipwright-io/build/pkg/apis/build/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *ContainerBuildReconciler) checkExpiry(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, bool, error) {
	log := r.Log.WithValues("containerbuild", cb.Name, "namespace", cb.Namespace)

	if cb.Status.Phase == phaseExpired {
		return ctrl.Result{}, false, nil
	}

	if cb.Status.CompletionTime == nil {
		return ctrl.Result{}, false, nil
	}

	if cb.Annotations[automotivev1alpha1.NoExpireAnnotation] == "true" {
		if err := r.updateExpiresAt(ctx, cb, nil); err != nil {
			return ctrl.Result{}, false, err
		}
		return ctrl.Result{}, false, nil
	}

	ttl, err := r.resolveEffectiveTTL(ctx, cb)
	if err != nil {
		log.Error(err, "Failed to resolve TTL, skipping expiry check")
		r.emitEventf(cb, corev1.EventTypeWarning, "InvalidTTL",
			"Failed to resolve TTL, expiry disabled for this build: %v", err)
		if clearErr := r.updateExpiresAt(ctx, cb, nil); clearErr != nil {
			return ctrl.Result{}, false, clearErr
		}
		return ctrl.Result{}, false, nil
	}
	if ttl == 0 {
		if err := r.updateExpiresAt(ctx, cb, nil); err != nil {
			return ctrl.Result{}, false, err
		}
		return ctrl.Result{}, false, nil
	}
	anchor := cb.Status.CompletionTime.Time

	expiresAt := anchor.Add(ttl)
	remaining := time.Until(expiresAt)

	if err := r.updateExpiresAt(ctx, cb, &expiresAt); err != nil {
		return ctrl.Result{}, false, err
	}

	if remaining > 0 {
		log.Info("Build not yet expired", "expiresAt", expiresAt, "remaining", remaining.Truncate(time.Second))
		return ctrl.Result{RequeueAfter: remaining}, false, nil
	}

	log.Info("Build expired, transitioning to Expired phase", "ttl", ttl, "anchor", anchor,
		"previousPhase", cb.Status.Phase)
	r.emitEventf(cb, corev1.EventTypeNormal, "BuildExpired",
		"Build expired after %s, cleaning up resources", ttl)

	if _, err := r.updatePhase(ctx, cb, phaseExpired, cb.Status.BuildRunName,
		fmt.Sprintf("Build expired after %s", ttl)); err != nil {
		return ctrl.Result{}, false, fmt.Errorf("failed to transition expired build: %w", err)
	}
	return ctrl.Result{}, true, nil
}

func (r *ContainerBuildReconciler) resolveEffectiveTTL(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (time.Duration, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{
		Name: "config", Namespace: controllerutils.OperatorNamespace(),
	}, operatorConfig); err != nil && !errors.IsNotFound(err) {
		return 0, fmt.Errorf("failed to load OperatorConfig: %w", err)
	}
	return controllerutils.ResolveBuildTTL(cb.Spec.GetTTL(), operatorConfig.Spec.ContainerBuilds)
}

func (r *ContainerBuildReconciler) updateExpiresAt(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
	expiresAt *time.Time,
) error {
	desired, needsUpdate := controllerutils.ComputeExpiresAt(cb.Status.ExpiresAt, expiresAt)
	if !needsUpdate {
		return nil
	}
	fresh := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(ctx, types.NamespacedName{
		Name: cb.Name, Namespace: cb.Namespace,
	}, fresh); err != nil {
		return err
	}
	fresh.Status.ExpiresAt = desired
	return r.Status().Update(ctx, fresh)
}

func (r *ContainerBuildReconciler) handleExpiredState(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", cb.Name, "namespace", cb.Namespace)

	if name := cb.Status.BuildRunName; name != "" {
		br := &shipwrightv1beta1.BuildRun{}
		br.Name = name
		br.Namespace = cb.Namespace
		if err := r.Delete(ctx, br); err != nil {
			if !errors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("failed to delete BuildRun %s: %w", name, err)
			}
		} else {
			log.Info("Deleted BuildRun", "name", name)
		}
	}

	return ctrl.Result{}, nil
}
