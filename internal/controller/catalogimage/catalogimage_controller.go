/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package catalogimage

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

const (
	// Default requeue intervals
	defaultVerificationInterval = 1 * time.Hour
	retryInterval               = 30 * time.Second
	unavailableRetryInterval    = 5 * time.Minute
	maxVerificationFailures     = 5
)

// CatalogImageReconciler reconciles a CatalogImage object
//
//nolint:revive // Name follows Kubebuilder convention for reconcilers
type CatalogImageReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Log            logr.Logger
	RegistryClient RegistryClient
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=catalogimages,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=catalogimages/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=catalogimages/finalizers,verbs=update
// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",namespace=system,resources=events,verbs=create;patch

// Reconcile handles CatalogImage reconciliation
func (r *CatalogImageReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("catalogimage", req.NamespacedName)

	// Fetch the CatalogImage instance
	catalogImage := &automotivev1alpha1.CatalogImage{}
	if err := r.Get(ctx, req.NamespacedName, catalogImage); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !catalogImage.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, catalogImage)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(catalogImage, automotivev1alpha1.CatalogImageFinalizer) {
		controllerutil.AddFinalizer(catalogImage, automotivev1alpha1.CatalogImageFinalizer)
		if err := r.Update(ctx, catalogImage); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	log.Info("Reconciling CatalogImage", "phase", catalogImage.Status.Phase)

	// Handle reconciliation based on current phase
	switch catalogImage.Status.Phase {
	case "", automotivev1alpha1.CatalogImagePhasePending:
		return r.handlePendingPhase(ctx, catalogImage)
	case automotivev1alpha1.CatalogImagePhaseVerifying:
		return r.handleVerifyingPhase(ctx, catalogImage)
	case automotivev1alpha1.CatalogImagePhaseAvailable:
		return r.handleAvailablePhase(ctx, catalogImage)
	case automotivev1alpha1.CatalogImagePhaseUnavailable:
		return r.handleUnavailablePhase(ctx, catalogImage)
	case automotivev1alpha1.CatalogImagePhaseFailed:
		return r.handleFailedPhase(ctx, catalogImage)
	default:
		log.Info("Unknown phase", "phase", catalogImage.Status.Phase)
		return ctrl.Result{}, nil
	}
}

// handleDeletion handles CatalogImage deletion with finalizer cleanup
func (r *CatalogImageReconciler) handleDeletion(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
) (ctrl.Result, error) {
	log := r.Log.WithValues("catalogimage", catalogImage.Name, "namespace", catalogImage.Namespace)

	if controllerutil.ContainsFinalizer(catalogImage, automotivev1alpha1.CatalogImageFinalizer) {
		log.Info("Processing finalizer for CatalogImage")

		// Perform cleanup tasks here (e.g., cleanup cache entries)
		// For now, just remove the finalizer

		controllerutil.RemoveFinalizer(catalogImage, automotivev1alpha1.CatalogImageFinalizer)
		if err := r.Update(ctx, catalogImage); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// handlePendingPhase handles newly created CatalogImages
func (r *CatalogImageReconciler) handlePendingPhase(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
) (ctrl.Result, error) {
	log := r.Log.WithValues("catalogimage", catalogImage.Name, "namespace", catalogImage.Namespace)
	log.Info("Transitioning from Pending to Verifying")

	// Set labels for indexing if metadata is provided
	r.ensureLabels(catalogImage)

	// Update status to Verifying
	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseVerifying
	catalogImage.Status.ObservedGeneration = catalogImage.Generation

	if err := r.Status().Update(ctx, catalogImage); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

// handleVerifyingPhase handles registry verification
func (r *CatalogImageReconciler) handleVerifyingPhase(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
) (ctrl.Result, error) {
	log := r.Log.WithValues("catalogimage", catalogImage.Name, "namespace", catalogImage.Namespace)
	log.Info("Verifying registry accessibility", "registryUrl", catalogImage.Spec.RegistryURL)

	// Get authentication if configured
	auth, err := GetAuthFromSecret(ctx, r.Client, catalogImage.Spec.AuthSecretRef, catalogImage.Namespace)
	if err != nil {
		log.Error(err, "Failed to get authentication from secret")
		return r.transitionToFailed(ctx, catalogImage, "AuthenticationError", err.Error())
	}

	// Get registry client
	registryClient := r.getRegistryClient()

	// Verify image is accessible
	accessible, err := registryClient.VerifyImageAccessible(ctx, catalogImage.Spec.RegistryURL, auth)
	if err != nil {
		log.Error(err, "Failed to access registry")
		return r.transitionToUnavailable(ctx, catalogImage, "RegistryAccessFailed", err.Error())
	}

	if !accessible {
		return r.transitionToUnavailable(ctx, catalogImage, "ImageNotFound", "Image not found in registry")
	}

	// Extract metadata from registry
	metadata, err := registryClient.GetImageMetadata(ctx, catalogImage.Spec.RegistryURL, auth)
	if err != nil {
		log.Error(err, "Failed to get image metadata")
		// Still transition to Available if image is accessible but metadata extraction fails
		log.Info("Image accessible but metadata extraction failed, continuing")
	}

	// Update status with metadata and transition to Available
	catalogImage.Status.RegistryMetadata = metadata
	catalogImage.Status.LastVerificationTime = GetCurrentTime()
	catalogImage.Status.VerificationFailures = 0

	// Set Published timestamp if not already set
	if catalogImage.Status.PublishedAt == nil {
		catalogImage.Status.PublishedAt = GetCurrentTime()
	}

	// Update phase
	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseAvailable
	catalogImage.Status.ObservedGeneration = catalogImage.Generation

	// Set Available condition
	r.setCondition(
		catalogImage,
		automotivev1alpha1.CatalogImageConditionAvailable,
		metav1.ConditionTrue,
		"RegistryAccessible",
		"Image is accessible in registry",
	)
	r.setCondition(
		catalogImage,
		automotivev1alpha1.CatalogImageConditionVerified,
		metav1.ConditionTrue,
		"VerificationSucceeded",
		"Image verification completed successfully",
	)
	r.setCondition(
		catalogImage,
		automotivev1alpha1.CatalogImageConditionReady,
		metav1.ConditionTrue,
		"Ready",
		"CatalogImage is ready for use",
	)

	if err := r.Status().Update(ctx, catalogImage); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue for periodic verification
	return ctrl.Result{RequeueAfter: r.getVerificationInterval(catalogImage)}, nil
}

// handleAvailablePhase handles periodic re-verification
func (r *CatalogImageReconciler) handleAvailablePhase(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
) (ctrl.Result, error) {
	log := r.Log.WithValues("catalogimage", catalogImage.Name, "namespace", catalogImage.Namespace)

	// Check if spec changed (generation mismatch)
	if catalogImage.Status.ObservedGeneration != catalogImage.Generation {
		log.Info("Spec changed, re-verifying")
		catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseVerifying
		catalogImage.Status.ObservedGeneration = catalogImage.Generation

		if err := r.Status().Update(ctx, catalogImage); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Check if re-verification is needed based on interval
	verificationInterval := r.getVerificationInterval(catalogImage)
	if catalogImage.Status.LastVerificationTime != nil {
		elapsed := time.Since(catalogImage.Status.LastVerificationTime.Time)
		if elapsed < verificationInterval {
			// Not time for re-verification yet
			remaining := verificationInterval - elapsed
			return ctrl.Result{RequeueAfter: remaining}, nil
		}
	}

	// Time for re-verification, transition to Verifying
	log.Info("Periodic re-verification triggered")
	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseVerifying
	catalogImage.Status.ObservedGeneration = catalogImage.Generation
	if err := r.Status().Update(ctx, catalogImage); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: true}, nil
}

// handleUnavailablePhase handles retry logic
func (r *CatalogImageReconciler) handleUnavailablePhase(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
) (ctrl.Result, error) {
	log := r.Log.WithValues("catalogimage", catalogImage.Name, "namespace", catalogImage.Namespace)
	log.Info("Retrying unavailable image")

	// Transition back to Verifying to retry
	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseVerifying
	catalogImage.Status.ObservedGeneration = catalogImage.Generation

	if err := r.Status().Update(ctx, catalogImage); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

// handleFailedPhase handles permanent failures
func (r *CatalogImageReconciler) handleFailedPhase(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
) (ctrl.Result, error) {
	// Failed state requires user intervention
	// Check if user has updated the spec
	if catalogImage.Status.ObservedGeneration != catalogImage.Generation {
		r.Log.Info("Spec updated, transitioning from Failed to Verifying")
		catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseVerifying
		catalogImage.Status.ObservedGeneration = catalogImage.Generation

		if err := r.Status().Update(ctx, catalogImage); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{}, nil
}

// transitionToUnavailable transitions to Unavailable phase
func (r *CatalogImageReconciler) transitionToUnavailable(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
	reason, message string,
) (ctrl.Result, error) {
	r.setCondition(catalogImage, automotivev1alpha1.CatalogImageConditionAvailable, metav1.ConditionFalse, reason, message)
	r.setCondition(catalogImage, automotivev1alpha1.CatalogImageConditionReady, metav1.ConditionFalse, reason, message)

	catalogImage.Status.VerificationFailures++
	catalogImage.Status.ObservedGeneration = catalogImage.Generation

	if catalogImage.Status.VerificationFailures >= maxVerificationFailures {
		catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseFailed
		r.setCondition(catalogImage, automotivev1alpha1.CatalogImageConditionReady, metav1.ConditionFalse, reason,
			fmt.Sprintf("%s (gave up after %d attempts)", message, catalogImage.Status.VerificationFailures))
		if err := r.Status().Update(ctx, catalogImage); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseUnavailable
	if err := r.Status().Update(ctx, catalogImage); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: unavailableRetryInterval}, nil
}

// transitionToFailed transitions to Failed phase
func (r *CatalogImageReconciler) transitionToFailed(
	ctx context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
	reason, message string,
) (ctrl.Result, error) {
	r.setCondition(catalogImage, automotivev1alpha1.CatalogImageConditionAvailable, metav1.ConditionFalse, reason, message)
	r.setCondition(catalogImage, automotivev1alpha1.CatalogImageConditionReady, metav1.ConditionFalse, reason, message)

	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseFailed
	catalogImage.Status.ObservedGeneration = catalogImage.Generation

	if err := r.Status().Update(ctx, catalogImage); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// setCondition sets a condition on the CatalogImage status
func (r *CatalogImageReconciler) setCondition(
	catalogImage *automotivev1alpha1.CatalogImage,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&catalogImage.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: catalogImage.Generation,
	})
}

// ensureLabels ensures that labels are set based on metadata
func (r *CatalogImageReconciler) ensureLabels(catalogImage *automotivev1alpha1.CatalogImage) {
	if catalogImage.Labels == nil {
		catalogImage.Labels = make(map[string]string)
	}

	if catalogImage.Spec.Metadata != nil {
		if catalogImage.Spec.Metadata.Architecture != "" {
			normalizedArch := NormalizeArchitecture(catalogImage.Spec.Metadata.Architecture)
			catalogImage.Labels[automotivev1alpha1.LabelArchitecture] = normalizedArch
		}
		if catalogImage.Spec.Metadata.Distro != "" {
			catalogImage.Labels[automotivev1alpha1.LabelDistro] = catalogImage.Spec.Metadata.Distro
		}
		if len(catalogImage.Spec.Metadata.Targets) > 0 {
			catalogImage.Labels[automotivev1alpha1.LabelTarget] = catalogImage.Spec.Metadata.Targets[0].Name
		}
		if catalogImage.Spec.Metadata.Bootc {
			catalogImage.Labels[automotivev1alpha1.LabelBootc] = "true"
		}
	}
}

// getVerificationInterval returns the verification interval for the CatalogImage
func (r *CatalogImageReconciler) getVerificationInterval(catalogImage *automotivev1alpha1.CatalogImage) time.Duration {
	if catalogImage.Spec.VerificationInterval != "" {
		if duration, err := time.ParseDuration(catalogImage.Spec.VerificationInterval); err == nil {
			return duration
		}
	}
	return defaultVerificationInterval
}

// getRegistryClient returns the registry client (allows for testing)
func (r *CatalogImageReconciler) getRegistryClient() RegistryClient {
	if r.RegistryClient != nil {
		return r.RegistryClient
	}
	return NewRegistryClient()
}

// SetupWithManager sets up the controller with the Manager.
func (r *CatalogImageReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Add field indexers for efficient queries
	registryURLIndexer := func(obj client.Object) []string {
		catalogImage := obj.(*automotivev1alpha1.CatalogImage)
		return []string{catalogImage.Spec.RegistryURL}
	}
	err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&automotivev1alpha1.CatalogImage{},
		"spec.registryUrl",
		registryURLIndexer,
	)
	if err != nil {
		return fmt.Errorf("failed to create field index for spec.registryUrl: %w", err)
	}

	phaseIndexer := func(obj client.Object) []string {
		catalogImage := obj.(*automotivev1alpha1.CatalogImage)
		return []string{string(catalogImage.Status.Phase)}
	}
	err = mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&automotivev1alpha1.CatalogImage{},
		"status.phase",
		phaseIndexer,
	)
	if err != nil {
		return fmt.Errorf("failed to create field index for status.phase: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.CatalogImage{}).
		Complete(r)
}
