// Package softwarebuild provides the controller for managing SoftwareBuild custom resources.
package softwarebuild

import (
	"context"
	"fmt"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	knativeapis "knative.dev/pkg/apis"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	conditionReady = "Ready"
	reasonRunning  = "Running"
)

// Reconciler reconciles SoftwareBuild objects.
type Reconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Log               logr.Logger
	OperatorNamespace string
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=softwarebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=softwarebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=softwarebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=pipelineruns,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles a single reconciliation loop for a SoftwareBuild resource.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("softwarebuild", req.NamespacedName)

	var sb automotivev1alpha1.SoftwareBuild
	if err := r.Get(ctx, req.NamespacedName, &sb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if sb.Status.PipelineRunName == "" {
		return r.createPipelineRun(ctx, logger, &sb)
	}

	return r.syncStatus(ctx, logger, &sb)
}

func (r *Reconciler) createPipelineRun(ctx context.Context, logger logr.Logger, sb *automotivev1alpha1.SoftwareBuild) (ctrl.Result, error) {
	config := r.loadBuildConfig(ctx)
	pr := tasks.GenerateSoftwareBuildPipelineRun(sb, config, r.OperatorNamespace)

	if err := controllerutil.SetControllerReference(sb, pr, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting controller reference: %w", err)
	}

	if err := r.Create(ctx, pr); err != nil {
		if errors.IsAlreadyExists(err) {
			sb.Status.PipelineRunName = pr.Name
			if statusErr := r.Status().Update(ctx, sb); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status after AlreadyExists: %w", statusErr)
			}
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("creating PipelineRun: %w", err)
	}

	sb.Status.PipelineRunName = pr.Name
	sb.Status.Phase = automotivev1alpha1.SoftwareBuildPhasePending
	meta.SetStatusCondition(&sb.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             "PipelineRunCreated",
		Message:            "PipelineRun created for SoftwareBuild",
		ObservedGeneration: sb.Generation,
	})

	if err := r.Status().Update(ctx, sb); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status after PipelineRun creation: %w", err)
	}

	logger.Info("created PipelineRun", "name", pr.Name)
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *Reconciler) syncStatus(ctx context.Context, logger logr.Logger, sb *automotivev1alpha1.SoftwareBuild) (ctrl.Result, error) {
	var pr tektonv1.PipelineRun
	ns := r.OperatorNamespace
	if ns == "" {
		ns = sb.Namespace
	}
	prKey := types.NamespacedName{Namespace: ns, Name: sb.Status.PipelineRunName}
	if err := r.Get(ctx, prKey, &pr); err != nil {
		if errors.IsNotFound(err) {
			sb.Status.Phase = automotivev1alpha1.SoftwareBuildPhaseFailed
			sb.Status.FailureReason = "PipelineRunNotFound"
			meta.SetStatusCondition(&sb.Status.Conditions, metav1.Condition{
				Type:               conditionReady,
				Status:             metav1.ConditionFalse,
				Reason:             "PipelineRunMissing",
				Message:            "Referenced PipelineRun no longer exists",
				ObservedGeneration: sb.Generation,
			})
			if statusErr := r.Status().Update(ctx, sb); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status after PipelineRun not found: %w", statusErr)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching PipelineRun %s: %w", prKey.Name, err)
	}

	r.syncStatusFromPipelineRun(sb, &pr)

	if err := r.Status().Update(ctx, sb); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating SoftwareBuild status: %w", err)
	}

	if sb.Status.Phase == automotivev1alpha1.SoftwareBuildPhaseRunning ||
		sb.Status.Phase == automotivev1alpha1.SoftwareBuildPhasePending {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	switch sb.Status.Phase {
	case automotivev1alpha1.SoftwareBuildPhaseSucceeded:
		logger.Info("build succeeded", "pipelineRun", sb.Status.PipelineRunName)
	case automotivev1alpha1.SoftwareBuildPhaseFailed:
		logger.Info("build failed", "pipelineRun", sb.Status.PipelineRunName, "reason", sb.Status.FailureReason)
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) syncStatusFromPipelineRun(sb *automotivev1alpha1.SoftwareBuild, pr *tektonv1.PipelineRun) {
	phase, condStatus, reason, message := mapPipelineRunPhase(pr)
	if phase == automotivev1alpha1.SoftwareBuildPhaseFailed {
		sb.Status.FailureReason = reason
	}

	sb.Status.Phase = phase
	meta.SetStatusCondition(&sb.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: sb.Generation,
	})

	sb.Status.Stages = buildStageStatuses(pr)

	if sb.Spec.Destination.Path != "" {
		sb.Status.ArtifactURI = sb.Spec.Destination.Path
	}
}

func mapPipelineRunPhase(pr *tektonv1.PipelineRun) (automotivev1alpha1.SoftwareBuildPhase, metav1.ConditionStatus, string, string) {
	for _, c := range pr.Status.Conditions {
		if c.Type == knativeapis.ConditionSucceeded {
			switch c.Status {
			case corev1.ConditionTrue:
				return automotivev1alpha1.SoftwareBuildPhaseSucceeded, metav1.ConditionTrue, c.Reason, c.Message
			case corev1.ConditionFalse:
				return automotivev1alpha1.SoftwareBuildPhaseFailed, metav1.ConditionFalse, c.Reason, c.Message
			default:
				return automotivev1alpha1.SoftwareBuildPhaseRunning, metav1.ConditionFalse, reasonRunning, "PipelineRun is in progress"
			}
		}
	}

	if pr.Status.StartTime != nil {
		return automotivev1alpha1.SoftwareBuildPhaseRunning, metav1.ConditionFalse, reasonRunning, "PipelineRun is in progress"
	}
	return automotivev1alpha1.SoftwareBuildPhasePending, metav1.ConditionFalse, "Pending", "PipelineRun is pending"
}

func buildStageStatuses(pr *tektonv1.PipelineRun) []automotivev1alpha1.SoftwareBuildStageStatus {
	stages := make([]automotivev1alpha1.SoftwareBuildStageStatus, 0, len(pr.Status.ChildReferences))
	for _, cr := range pr.Status.ChildReferences {
		stages = append(stages, automotivev1alpha1.SoftwareBuildStageStatus{
			Name:    cr.PipelineTaskName,
			State:   "Created",
			Message: fmt.Sprintf("TaskRun: %s", cr.Name),
		})
	}
	return stages
}

func (r *Reconciler) loadBuildConfig(ctx context.Context) *tasks.BuildConfig {
	var opConfig automotivev1alpha1.OperatorConfig
	if err := r.Get(ctx, types.NamespacedName{Name: "default", Namespace: r.OperatorNamespace}, &opConfig); err != nil {
		return nil
	}
	if opConfig.Spec.SoftwareBuilds == nil {
		return nil
	}
	return &tasks.BuildConfig{
		PVCSize:             opConfig.Spec.SoftwareBuilds.PVCSize,
		BuildTimeoutMinutes: opConfig.Spec.SoftwareBuilds.BuildTimeoutMinutes,
		DefaultImage:        opConfig.Spec.SoftwareBuilds.DefaultImage,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.SoftwareBuild{}).
		Owns(&tektonv1.PipelineRun{}).
		Complete(r)
}
