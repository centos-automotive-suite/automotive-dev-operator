// Package containerbuild provides the controller for managing ContainerBuild custom resources.
package containerbuild

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	shipwrightv1beta1 "github.com/shipwright-io/build/pkg/apis/build/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
	phasePending   = "Pending"
	phaseUploading = "Uploading"
	phaseBuilding  = "Building"

	maxK8sNameLength = 63

	// OperatorNamespace is the namespace where the operator is deployed.
	OperatorNamespace = "automotive-dev-operator-system"

	// defaultUploadTimeoutMinutes is the default source upload timeout for container builds.
	defaultUploadTimeoutMinutes = 10
)

// safeDerivedName generates a Kubernetes-safe derived resource name.
func safeDerivedName(baseName, suffix string) string {
	maxBaseLength := maxK8sNameLength - len(suffix) - 9
	if maxBaseLength >= len(baseName) {
		return fmt.Sprintf("%s%s", baseName, suffix)
	}
	hash := sha256.Sum256([]byte(baseName))
	hexHash := fmt.Sprintf("%x", hash[:4])
	if maxBaseLength <= 0 {
		name := hexHash + suffix
		if len(name) > maxK8sNameLength {
			name = name[:maxK8sNameLength]
		}
		return name
	}
	truncated := baseName[:maxBaseLength]
	return fmt.Sprintf("%s-%s%s", truncated, hexHash, suffix)
}

// ContainerBuildReconciler reconciles a ContainerBuild object
//
//nolint:revive // Name follows Kubebuilder convention for reconcilers
type ContainerBuildReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=containerbuilds,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=containerbuilds/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=containerbuilds/finalizers,verbs=update
//+kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs,verbs=get;list;watch
//+kubebuilder:rbac:groups=shipwright.io,resources=buildruns,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=shipwright.io,resources=builds,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles the reconciliation loop for ContainerBuild resources.
func (r *ContainerBuildReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", req.NamespacedName)

	cb := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(ctx, req.NamespacedName, cb); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	switch cb.Status.Phase {
	case "", phasePending:
		return r.reconcilePending(ctx, log, cb)
	case phaseUploading:
		return r.reconcileUploading(ctx, log, cb)
	case phaseBuilding:
		return r.reconcileBuilding(ctx, log, cb)
	case phaseCompleted, phaseFailed:
		return ctrl.Result{}, nil
	default:
		log.Info("unknown phase", "phase", cb.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *ContainerBuildReconciler) reconcilePending(
	ctx context.Context, log logr.Logger, cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log.Info("creating BuildRun for ContainerBuild")

	buildRunName := safeDerivedName(cb.Name, "-br")

	// Check if BuildRun already exists
	existing := &shipwrightv1beta1.BuildRun{}
	if err := r.Get(ctx, types.NamespacedName{Name: buildRunName, Namespace: cb.Namespace}, existing); err == nil {
		// BuildRun already exists, update status and move on
		return r.updatePhase(ctx, cb, phaseUploading, buildRunName, "Waiting for source upload")
	} else if !errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	// Read upload timeout from OperatorConfig, falling back to default
	uploadTimeout := time.Duration(defaultUploadTimeoutMinutes) * time.Minute
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: OperatorNamespace}, operatorConfig); err == nil {
		if operatorConfig.Spec.ContainerBuilds != nil && operatorConfig.Spec.ContainerBuilds.UploadTimeoutMinutes > 0 {
			uploadTimeout = time.Duration(operatorConfig.Spec.ContainerBuilds.UploadTimeoutMinutes) * time.Minute
		}
	}

	buildRun := r.buildShipwrightBuildRun(cb, buildRunName, uploadTimeout)
	if err := ctrl.SetControllerReference(cb, buildRun, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting owner reference: %w", err)
	}

	if err := r.Create(ctx, buildRun); err != nil {
		if errors.IsAlreadyExists(err) {
			return r.updatePhase(ctx, cb, phaseUploading, buildRunName, "Waiting for source upload")
		}
		return ctrl.Result{}, fmt.Errorf("creating BuildRun: %w", err)
	}
	r.emitEventf(
		cb,
		corev1.EventTypeNormal,
		"BuildRunCreated",
		"BuildRun created: name=%s strategy=%s arch=%s output=%s",
		buildRunName,
		cb.Spec.GetStrategy(),
		cb.Spec.GetArchitecture(),
		cb.Spec.Output,
	)

	log.Info("BuildRun created", "buildRun", buildRunName)
	return r.updatePhase(ctx, cb, phaseUploading, buildRunName, "Waiting for source upload")
}

func (r *ContainerBuildReconciler) reconcileUploading(
	ctx context.Context, log logr.Logger, cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	if cb.Status.BuildRunName == "" {
		return r.updatePhase(ctx, cb, phaseFailed, "", "BuildRun name missing from status")
	}

	// Check if source upload has been completed by checking if the waiter container has finished.
	// In modern Shipwright, the waiter is a regular container (step-source-local), not an init container.
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList,
		client.InNamespace(cb.Namespace),
		client.MatchingLabels{"buildrun.shipwright.io/name": cb.Status.BuildRunName},
	); err != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	if len(podList.Items) == 0 {
		log.Info("waiting for BuildRun pod to be created")
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	pod := &podList.Items[0]

	// Find the source-local waiter container
	var waiterContainer *corev1.ContainerStatus
	for _, cs := range pod.Status.ContainerStatuses {
		if strings.Contains(cs.Name, "source-local") {
			// Create a copy to avoid referencing loop variable
			containerCopy := cs
			waiterContainer = &containerCopy
			break
		}
	}

	// If no waiter container found, check init containers for backward compatibility
	if waiterContainer == nil {
		for _, cs := range pod.Status.InitContainerStatuses {
			if strings.Contains(cs.Name, "source-local") {
				// Convert init container status to regular container status format
				waiterContainer = &corev1.ContainerStatus{
					Name:  cs.Name,
					State: cs.State,
				}
				break
			}
		}
	}

	if waiterContainer == nil {
		log.Info("source waiter container not found, waiting for pod to start")
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Check if waiter container is still running (waiting for upload)
	if waiterContainer.State.Running != nil {
		log.Info("source waiter container still running, waiting for upload", "container", waiterContainer.Name)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Check if waiter container terminated successfully (upload complete)
	if waiterContainer.State.Terminated != nil {
		if waiterContainer.State.Terminated.ExitCode == 0 {
			log.Info("source upload completed successfully", "container", waiterContainer.Name)
			now := metav1.Now()
			original := cb.DeepCopy()
			cb.Status.Phase = phaseBuilding
			cb.Status.Message = "Source uploaded, build in progress"
			cb.Status.StartTime = &now
			if err := r.Status().Patch(ctx, cb, client.MergeFrom(original)); err != nil {
				return ctrl.Result{}, err
			}
			r.emitEventf(
				cb,
				corev1.EventTypeNormal,
				"UploadCompleted",
				"Source upload completed, build started: buildRun=%s",
				cb.Status.BuildRunName,
			)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		// Waiter failed
		msg := fmt.Sprintf("source upload failed: container %s exited with code %d", waiterContainer.Name, waiterContainer.State.Terminated.ExitCode)
		log.Error(nil, "source upload failed", "container", waiterContainer.Name, "exitCode", waiterContainer.State.Terminated.ExitCode)
		return r.updatePhase(ctx, cb, phaseFailed, cb.Status.BuildRunName, msg)
	}

	// Container is waiting or starting
	log.Info("waiting for source waiter container to be ready", "container", waiterContainer.Name)
	return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
}

func (r *ContainerBuildReconciler) reconcileBuilding(
	ctx context.Context, log logr.Logger, cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	if cb.Status.BuildRunName == "" {
		return r.updatePhase(ctx, cb, phaseFailed, "", "BuildRun name missing from status")
	}

	buildRun := &shipwrightv1beta1.BuildRun{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      cb.Status.BuildRunName,
		Namespace: cb.Namespace,
	}, buildRun); err != nil {
		if errors.IsNotFound(err) {
			return r.updatePhase(ctx, cb, phaseFailed, cb.Status.BuildRunName, "BuildRun not found")
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	// Check BuildRun completion via conditions
	for _, condition := range buildRun.Status.Conditions {
		if condition.Type == "Succeeded" {
			if condition.Status == corev1.ConditionTrue {
				log.Info("BuildRun succeeded")
				now := metav1.Now()
				original := cb.DeepCopy()
				cb.Status.Phase = phaseCompleted
				cb.Status.Message = "Container image built and pushed successfully"
				cb.Status.CompletionTime = &now
				// Extract image digest from BuildRun status
				if buildRun.Status.Output != nil {
					cb.Status.ImageDigest = buildRun.Status.Output.Digest
				}
				if err := r.Status().Patch(ctx, cb, client.MergeFrom(original)); err != nil {
					return ctrl.Result{}, err
				}
				r.emitContainerLifecycleEvent(cb, phaseBuilding, phaseCompleted, cb.Status.Message)
				return ctrl.Result{}, nil
			}
			if condition.Status == corev1.ConditionFalse {
				log.Info("BuildRun failed", "reason", condition.Message)
				now := metav1.Now()
				original := cb.DeepCopy()
				cb.Status.Phase = phaseFailed
				cb.Status.Message = condition.Message
				cb.Status.CompletionTime = &now
				if err := r.Status().Patch(ctx, cb, client.MergeFrom(original)); err != nil {
					return ctrl.Result{}, err
				}
				r.emitContainerLifecycleEvent(cb, phaseBuilding, phaseFailed, cb.Status.Message)
				return ctrl.Result{}, nil
			}
		}
	}

	log.Info("BuildRun still in progress")
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *ContainerBuildReconciler) updatePhase(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
	phase, buildRunName, message string,
) (ctrl.Result, error) {
	original := cb.DeepCopy()
	oldPhase := cb.Status.Phase
	oldMessage := cb.Status.Message
	cb.Status.Phase = phase
	cb.Status.Message = message
	if buildRunName != "" {
		cb.Status.BuildRunName = buildRunName
	}
	if phase == phaseFailed || phase == phaseCompleted {
		now := metav1.Now()
		cb.Status.CompletionTime = &now
	}
	if err := r.Status().Patch(ctx, cb, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, err
	}
	if oldPhase != phase || oldMessage != message {
		r.emitEventf(
			cb,
			eventTypeForContainerPhase(phase),
			"PhaseChanged",
			"Phase transitioned: %s -> %s, message=%s, buildRun=%s",
			oldPhase,
			phase,
			message,
			cb.Status.BuildRunName,
		)
		r.emitContainerLifecycleEvent(cb, oldPhase, phase, message)
	}
	if phase == phaseFailed || phase == phaseCompleted {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
}

func (r *ContainerBuildReconciler) emitContainerLifecycleEvent(
	cb *automotivev1alpha1.ContainerBuild,
	oldPhase, newPhase, message string,
) {
	switch newPhase {
	case phaseUploading:
		r.emitEventf(
			cb,
			corev1.EventTypeNormal,
			"ContainerUploadStarted",
			"Container build upload started: strategy=%s arch=%s output=%s message=%s",
			cb.Spec.GetStrategy(),
			cb.Spec.GetArchitecture(),
			cb.Spec.Output,
			message,
		)
	case phaseBuilding:
		reason := "ContainerBuildStarted"
		if oldPhase == phaseBuilding {
			reason = "ContainerBuildRunning"
		}
		r.emitEventf(
			cb,
			corev1.EventTypeNormal,
			reason,
			"Container build running: strategy=%s arch=%s output=%s message=%s",
			cb.Spec.GetStrategy(),
			cb.Spec.GetArchitecture(),
			cb.Spec.Output,
			message,
		)
	case phaseCompleted:
		r.emitEventf(
			cb,
			corev1.EventTypeNormal,
			"ContainerBuildCompleted",
			"Container build completed: buildRun=%s digest=%s message=%s",
			cb.Status.BuildRunName,
			cb.Status.ImageDigest,
			message,
		)
	case phaseFailed:
		r.emitEventf(
			cb,
			corev1.EventTypeWarning,
			"ContainerBuildFailed",
			"Container build failed: buildRun=%s message=%s",
			cb.Status.BuildRunName,
			message,
		)
	}
}

func eventTypeForContainerPhase(phase string) string {
	if phase == phaseFailed {
		return corev1.EventTypeWarning
	}
	return corev1.EventTypeNormal
}

func (r *ContainerBuildReconciler) emitEventf(
	cb *automotivev1alpha1.ContainerBuild,
	eventType, reason, messageFmt string,
	args ...interface{},
) {
	if r.Recorder == nil || cb == nil {
		return
	}
	r.Recorder.Eventf(cb, eventType, reason, messageFmt, args...)
}

func (r *ContainerBuildReconciler) buildShipwrightBuildRun(
	cb *automotivev1alpha1.ContainerBuild,
	buildRunName string,
	uploadTimeout time.Duration,
) *shipwrightv1beta1.BuildRun {
	strategyKind := shipwrightv1beta1.ClusterBuildStrategyKind
	if cb.Spec.GetStrategyKind() == "BuildStrategy" {
		strategyKind = shipwrightv1beta1.NamespacedBuildStrategyKind
	}

	timeout := time.Duration(cb.Spec.GetTimeout()) * time.Minute
	timeoutDuration := metav1.Duration{Duration: timeout}

	localName := cb.Name + "-source"

	// Build paramValues for Containerfile path
	paramValues := make([]shipwrightv1beta1.ParamValue, 0, 1+len(cb.Spec.BuildArgs))
	containerfile := cb.Spec.GetContainerfile()
	if containerfile != "Containerfile" {
		paramValues = append(paramValues, shipwrightv1beta1.ParamValue{
			Name:        "dockerfile",
			SingleValue: &shipwrightv1beta1.SingleValue{Value: &containerfile},
		})
	}

	// Collect all build args into a single ParamValue entry
	buildArgValues := make([]shipwrightv1beta1.SingleValue, 0, len(cb.Spec.BuildArgs)+1)
	for key, val := range cb.Spec.BuildArgs {
		arg := fmt.Sprintf("%s=%s", key, val)
		buildArgValues = append(buildArgValues, shipwrightv1beta1.SingleValue{Value: &arg})
	}
	// Pass architecture as build arg so Dockerfiles can use TARGETARCH
	arch := cb.Spec.GetArchitecture()
	platformArg := fmt.Sprintf("TARGETARCH=%s", arch)
	buildArgValues = append(buildArgValues, shipwrightv1beta1.SingleValue{Value: &platformArg})

	paramValues = append(paramValues, shipwrightv1beta1.ParamValue{
		Name:   "build-args",
		Values: buildArgValues,
	})

	// Build output
	output := shipwrightv1beta1.Image{
		Image: cb.Spec.Output,
	}
	if cb.Spec.PushSecretRef != "" {
		pushSecret := cb.Spec.PushSecretRef
		output.PushSecret = &pushSecret
	}

	saName := automotivev1alpha1.BuildServiceAccountName
	buildRun := &shipwrightv1beta1.BuildRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildRunName,
			Namespace: cb.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                   "automotive-dev-operator",
				"app.kubernetes.io/part-of":                      "automotive-dev",
				"automotive.sdv.cloud.redhat.com/containerbuild": cb.Name,
			},
		},
		Spec: shipwrightv1beta1.BuildRunSpec{
			ServiceAccount: &saName,
			Build: shipwrightv1beta1.ReferencedBuild{
				Spec: &shipwrightv1beta1.BuildSpec{
					Source: &shipwrightv1beta1.Source{
						Type: shipwrightv1beta1.LocalType,
						Local: &shipwrightv1beta1.Local{
							Name:    localName,
							Timeout: &metav1.Duration{Duration: uploadTimeout},
						},
					},
					Strategy: shipwrightv1beta1.Strategy{
						Name: cb.Spec.GetStrategy(),
						Kind: &strategyKind,
					},
					Output:      output,
					ParamValues: paramValues,
					Timeout:     &timeoutDuration,
				},
			},
		},
	}

	return buildRun
}

// SetupWithManager sets up the controller with the Manager.
// Note: We intentionally do not call Owns(&BuildRun{}) because that would create an informer
// for the Shipwright BuildRun CRD, crashing the entire operator if Shipwright is not installed.
// Instead, the controller uses RequeueAfter-based polling to monitor BuildRun progress,
// which is sufficient for builds that run for minutes.
func (r *ContainerBuildReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ContainerBuild{}).
		Complete(r)
}
