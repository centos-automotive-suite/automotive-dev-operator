// Package containerbuild provides the controller for managing ContainerBuild custom resources.
package containerbuild

import (
	"context"
	"fmt"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/go-logr/logr"
	shipwrightv1beta1 "github.com/shipwright-io/build/pkg/apis/build/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Phase constants
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
)

// ContainerBuildReconciler reconciles a ContainerBuild object
//
//nolint:revive // Name follows Kubebuilder convention for reconcilers
type ContainerBuildReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Log        logr.Logger
	RestConfig *rest.Config
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=containerbuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=containerbuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=containerbuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=shipwright.io,resources=builds;buildruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=shipwright.io,resources=clusterbuildstrategies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;delete

// Reconcile handles ContainerBuild reconciliation and manages the build lifecycle
func (r *ContainerBuildReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", req.NamespacedName)

	cb := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(ctx, req.NamespacedName, cb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch cb.Status.Phase {
	case "":
		return r.handleInitialState(ctx, cb)
	case "Uploading":
		return r.handleUploadingState(ctx, cb)
	case "Building":
		return r.handleBuildingState(ctx, cb)
	case phaseCompleted:
		return ctrl.Result{}, nil
	case phaseFailed:
		return ctrl.Result{}, nil
	default:
		log.Info("Unknown phase", "phase", cb.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *ContainerBuildReconciler) handleInitialState(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	// Create PVC and upload pod for build context
	if err := r.createUploadPod(ctx, cb); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create upload pod: %w", err)
	}

	if err := r.updateStatus(ctx, cb, "Uploading", "Waiting for build context upload"); err != nil {
		log.Error(err, "Failed to update status to Uploading")
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: true}, nil
}

func (r *ContainerBuildReconciler) handleUploadingState(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	uploadsComplete := cb.Annotations != nil &&
		cb.Annotations["automotive.sdv.cloud.redhat.com/uploads-complete"] == "true"

	if !uploadsComplete {
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	if err := r.shutdownUploadPod(ctx, cb); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to shutdown upload pod: %w", err)
	}

	if err := r.updateStatus(ctx, cb, "Building", "Build started"); err != nil {
		log.Error(err, "Failed to update status to Building")
		return ctrl.Result{}, err
	}

	return ctrl.Result{Requeue: true}, nil
}

func (r *ContainerBuildReconciler) handleBuildingState(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	if cb.Status.BuildRunName != "" {
		return r.checkBuildRunProgress(ctx, cb)
	}

	// Look for existing BuildRuns for this ContainerBuild
	buildRunList := &shipwrightv1beta1.BuildRunList{}
	if err := r.List(ctx, buildRunList,
		client.InNamespace(cb.Namespace),
		client.MatchingLabels{
			"automotive.sdv.cloud.redhat.com/containerbuild-name": cb.Name,
		}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list existing build runs: %w", err)
	}

	for _, br := range buildRunList.Items {
		if br.DeletionTimestamp == nil {
			log.Info("Found existing BuildRun for this ContainerBuild", "buildRun", br.Name)

			fresh := &automotivev1alpha1.ContainerBuild{}
			if err := r.Get(ctx, types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace}, fresh); err != nil {
				return ctrl.Result{}, err
			}

			if fresh.Status.BuildRunName != br.Name {
				fresh.Status.BuildRunName = br.Name
				if err := r.Status().Update(ctx, fresh); err != nil {
					return ctrl.Result{}, err
				}
			}

			cb.Status.BuildRunName = br.Name
			return r.checkBuildRunProgress(ctx, cb)
		}
	}

	return r.createBuildRun(ctx, cb)
}

func (r *ContainerBuildReconciler) checkBuildRunProgress(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	buildRun := &shipwrightv1beta1.BuildRun{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      cb.Status.BuildRunName,
		Namespace: cb.Namespace,
	}, buildRun)
	if err != nil {
		if errors.IsNotFound(err) {
			// BuildRun was deleted, re-create
			return r.createBuildRun(ctx, cb)
		}
		return ctrl.Result{}, err
	}

	if buildRun.Status.CompletionTime == nil {
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	// BuildRun completed — check success/failure
	fresh := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace}, fresh); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(fresh.DeepCopy())

	if isBuildRunSuccessful(buildRun) {
		fresh.Status.Phase = phaseCompleted
		fresh.Status.Message = fmt.Sprintf("Image pushed to %s", cb.Spec.Output)
	} else {
		fresh.Status.Phase = phaseFailed
		fresh.Status.Message = extractBuildRunFailureMessage(buildRun)
	}

	now := metav1.Now()
	fresh.Status.CompletionTime = &now

	if err := r.Status().Patch(ctx, fresh, patch); err != nil {
		log.Error(err, "Failed to patch status after BuildRun completion")
		return ctrl.Result{}, err
	}

	// Cleanup transient secrets
	r.cleanupTransientSecrets(ctx, cb)

	return ctrl.Result{}, nil
}

func (r *ContainerBuildReconciler) createBuildRun(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (ctrl.Result, error) {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})
	log.Info("Creating Shipwright BuildRun for ContainerBuild")

	dockerfile := cb.Spec.Dockerfile
	if dockerfile == "" {
		dockerfile = "Containerfile"
	}

	buildArgs := strings.Join(cb.Spec.BuildArgs, ",")

	strategyKind := shipwrightv1beta1.ClusterBuildStrategyKind

	buildSpec := shipwrightv1beta1.BuildSpec{
		Source: nil, // Context provided via volume override
		Strategy: shipwrightv1beta1.Strategy{
			Name: tasks.ContainerBuildStrategyName,
			Kind: &strategyKind,
		},
		Output: shipwrightv1beta1.Image{
			Image: cb.Spec.Output,
		},
		ParamValues: []shipwrightv1beta1.ParamValue{
			{
				Name:        "dockerfile",
				SingleValue: &shipwrightv1beta1.SingleValue{Value: &dockerfile},
			},
			{
				Name:        "build-args",
				SingleValue: &shipwrightv1beta1.SingleValue{Value: &buildArgs},
			},
		},
		Volumes: []shipwrightv1beta1.BuildVolume{
			{
				Name: "build-context",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: cb.Status.PVCName,
					},
				},
			},
		},
	}

	if cb.Spec.SecretRef != "" {
		buildSpec.Output.PushSecret = &cb.Spec.SecretRef
	}

	buildRun := &shipwrightv1beta1.BuildRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", cb.Name),
			Namespace:    cb.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                        "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/containerbuild-name": cb.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: cb.APIVersion,
					Kind:       cb.Kind,
					Name:       cb.Name,
					UID:        cb.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: shipwrightv1beta1.BuildRunSpec{
			Build: shipwrightv1beta1.ReferencedBuild{
				Spec: &buildSpec,
			},
		},
	}

	if err := r.Create(ctx, buildRun); err != nil {
		if statusErr := r.updateStatus(ctx, cb, phaseFailed,
			fmt.Sprintf("Failed to create BuildRun: %v", err)); statusErr != nil {
			log.Error(statusErr, "Failed to update status after BuildRun creation failure")
		}
		return ctrl.Result{}, fmt.Errorf("failed to create BuildRun: %w", err)
	}

	fresh := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace}, fresh); err != nil {
		return ctrl.Result{}, err
	}

	fresh.Status.BuildRunName = buildRun.Name
	if err := r.Status().Update(ctx, fresh); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Successfully created BuildRun", "name", buildRun.Name)
	return ctrl.Result{RequeueAfter: time.Second * 10}, nil
}

func (r *ContainerBuildReconciler) createUploadPod(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) error {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	podName := fmt.Sprintf("%s-upload-pod", cb.Name)
	existingPod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{Name: podName, Namespace: cb.Namespace}, existingPod)
	if err == nil {
		if existingPod.Status.Phase == corev1.PodRunning {
			log.Info("Upload pod already exists and is running", "pod", podName)
			return nil
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("error checking for existing pod: %w", err)
	}

	workspacePVCName, err := r.getOrCreateWorkspacePVC(ctx, cb)
	if err != nil {
		return err
	}

	if cb.Status.PVCName != workspacePVCName {
		fresh := &automotivev1alpha1.ContainerBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace}, fresh); err != nil {
			return fmt.Errorf("failed to get fresh ContainerBuild: %w", err)
		}
		fresh.Status.PVCName = workspacePVCName
		if err := r.Status().Update(ctx, fresh); err != nil {
			return fmt.Errorf("failed to update ContainerBuild status with PVC name: %w", err)
		}
		cb.Status.PVCName = workspacePVCName
	}

	labels := map[string]string{
		"app.kubernetes.io/managed-by":                        "automotive-dev-operator",
		"automotive.sdv.cloud.redhat.com/containerbuild-name": cb.Name,
		"app.kubernetes.io/name":                              "upload-pod",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: cb.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         cb.APIVersion,
					Kind:               cb.Kind,
					Name:               cb.Name,
					UID:                cb.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:    ptr.To[int64](1000),
				RunAsGroup:   ptr.To[int64](1000),
				FSGroup:      ptr.To[int64](1000),
				RunAsNonRoot: ptr.To(true),
			},
			Containers: []corev1.Container{
				{
					Name:    "fileserver",
					Image:   "quay.io/nginx/nginx-unprivileged:latest",
					Command: []string{"sleep", "infinity"},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("64Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("200m"),
							corev1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "workspace",
							MountPath: "/workspace/shared",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "workspace",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: workspacePVCName,
						},
					},
				},
			},
		},
	}

	if err := r.Create(ctx, pod); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create upload pod: %w", err)
	}

	log.Info("Created upload pod", "pod", podName)
	return nil
}

func (r *ContainerBuildReconciler) getOrCreateWorkspacePVC(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) (string, error) {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	if cb.Status.PVCName != "" {
		existingPVC := &corev1.PersistentVolumeClaim{}
		err := r.Get(ctx, types.NamespacedName{Name: cb.Status.PVCName, Namespace: cb.Namespace}, existingPVC)
		if err == nil && existingPVC.DeletionTimestamp == nil {
			log.Info("Using existing workspace PVC from status", "pvc", cb.Status.PVCName)
			return cb.Status.PVCName, nil
		}
	}

	storageSize := resource.MustParse("2Gi")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	uniquePVCName := fmt.Sprintf("%s-ws-%s", cb.Name, timestamp)

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uniquePVCName,
			Namespace: cb.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                        "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/containerbuild-name": cb.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         cb.APIVersion,
					Kind:               cb.Kind,
					Name:               cb.Name,
					UID:                cb.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: storageSize,
				},
			},
		},
	}

	if cb.Spec.StorageClass != "" {
		pvc.Spec.StorageClassName = &cb.Spec.StorageClass
	}

	if err := r.Create(ctx, pvc); err != nil {
		return "", fmt.Errorf("failed to create workspace PVC: %w", err)
	}

	log.Info("Created workspace PVC", "pvc", uniquePVCName)
	return uniquePVCName, nil
}

func (r *ContainerBuildReconciler) shutdownUploadPod(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) error {
	log := r.Log.WithValues("containerbuild", types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace})

	podName := fmt.Sprintf("%s-upload-pod", cb.Name)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: cb.Namespace,
		},
	}

	if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete upload pod: %w", err)
	}

	log.Info("Upload pod deleted")
	return nil
}

func (r *ContainerBuildReconciler) updateStatus(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
	phase, message string,
) error {
	fresh := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: cb.Name, Namespace: cb.Namespace}, fresh); err != nil {
		return err
	}

	patch := client.MergeFrom(fresh.DeepCopy())

	fresh.Status.Phase = phase
	fresh.Status.Message = message

	if phase == "Building" && fresh.Status.StartTime == nil {
		now := metav1.Now()
		fresh.Status.StartTime = &now
	} else if (phase == phaseCompleted || phase == phaseFailed) && fresh.Status.CompletionTime == nil {
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
	}

	return r.Status().Patch(ctx, fresh, patch)
}

func (r *ContainerBuildReconciler) cleanupTransientSecrets(
	ctx context.Context,
	cb *automotivev1alpha1.ContainerBuild,
) {
	if cb.Spec.SecretRef == "" {
		return
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cb.Spec.SecretRef,
			Namespace: cb.Namespace,
		},
	}
	if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		r.Log.Error(err, "Failed to delete transient secret", "secret", cb.Spec.SecretRef)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ContainerBuildReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ContainerBuild{}).
		Owns(&shipwrightv1beta1.BuildRun{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Complete(r)
}

func isBuildRunSuccessful(buildRun *shipwrightv1beta1.BuildRun) bool {
	for _, condition := range buildRun.Status.Conditions {
		if condition.Type == shipwrightv1beta1.Succeeded {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func extractBuildRunFailureMessage(buildRun *shipwrightv1beta1.BuildRun) string {
	for _, condition := range buildRun.Status.Conditions {
		if condition.Type == shipwrightv1beta1.Succeeded && condition.Status == corev1.ConditionFalse {
			return fmt.Sprintf("Build failed: %s", condition.Message)
		}
	}
	return "Build failed"
}
