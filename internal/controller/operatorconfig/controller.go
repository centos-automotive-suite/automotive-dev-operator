// Package operatorconfig provides the controller for managing OperatorConfig custom resources.
package operatorconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

const (
	finalizerName           = "operatorconfig.automotive.sdv.cloud.redhat.com/finalizer"
	buildAPIName            = "ado-build-api"
	phaseFailed             = "Failed"
	internalJWTSecretName   = "ado-build-api-internal-jwt"
	unmanagedAnnotationKey  = "automotive.sdv.cloud.redhat.com/unmanaged"
	unmanagedAnnotationTrue = "true"
)

// targetDefaultsYAML is the default content for the aib-target-defaults ConfigMap.
// It defines per-target build defaults (architecture, extra args, partition rules).
var targetDefaultsYAML = `targets:
  ridesx4:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ridesx4_r3:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ridesx4_scmi:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ride4_sa8775p_sx_r3:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ride4_sa8775p_sx:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ride4_sa8775p_sx_legacy:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ride4_sa8775p_sx_legacy_r3:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ride4_sa8650p_sx_r3:
    architecture: arm64
    extraArgs: ["--separate-partitions"]
    include: ["system_a", "system_b", "boot_a", "boot_b"]
  ebbr:
    architecture: arm64
  rcar_s4:
    architecture: arm64
  j784s4evm:
    architecture: arm64
  s32g_vnp_rdb3:
    architecture: arm64
`

// isNoMatchError checks if error is "no matches for kind" error (CRD doesn't exist)
func isNoMatchError(err error) bool {
	if err == nil {
		return false
	}
	if apimeta.IsNoMatchError(err) {
		return true
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "no matches for kind \"route\"") ||
		strings.Contains(errMsg, "no matches for kind \"ingress\"")
}

// detectOpenShift checks if we're running on OpenShift by looking for OpenShift-specific APIs.
// The probe uses the reconciled namespace so it works with namespace-scoped caches.
func (r *OperatorConfigReconciler) detectOpenShift(ctx context.Context, namespace string) bool {
	if r.IsOpenShift != nil {
		return *r.IsOpenShift
	}
	if namespace == "" {
		namespace = "default"
	}

	route := &routev1.Route{}
	route.Name = "test"
	route.Namespace = namespace
	err := r.Get(ctx, client.ObjectKey{Name: "test", Namespace: namespace}, route)

	// Route API exists on OpenShift; probing a dummy object should return NotFound there.
	// Any ambiguous error is treated as non-OpenShift to avoid creating OpenShift-only resources on Kubernetes.
	isOpenShift := err == nil || errors.IsNotFound(err)
	if err != nil && !errors.IsNotFound(err) && !isNoMatchError(err) {
		r.Log.Error(err, "OpenShift detection probe failed unexpectedly, defaulting to non-OpenShift")
		isOpenShift = false
	}

	r.IsOpenShift = &isOpenShift
	r.Log.Info("Platform detected", "isOpenShift", isOpenShift)
	return isOpenShift
}

// detectJumpstarter checks if Jumpstarter CRDs are installed in the cluster
func (r *OperatorConfigReconciler) detectJumpstarter(ctx context.Context) bool {
	if r.IsJumpstarter != nil {
		return *r.IsJumpstarter
	}

	// Try to get the Exporter CRD
	crd := &apiextensionsv1.CustomResourceDefinition{}
	err := r.Get(ctx, client.ObjectKey{Name: "exporters.jumpstarter.dev"}, crd)

	if err == nil {
		// Successfully found Jumpstarter CRD - cache positive result
		detected := true
		r.IsJumpstarter = &detected
		r.Log.Info("Jumpstarter detection", "available", true)
		return true
	}

	if errors.IsNotFound(err) {
		// Definitively not found - cache negative result
		detected := false
		r.IsJumpstarter = &detected
		r.Log.Info("Jumpstarter detection", "available", false)
		return false
	}

	// Transient error (RBAC, network, etc.) - don't cache, allow retry
	r.Log.Error(err, "Failed to check for Jumpstarter CRDs, will retry on next reconciliation")
	return false
}

// OperatorConfigReconciler reconciles an OperatorConfig object
//
//nolint:revive // Name follows Kubebuilder convention for reconcilers
type OperatorConfigReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Log           logr.Logger
	IsOpenShift   *bool
	IsJumpstarter *bool
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings;clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;pipelines;pipelineruns,verbs=get;list;watch;create;update;patch;delete

// Reconcile manages the OperatorConfig resource lifecycle.
func (r *OperatorConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("operatorconfig", req.NamespacedName)
	log.Info("=== Reconciliation started ===")

	config := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, req.NamespacedName, config); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OperatorConfig not found, skipping reconciliation")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OperatorConfig")
		return ctrl.Result{}, err
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(config, finalizerName) {
		log.Info("Adding finalizer")
		controllerutil.AddFinalizer(config, finalizerName)
		if err := r.Update(ctx, config); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		log.Info("Finalizer added, requeuing")
		// Requeue to avoid doing more work in this reconciliation
		return ctrl.Result{Requeue: true}, nil
	}

	// Handle deletion
	if !config.DeletionTimestamp.IsZero() {
		log.Info("Handling deletion")
		if err := r.cleanupOSBuilds(ctx, config); err != nil {
			log.Error(err, "Failed to cleanup OSBuilds")
			return ctrl.Result{}, err
		}
		log.Info("Removing finalizer")
		controllerutil.RemoveFinalizer(config, finalizerName)
		if err := r.Update(ctx, config); err != nil {
			log.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
		log.Info("Deletion completed successfully")
		return ctrl.Result{}, nil
	}

	statusChanged := false

	// Reconcile OSBuilds
	log.Info("Processing OSBuilds configuration", "osBuilds", config.Spec.OSBuilds, "generation", config.Generation)
	if config.Spec.OSBuilds != nil && config.Spec.OSBuilds.Enabled {
		if err := r.deployOSBuilds(ctx, config); err != nil {
			log.Error(err, "Failed to deploy OSBuilds")
			if config.Status.Phase != phaseFailed || config.Status.OSBuildsDeployed {
				config.Status.Phase = phaseFailed
				config.Status.Message = fmt.Sprintf("Failed to deploy OSBuilds: %v", err)
				config.Status.OSBuildsDeployed = false
				statusChanged = true
			}
			if statusChanged {
				_ = r.Status().Update(ctx, config)
			}
			return ctrl.Result{}, err
		}
		if !config.Status.OSBuildsDeployed {
			config.Status.OSBuildsDeployed = true
			config.Status.Phase = "Ready"
			config.Status.Message = "OSBuilds deployed successfully"
			statusChanged = true
		}
	} else {
		if err := r.cleanupOSBuilds(ctx, config); err != nil {
			log.Error(err, "Failed to cleanup OSBuilds")
			if config.Status.Phase != phaseFailed {
				config.Status.Phase = phaseFailed
				config.Status.Message = fmt.Sprintf("Failed to cleanup OSBuilds: %v", err)
				statusChanged = true
			}
			if statusChanged {
				_ = r.Status().Update(ctx, config)
			}
			return ctrl.Result{}, err
		}
		if config.Status.OSBuildsDeployed {
			config.Status.OSBuildsDeployed = false
			statusChanged = true
		}
	}

	// Detect Jumpstarter availability
	jumpstarterAvailable := r.detectJumpstarter(ctx)
	if config.Status.JumpstarterAvailable != jumpstarterAvailable {
		config.Status.JumpstarterAvailable = jumpstarterAvailable
		statusChanged = true
	}

	if statusChanged {
		log.Info("Updating status", "phase", config.Status.Phase, "osBuildsDeployed", config.Status.OSBuildsDeployed, "jumpstarterAvailable", config.Status.JumpstarterAvailable)
		if err := r.Status().Update(ctx, config); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
	}

	log.Info("=== Reconciliation completed successfully ===")
	return ctrl.Result{}, nil
}

func (r *OperatorConfigReconciler) deployBuildAPI(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Starting Build-API deployment")

	// Ensure OAuth secret for build-api
	if err := r.ensureBuildAPIOAuthSecret(ctx, owner); err != nil {
		r.Log.Error(err, "Failed to ensure build-api OAuth secret")
		return fmt.Errorf("failed to ensure build-api OAuth secret: %w", err)
	}

	// Ensure internal JWT secret for build-api
	if err := r.ensureBuildAPIInternalJWTSecret(ctx, owner); err != nil {
		r.Log.Error(err, "Failed to ensure build-api internal JWT secret")
		return fmt.Errorf("failed to ensure build-api internal JWT secret: %w", err)
	}

	// Build API now reads authentication configuration directly from OperatorConfig CRD
	// No need to generate ConfigMap anymore
	r.Log.Info("Build API will read authentication config directly from OperatorConfig")

	// Update ServiceAccount with build-api OAuth redirect annotation
	if err := r.updateBuildAPIServiceAccountAnnotation(ctx, owner); err != nil {
		r.Log.Error(err, "Failed to update ServiceAccount build-api OAuth annotation")
		return fmt.Errorf("failed to update ServiceAccount build-api OAuth annotation: %w", err)
	}

	isOpenShift := r.detectOpenShift(ctx, owner.Namespace)

	// Create/update build-api deployment
	r.Log.Info("Creating/updating build-api deployment")
	buildAPIDeployment := r.buildBuildAPIDeployment(owner.Namespace, isOpenShift)
	if err := r.createOrUpdate(ctx, buildAPIDeployment, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api deployment")
		return fmt.Errorf("failed to create/update build-api deployment: %w", err)
	}
	r.Log.Info("Build-API deployment created/updated successfully")

	// Create/update build-api service
	r.Log.Info("Creating/updating build-api service")
	buildAPIService := r.buildBuildAPIService(owner.Namespace, isOpenShift)
	if err := r.createOrUpdate(ctx, buildAPIService, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api service")
		return fmt.Errorf("failed to create/update build-api service: %w", err)
	}
	r.Log.Info("Build-API service created/updated successfully")

	// Create/update build-api route (OpenShift)
	r.Log.Info("Creating/updating build-api route")
	buildAPIRoute := r.buildBuildAPIRoute(owner.Namespace)
	if err := r.createOrUpdate(ctx, buildAPIRoute, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api route (this is expected on non-OpenShift clusters)")
	} else {
		r.Log.Info("Build-API route created/updated successfully")
	}

	// Create/update build-api ingress (Kubernetes)
	r.Log.Info("Creating/updating build-api ingress")
	buildAPIIngress := r.buildBuildAPIIngress(owner.Namespace)
	if err := r.createOrUpdate(ctx, buildAPIIngress, owner); err != nil {
		r.Log.Error(err,
			"Failed to create/update build-api ingress (expected if ingress controller is not installed)")
	} else {
		r.Log.Info("Build-API ingress created/updated successfully")
	}

	r.Log.Info("Build-API deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) ensureBuildAPIOAuthSecret(
	ctx context.Context,
	owner *automotivev1alpha1.OperatorConfig,
) error {
	secretName := "ado-build-api-oauth-proxy"
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: owner.Namespace}, secret)

	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get secret %s: %w", secretName, err)
		}
		// Secret doesn't exist, create it
		secret = r.buildOAuthSecret(secretName, owner.Namespace)
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret %s: %w", secretName, err)
		}
		r.Log.Info("Created OAuth secret", "name", secretName)
	}
	return nil
}

func (r *OperatorConfigReconciler) updateBuildAPIServiceAccountAnnotation(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	sa := &corev1.ServiceAccount{}
	if err := r.Get(ctx, client.ObjectKey{Name: "ado-operator", Namespace: owner.Namespace}, sa); err != nil {
		return fmt.Errorf("failed to get service account: %w", err)
	}

	if sa.Annotations == nil {
		sa.Annotations = make(map[string]string)
	}

	buildAPIAnnotation := `{"kind":"OAuthRedirectReference","apiVersion":"v1",` +
		`"reference":{"kind":"Route","name":"ado-build-api"}}`
	annotationKey := "serviceaccounts.openshift.io/oauth-redirectreference.buildapi"
	if sa.Annotations[annotationKey] == buildAPIAnnotation {
		return nil // Already set
	}

	sa.Annotations["serviceaccounts.openshift.io/oauth-redirectreference.buildapi"] = buildAPIAnnotation
	if err := r.Update(ctx, sa); err != nil {
		return fmt.Errorf("failed to update service account: %w", err)
	}
	r.Log.Info("Updated ServiceAccount with build-api OAuth annotation")
	return nil
}

func (r *OperatorConfigReconciler) cleanupBuildAPI(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	// Delete build-api deployment
	deployment := &appsv1.Deployment{}
	deployment.Name = buildAPIName
	deployment.Namespace = config.Namespace
	if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api deployment: %w", err)
	}

	// Delete build-api service
	service := &corev1.Service{}
	service.Name = buildAPIName
	service.Namespace = config.Namespace
	if err := r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api service: %w", err)
	}

	// Delete build-api route (OpenShift only)
	route := &routev1.Route{}
	route.Name = buildAPIName
	route.Namespace = config.Namespace
	if err := r.Delete(ctx, route); err != nil && !errors.IsNotFound(err) && !isNoMatchError(err) {
		r.Log.Error(err, "Failed to delete build-api route (ignoring, expected on non-OpenShift clusters)")
	}

	// Delete build-api ingress
	ingress := &networkingv1.Ingress{}
	ingress.Name = buildAPIName
	ingress.Namespace = config.Namespace
	if err := r.Delete(ctx, ingress); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api ingress: %w", err)
	}

	// Delete build-api OAuth secret
	secret := &corev1.Secret{}
	secret.Name = "ado-build-api-oauth-proxy"
	secret.Namespace = config.Namespace
	if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api OAuth secret: %w", err)
	}

	// Delete build-api internal JWT secret
	jwtSecret := &corev1.Secret{}
	jwtSecret.Name = internalJWTSecretName
	jwtSecret.Namespace = config.Namespace
	if err := r.Delete(ctx, jwtSecret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api internal JWT secret: %w", err)
	}

	return nil
}

const internalJWTExpiryThreshold = 30 * 24 * time.Hour // Regenerate when within 30 days of expiry

func (r *OperatorConfigReconciler) ensureBuildAPIInternalJWTSecret(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: internalJWTSecretName, Namespace: owner.Namespace}, secret)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get internal JWT secret %s: %w", internalJWTSecretName, err)
		}
		// Secret doesn't exist, create it
		secret, err = r.buildInternalJWTSecret(internalJWTSecretName, owner.Namespace)
		if err != nil {
			return fmt.Errorf("failed to build internal JWT secret: %w", err)
		}
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create internal JWT secret %s: %w", internalJWTSecretName, err)
		}
		r.Log.Info("Created internal JWT secret", "name", internalJWTSecretName)
		return nil
	}
	// Secret exists: check expiry and regenerate if expired or within threshold
	expiresAtBytes, ok := secret.Data["expires-at"]
	if !ok {
		// No expires-at (old secret format), regenerate
		r.Log.Info("Internal JWT secret missing expires-at, regenerating", "name", internalJWTSecretName)
		return r.regenerateInternalJWTSecret(ctx, owner)
	}
	expiresAt, err := time.Parse(time.RFC3339, string(expiresAtBytes))
	if err != nil {
		r.Log.Info("Internal JWT secret has invalid expires-at, regenerating", "name", internalJWTSecretName, "error", err)
		return r.regenerateInternalJWTSecret(ctx, owner)
	}
	if time.Until(expiresAt) < internalJWTExpiryThreshold {
		r.Log.Info("Internal JWT secret expired or expiring soon, regenerating", "name", internalJWTSecretName, "expiresAt", expiresAt)
		return r.regenerateInternalJWTSecret(ctx, owner)
	}
	return nil
}

func (r *OperatorConfigReconciler) regenerateInternalJWTSecret(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	secret, err := r.buildInternalJWTSecret(internalJWTSecretName, owner.Namespace)
	if err != nil {
		return fmt.Errorf("failed to build internal JWT secret: %w", err)
	}
	existing := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: internalJWTSecretName, Namespace: owner.Namespace}, existing); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		return r.Create(ctx, secret)
	}
	secret.SetResourceVersion(existing.GetResourceVersion())
	if err := r.Update(ctx, secret); err != nil {
		return fmt.Errorf("failed to update internal JWT secret %s: %w", internalJWTSecretName, err)
	}
	r.Log.Info("Regenerated internal JWT secret", "name", internalJWTSecretName)
	return nil
}

func (r *OperatorConfigReconciler) createOrUpdate(
	ctx context.Context,
	obj client.Object,
	_ *automotivev1alpha1.OperatorConfig,
) error {
	// Try to get the existing resource
	key := client.ObjectKeyFromObject(obj)
	existing := obj.DeepCopyObject().(client.Object)

	err := r.Get(ctx, key, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new resource
			return r.Create(ctx, obj)
		}
		return err
	}

	// Skip update if resource is marked as unmanaged
	if annotations := existing.GetAnnotations(); annotations != nil && annotations[unmanagedAnnotationKey] == unmanagedAnnotationTrue {
		r.Log.Info("Skipping update for unmanaged resource", "name", obj.GetName(), "kind", obj.GetObjectKind().GroupVersionKind().Kind)
		return nil
	}

	// Resource exists, update it
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

func (r *OperatorConfigReconciler) deployOSBuilds(
	ctx context.Context,
	config *automotivev1alpha1.OperatorConfig,
) error {
	r.Log.Info("Starting OSBuilds deployment")

	// Deploy build controller (runs ImageBuild/Image/CatalogImage controllers)
	if err := r.deployBuildController(ctx, config); err != nil {
		return fmt.Errorf("failed to deploy build controller: %w", err)
	}

	// Deploy build-api (required for CLI access to builds)
	if err := r.deployBuildAPI(ctx, config); err != nil {
		return fmt.Errorf("failed to deploy build-api: %w", err)
	}

	// Convert OSBuildsConfig to BuildConfig for task generation
	var buildConfig *tasks.BuildConfig
	if config.Spec.OSBuilds != nil {
		buildConfig = &tasks.BuildConfig{
			UseMemoryVolumes:          config.Spec.OSBuilds.UseMemoryVolumes,
			UseMemoryContainerStorage: config.Spec.OSBuilds.UseMemoryContainerStorage,
			MemoryVolumeSize:          config.Spec.OSBuilds.MemoryVolumeSize,
			PVCSize:                   config.Spec.OSBuilds.PVCSize,
			RuntimeClassName:          config.Spec.OSBuilds.RuntimeClassName,
		}
	}

	// Create target defaults ConfigMap (architecture, partition rules, etc.)
	if err := r.createOrUpdateTargetDefaults(ctx, config); err != nil {
		r.Log.Error(err, "Failed to create target defaults ConfigMap")
		return fmt.Errorf("failed to create target defaults ConfigMap: %w", err)
	}

	// Generate and deploy Tekton tasks
	tektonTasks := []*tektonv1.Task{
		tasks.GenerateBuildAutomotiveImageTask(config.Namespace, buildConfig, ""),
		tasks.GeneratePushArtifactRegistryTask(config.Namespace),
		tasks.GeneratePrepareBuilderTask(config.Namespace, buildConfig),
		tasks.GenerateFlashTask(config.Namespace),
	}

	for _, task := range tektonTasks {
		task.Labels["automotive.sdv.cloud.redhat.com/managed-by"] = config.Name

		if err := controllerutil.SetControllerReference(config, task, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference on task: %w", err)
		}

		if err := r.createOrUpdateTask(ctx, task); err != nil {
			r.Log.Error(err, "Failed to create/update Task", "task", task.Name)
			return fmt.Errorf("failed to create/update task %s: %w", task.Name, err)
		}

		r.Log.Info("Task created/updated successfully", "name", task.Name)
	}

	// Generate and deploy Tekton pipeline
	pipeline := tasks.GenerateTektonPipeline("automotive-build-pipeline", config.Namespace)
	pipeline.Labels["automotive.sdv.cloud.redhat.com/managed-by"] = config.Name

	if err := controllerutil.SetControllerReference(config, pipeline, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on pipeline: %w", err)
	}

	if err := r.createOrUpdatePipeline(ctx, pipeline); err != nil {
		r.Log.Error(err, "Failed to create/update Pipeline")
		return fmt.Errorf("failed to create/update pipeline: %w", err)
	}

	r.Log.Info("OSBuilds deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) createOrUpdateTargetDefaults(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aib-target-defaults",
			Namespace: owner.Namespace,
		},
		Data: map[string]string{
			"target-defaults.yaml": targetDefaultsYAML,
		},
	}

	if err := controllerutil.SetControllerReference(owner, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Only create the ConfigMap if it doesn't exist; never overwrite user changes
	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, client.ObjectKeyFromObject(configMap), existing)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, configMap)
		}
		return err
	}

	return nil
}

func (r *OperatorConfigReconciler) deployBuildController(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	// In "all" mode, build controllers run in-process; no separate deployment needed.
	if os.Getenv("OPERATOR_MODE") == "all" {
		r.Log.Info("Skipping build controller deployment (running in 'all' mode)")
		return nil
	}
	r.Log.Info("Starting build controller deployment")

	// Create/update ServiceAccount
	sa := r.buildBuildControllerServiceAccount(config.Namespace)
	if err := r.createOrUpdate(ctx, sa, config); err != nil {
		return fmt.Errorf("failed to create/update build controller service account: %w", err)
	}

	// Create/update ClusterRole
	clusterRole := r.buildBuildControllerClusterRole()
	if err := r.createOrUpdate(ctx, clusterRole, config); err != nil {
		return fmt.Errorf("failed to create/update build controller cluster role: %w", err)
	}

	// Create/update ClusterRoleBinding
	clusterRoleBinding := r.buildBuildControllerClusterRoleBinding(config.Namespace)
	if err := r.createOrUpdate(ctx, clusterRoleBinding, config); err != nil {
		return fmt.Errorf("failed to create/update build controller cluster role binding: %w", err)
	}

	// Create/update leader election Role
	leRole := r.buildBuildControllerLeaderElectionRole(config.Namespace)
	if err := r.createOrUpdate(ctx, leRole, config); err != nil {
		return fmt.Errorf("failed to create/update build controller leader election role: %w", err)
	}

	// Create/update leader election RoleBinding
	leRoleBinding := r.buildBuildControllerLeaderElectionRoleBinding(config.Namespace)
	if err := r.createOrUpdate(ctx, leRoleBinding, config); err != nil {
		return fmt.Errorf("failed to create/update build controller leader election role binding: %w", err)
	}

	// Create/update Deployment with owner reference for reconciliation
	deployment := r.buildBuildControllerDeployment(config.Namespace)
	if err := controllerutil.SetControllerReference(config, deployment, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on build controller deployment: %w", err)
	}
	if err := r.createOrUpdate(ctx, deployment, config); err != nil {
		return fmt.Errorf("failed to create/update build controller deployment: %w", err)
	}

	r.Log.Info("Build controller deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) cleanupBuildController(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	// In "all" mode, build controllers run in-process; nothing to clean up.
	if os.Getenv("OPERATOR_MODE") == "all" {
		r.Log.Info("Skipping build controller cleanup (running in 'all' mode)")
		return nil
	}
	r.Log.Info("Cleaning up build controller resources")

	// Delete Deployment
	deployment := &appsv1.Deployment{}
	deployment.Name = buildControllerName
	deployment.Namespace = config.Namespace
	if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build controller deployment: %w", err)
	}

	// Delete ServiceAccount
	sa := &corev1.ServiceAccount{}
	sa.Name = buildControllerName
	sa.Namespace = config.Namespace
	if err := r.Delete(ctx, sa); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build controller service account: %w", err)
	}

	// Delete ClusterRole
	clusterRole := &rbacv1.ClusterRole{}
	clusterRole.Name = buildControllerName
	if err := r.Delete(ctx, clusterRole); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build controller cluster role: %w", err)
	}

	// Delete ClusterRoleBinding
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	clusterRoleBinding.Name = buildControllerName
	if err := r.Delete(ctx, clusterRoleBinding); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build controller cluster role binding: %w", err)
	}

	// Delete leader election Role
	leRole := &rbacv1.Role{}
	leRole.Name = buildControllerName + "-leader-election"
	leRole.Namespace = config.Namespace
	if err := r.Delete(ctx, leRole); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build controller leader election role: %w", err)
	}

	// Delete leader election RoleBinding
	leRoleBinding := &rbacv1.RoleBinding{}
	leRoleBinding.Name = buildControllerName + "-leader-election"
	leRoleBinding.Namespace = config.Namespace
	if err := r.Delete(ctx, leRoleBinding); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build controller leader election role binding: %w", err)
	}

	r.Log.Info("Build controller cleanup completed")
	return nil
}

func (r *OperatorConfigReconciler) cleanupOSBuilds(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Cleaning up OSBuilds resources")

	// Delete target defaults ConfigMap
	configMap := &corev1.ConfigMap{}
	configMap.Name = "aib-target-defaults"
	configMap.Namespace = config.Namespace
	if err := r.Delete(ctx, configMap); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete target defaults ConfigMap: %w", err)
	}
	r.Log.Info("Target defaults ConfigMap deleted")

	// Delete Tekton tasks
	taskNames := []string{"build-automotive-image", "push-artifact-registry", "prepare-builder", "flash-image"}
	for _, taskName := range taskNames {
		task := &tektonv1.Task{}
		task.Name = taskName
		task.Namespace = config.Namespace
		if err := r.Delete(ctx, task); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete task %s: %w", taskName, err)
		}
		r.Log.Info("Task deleted", "name", taskName)
	}

	// Delete Tekton pipeline
	pipeline := &tektonv1.Pipeline{}
	pipeline.Name = "automotive-build-pipeline"
	pipeline.Namespace = config.Namespace
	if err := r.Delete(ctx, pipeline); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete pipeline: %w", err)
	}
	r.Log.Info("Pipeline deleted")

	// Cleanup build-api
	if err := r.cleanupBuildAPI(ctx, config); err != nil {
		return fmt.Errorf("failed to cleanup build-api: %w", err)
	}

	// Cleanup build controller
	if err := r.cleanupBuildController(ctx, config); err != nil {
		return fmt.Errorf("failed to cleanup build controller: %w", err)
	}

	r.Log.Info("OSBuilds cleanup completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) createOrUpdateTask(ctx context.Context, task *tektonv1.Task) error {
	existingTask := &tektonv1.Task{}
	err := r.Get(ctx, client.ObjectKey{Name: task.Name, Namespace: task.Namespace}, existingTask)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get Task: %w", err)
		}
		return r.Create(ctx, task)
	}

	// Skip update if task is marked as unmanaged
	if existingTask.Annotations != nil && existingTask.Annotations[unmanagedAnnotationKey] == unmanagedAnnotationTrue {
		r.Log.Info("Skipping update for unmanaged task", "name", task.Name)
		return nil
	}

	task.ResourceVersion = existingTask.ResourceVersion
	return r.Update(ctx, task)
}

func (r *OperatorConfigReconciler) createOrUpdatePipeline(ctx context.Context, pipeline *tektonv1.Pipeline) error {
	existingPipeline := &tektonv1.Pipeline{}
	err := r.Get(ctx, client.ObjectKey{Name: pipeline.Name, Namespace: pipeline.Namespace}, existingPipeline)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get Pipeline: %w", err)
		}
		return r.Create(ctx, pipeline)
	}

	// Skip update if pipeline is marked as unmanaged
	if existingPipeline.Annotations != nil && existingPipeline.Annotations[unmanagedAnnotationKey] == unmanagedAnnotationTrue {
		r.Log.Info("Skipping update for unmanaged pipeline", "name", pipeline.Name)
		return nil
	}

	pipeline.ResourceVersion = existingPipeline.ResourceVersion
	return r.Update(ctx, pipeline)
}

// SetupWithManager sets up the controller with the Manager.
func (r *OperatorConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.OperatorConfig{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&tektonv1.Task{}).
		Owns(&tektonv1.Pipeline{}).
		Complete(r)
}
