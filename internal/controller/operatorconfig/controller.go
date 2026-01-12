package operatorconfig

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

const (
	operatorNamespace = "automotive-dev-operator-system"
	finalizerName     = "operatorconfig.automotive.sdv.cloud.redhat.com/finalizer"
)

// isNoMatchError checks if error is "no matches for kind" error (CRD doesn't exist)
func isNoMatchError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return errMsg == "no matches for kind \"Route\" in version \"route.openshift.io/v1\"" ||
		errMsg == "no matches for kind \"Ingress\" in version \"networking.k8s.io/v1\""
}

// detectOpenShift checks if we're running on OpenShift by looking for OpenShift-specific APIs
func (r *OperatorConfigReconciler) detectOpenShift(ctx context.Context) bool {
	if r.IsOpenShift != nil {
		return *r.IsOpenShift
	}

	route := &routev1.Route{}
	route.Name = "test"
	route.Namespace = "default"
	err := r.Get(ctx, client.ObjectKey{Name: "test", Namespace: "default"}, route)

	isOpenShift := !isNoMatchError(err)
	r.IsOpenShift = &isOpenShift
	r.Log.Info("Platform detected", "isOpenShift", isOpenShift)
	return isOpenShift
}

// OperatorConfigReconciler reconciles an OperatorConfig object
type OperatorConfigReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	Log         logr.Logger
	IsOpenShift *bool
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;pipelines;pipelineruns,verbs=get;list;watch;create;update;patch;delete

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
		if err := r.cleanupWebUI(ctx); err != nil {
			log.Error(err, "Failed to cleanup WebUI")
			return ctrl.Result{}, err
		}
		if err := r.cleanupOSBuilds(ctx); err != nil {
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

	// Reconcile WebUI
	log.Info("Processing WebUI configuration", "webUI", config.Spec.WebUI, "generation", config.Generation)
	statusChanged := false
	if config.Spec.WebUI {
		if err := r.deployWebUI(ctx, config); err != nil {
			log.Error(err, "Failed to deploy WebUI")
			if config.Status.Phase != "Failed" || config.Status.WebUIDeployed {
				config.Status.Phase = "Failed"
				config.Status.Message = fmt.Sprintf("Failed to deploy WebUI: %v", err)
				config.Status.WebUIDeployed = false
				statusChanged = true
			}
			if statusChanged {
				_ = r.Status().Update(ctx, config)
			}
			return ctrl.Result{}, err
		}
		if config.Status.Phase != "Ready" || !config.Status.WebUIDeployed {
			config.Status.Phase = "Ready"
			config.Status.Message = "WebUI deployed successfully"
			config.Status.WebUIDeployed = true
			statusChanged = true
		}
	} else {
		if err := r.cleanupWebUI(ctx); err != nil {
			log.Error(err, "Failed to cleanup WebUI")
			if config.Status.Phase != "Failed" {
				config.Status.Phase = "Failed"
				config.Status.Message = fmt.Sprintf("Failed to cleanup WebUI: %v", err)
				statusChanged = true
			}
			if statusChanged {
				_ = r.Status().Update(ctx, config)
			}
			return ctrl.Result{}, err
		}
		if config.Status.Phase != "Ready" || config.Status.WebUIDeployed {
			config.Status.Phase = "Ready"
			config.Status.Message = "WebUI disabled"
			config.Status.WebUIDeployed = false
			statusChanged = true
		}
	}

	// Reconcile OSBuilds
	log.Info("Processing OSBuilds configuration", "osBuilds", config.Spec.OSBuilds, "generation", config.Generation)
	if config.Spec.OSBuilds != nil && config.Spec.OSBuilds.Enabled {
		if err := r.deployOSBuilds(ctx, config); err != nil {
			log.Error(err, "Failed to deploy OSBuilds")
			if config.Status.Phase != "Failed" || config.Status.OSBuildsDeployed {
				config.Status.Phase = "Failed"
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
		if err := r.cleanupOSBuilds(ctx); err != nil {
			log.Error(err, "Failed to cleanup OSBuilds")
			if config.Status.Phase != "Failed" {
				config.Status.Phase = "Failed"
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

	if statusChanged {
		log.Info("Updating status", "phase", config.Status.Phase, "webUIDeployed", config.Status.WebUIDeployed, "osBuildsDeployed", config.Status.OSBuildsDeployed)
		if err := r.Status().Update(ctx, config); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
	}

	log.Info("=== Reconciliation completed successfully ===")
	return ctrl.Result{}, nil
}

func (r *OperatorConfigReconciler) deployWebUI(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Starting WebUI deployment")

	// Create cookie secrets for OAuth proxies
	r.Log.Info("Ensuring OAuth secrets")
	if err := r.ensureOAuthSecrets(ctx, owner); err != nil {
		r.Log.Error(err, "Failed to ensure OAuth secrets")
		return fmt.Errorf("failed to ensure OAuth secrets: %w", err)
	}
	r.Log.Info("OAuth secrets ensured successfully")

	// Update ServiceAccount with OAuth redirect annotations
	r.Log.Info("Updating ServiceAccount OAuth annotations")
	if err := r.updateServiceAccountOAuthAnnotations(ctx); err != nil {
		r.Log.Error(err, "Failed to update ServiceAccount OAuth annotations")
		return fmt.Errorf("failed to update ServiceAccount OAuth annotations: %w", err)
	}
	r.Log.Info("ServiceAccount OAuth annotations updated successfully")

	// Create/update nginx ConfigMap
	r.Log.Info("Creating/updating nginx ConfigMap")
	nginxConfigMap := r.buildWebUINginxConfigMap()
	if err := r.createOrUpdate(ctx, nginxConfigMap, owner); err != nil {
		r.Log.Error(err, "Failed to create/update nginx configmap")
		return fmt.Errorf("failed to create/update nginx configmap: %w", err)
	}
	r.Log.Info("Nginx ConfigMap created/updated successfully")

	// Create/update deployment
	r.Log.Info("Creating/updating webui deployment")
	isOpenShift := r.detectOpenShift(ctx)
	deployment := r.buildWebUIDeployment(isOpenShift)
	if err := r.createOrUpdate(ctx, deployment, owner); err != nil {
		r.Log.Error(err, "Failed to create/update webui deployment")
		return fmt.Errorf("failed to create/update webui deployment: %w", err)
	}
	r.Log.Info("WebUI deployment created/updated successfully")

	// Create/update service
	r.Log.Info("Creating/updating webui service")
	service := r.buildWebUIService(isOpenShift)
	if err := r.createOrUpdate(ctx, service, owner); err != nil {
		r.Log.Error(err, "Failed to create/update webui service")
		return fmt.Errorf("failed to create/update webui service: %w", err)
	}
	r.Log.Info("WebUI service created/updated successfully")

	// Create/update route (OpenShift)
	r.Log.Info("Creating/updating webui route")
	route := r.buildWebUIRoute()
	if err := r.createOrUpdate(ctx, route, owner); err != nil {
		r.Log.Error(err, "Failed to create/update webui route (this is expected on non-OpenShift clusters)")
	} else {
		r.Log.Info("WebUI route created/updated successfully")
	}

	// Create/update ingress (Kubernetes)
	r.Log.Info("Creating/updating webui ingress")
	ingress := r.buildWebUIIngress()
	if err := r.createOrUpdate(ctx, ingress, owner); err != nil {
		r.Log.Error(err, "Failed to create/update webui ingress (this is expected if ingress controller is not installed)")
	} else {
		r.Log.Info("WebUI ingress created/updated successfully")
	}

	r.Log.Info("WebUI deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) deployBuildAPI(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Starting Build-API deployment")

	// Ensure OAuth secret for build-api
	if err := r.ensureBuildAPIOAuthSecret(ctx, owner); err != nil {
		r.Log.Error(err, "Failed to ensure build-api OAuth secret")
		return fmt.Errorf("failed to ensure build-api OAuth secret: %w", err)
	}

	// Update ServiceAccount with build-api OAuth redirect annotation
	if err := r.updateBuildAPIServiceAccountAnnotation(ctx); err != nil {
		r.Log.Error(err, "Failed to update ServiceAccount build-api OAuth annotation")
		return fmt.Errorf("failed to update ServiceAccount build-api OAuth annotation: %w", err)
	}

	isOpenShift := r.detectOpenShift(ctx)

	// Create/update build-api deployment
	r.Log.Info("Creating/updating build-api deployment")
	buildAPIDeployment := r.buildBuildAPIDeployment(isOpenShift)
	if err := r.createOrUpdate(ctx, buildAPIDeployment, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api deployment")
		return fmt.Errorf("failed to create/update build-api deployment: %w", err)
	}
	r.Log.Info("Build-API deployment created/updated successfully")

	// Create/update build-api service
	r.Log.Info("Creating/updating build-api service")
	buildAPIService := r.buildBuildAPIService(isOpenShift)
	if err := r.createOrUpdate(ctx, buildAPIService, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api service")
		return fmt.Errorf("failed to create/update build-api service: %w", err)
	}
	r.Log.Info("Build-API service created/updated successfully")

	// Create/update build-api route (OpenShift)
	r.Log.Info("Creating/updating build-api route")
	buildAPIRoute := r.buildBuildAPIRoute()
	if err := r.createOrUpdate(ctx, buildAPIRoute, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api route (this is expected on non-OpenShift clusters)")
	} else {
		r.Log.Info("Build-API route created/updated successfully")
	}

	// Create/update build-api ingress (Kubernetes)
	r.Log.Info("Creating/updating build-api ingress")
	buildAPIIngress := r.buildBuildAPIIngress()
	if err := r.createOrUpdate(ctx, buildAPIIngress, owner); err != nil {
		r.Log.Error(err, "Failed to create/update build-api ingress (this is expected if ingress controller is not installed)")
	} else {
		r.Log.Info("Build-API ingress created/updated successfully")
	}

	r.Log.Info("Build-API deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) ensureBuildAPIOAuthSecret(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	secretName := "ado-build-api-oauth-proxy"
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: operatorNamespace}, secret)

	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get secret %s: %w", secretName, err)
		}
		// Secret doesn't exist, create it
		secret = r.buildOAuthSecret(secretName)
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret %s: %w", secretName, err)
		}
		r.Log.Info("Created OAuth secret", "name", secretName)
	}
	return nil
}

func (r *OperatorConfigReconciler) updateBuildAPIServiceAccountAnnotation(ctx context.Context) error {
	sa := &corev1.ServiceAccount{}
	if err := r.Get(ctx, client.ObjectKey{Name: "ado-controller-manager", Namespace: operatorNamespace}, sa); err != nil {
		return fmt.Errorf("failed to get service account: %w", err)
	}

	if sa.Annotations == nil {
		sa.Annotations = make(map[string]string)
	}

	buildAPIAnnotation := `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"ado-build-api"}}`
	if sa.Annotations["serviceaccounts.openshift.io/oauth-redirectreference.buildapi"] == buildAPIAnnotation {
		return nil // Already set
	}

	sa.Annotations["serviceaccounts.openshift.io/oauth-redirectreference.buildapi"] = buildAPIAnnotation
	if err := r.Update(ctx, sa); err != nil {
		return fmt.Errorf("failed to update service account: %w", err)
	}
	r.Log.Info("Updated ServiceAccount with build-api OAuth annotation")
	return nil
}

func (r *OperatorConfigReconciler) ensureOAuthSecrets(ctx context.Context, owner *automotivev1alpha1.OperatorConfig) error {
	secrets := []string{"ado-webui-oauth-proxy", "ado-build-api-oauth-proxy"}

	for _, secretName := range secrets {
		secret := &corev1.Secret{}
		err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: operatorNamespace}, secret)

		if err != nil {
			if !errors.IsNotFound(err) {
				return fmt.Errorf("failed to get secret %s: %w", secretName, err)
			}

			// Secret doesn't exist, create it
			secret = r.buildOAuthSecret(secretName)
			// Don't set controller reference - cleanup handled by finalizer
			if err := r.Create(ctx, secret); err != nil {
				return fmt.Errorf("failed to create secret %s: %w", secretName, err)
			}
			r.Log.Info("Created OAuth secret", "name", secretName)
		}
	}

	return nil
}

func (r *OperatorConfigReconciler) updateServiceAccountOAuthAnnotations(ctx context.Context) error {
	sa := &corev1.ServiceAccount{}
	err := r.Get(ctx, client.ObjectKey{Name: "ado-controller-manager", Namespace: operatorNamespace}, sa)
	if err != nil {
		if errors.IsNotFound(err) {
			// ServiceAccount doesn't exist (likely running locally in dev mode)
			r.Log.Info("ServiceAccount not found, skipping OAuth annotation update (running locally?)")
			return nil
		}
		return fmt.Errorf("failed to get ServiceAccount: %w", err)
	}

	if sa.Annotations == nil {
		sa.Annotations = make(map[string]string)
	}

	annotations := map[string]string{
		"serviceaccounts.openshift.io/oauth-redirectreference.webui":    `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"ado-webui"}}`,
		"serviceaccounts.openshift.io/oauth-redirectreference.buildapi": `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"ado-build-api"}}`,
	}

	updated := false
	for key, value := range annotations {
		if sa.Annotations[key] != value {
			sa.Annotations[key] = value
			updated = true
		}
	}

	if updated {
		if err := r.Update(ctx, sa); err != nil {
			return fmt.Errorf("failed to update ServiceAccount annotations: %w", err)
		}
		r.Log.Info("Updated ServiceAccount OAuth annotations")
	}

	return nil
}

func (r *OperatorConfigReconciler) cleanupWebUI(ctx context.Context) error {
	// Delete deployment
	deployment := &appsv1.Deployment{}
	deployment.Name = "ado-webui"
	deployment.Namespace = operatorNamespace
	if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete webui deployment: %w", err)
	}

	// Delete service
	service := &corev1.Service{}
	service.Name = "ado-webui"
	service.Namespace = operatorNamespace
	if err := r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete webui service: %w", err)
	}

	// Delete route
	route := &routev1.Route{}
	route.Name = "ado-webui"
	route.Namespace = operatorNamespace
	if err := r.Delete(ctx, route); err != nil && !errors.IsNotFound(err) && !isNoMatchError(err) {
		r.Log.Error(err, "Failed to delete webui route (ignoring, expected on non-OpenShift clusters)")
	}

	// Delete ingress
	ingress := &networkingv1.Ingress{}
	ingress.Name = "ado-webui"
	ingress.Namespace = operatorNamespace
	if err := r.Delete(ctx, ingress); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete webui ingress: %w", err)
	}

	// Delete nginx ConfigMap
	configMap := &corev1.ConfigMap{}
	configMap.Name = "ado-webui-nginx-config"
	configMap.Namespace = operatorNamespace
	if err := r.Delete(ctx, configMap); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete nginx configmap: %w", err)
	}

	// Delete WebUI OAuth secret
	secrets := []string{"ado-webui-oauth-proxy"}
	for _, secretName := range secrets {
		secret := &corev1.Secret{}
		secret.Name = secretName
		secret.Namespace = operatorNamespace
		if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete secret %s: %w", secretName, err)
		}
	}

	return nil
}

func (r *OperatorConfigReconciler) cleanupBuildAPI(ctx context.Context) error {
	// Delete build-api deployment
	deployment := &appsv1.Deployment{}
	deployment.Name = "ado-build-api"
	deployment.Namespace = operatorNamespace
	if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api deployment: %w", err)
	}

	// Delete build-api service
	service := &corev1.Service{}
	service.Name = "ado-build-api"
	service.Namespace = operatorNamespace
	if err := r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api service: %w", err)
	}

	// Delete build-api route (OpenShift only)
	route := &routev1.Route{}
	route.Name = "ado-build-api"
	route.Namespace = operatorNamespace
	if err := r.Delete(ctx, route); err != nil && !errors.IsNotFound(err) && !isNoMatchError(err) {
		r.Log.Error(err, "Failed to delete build-api route (ignoring, expected on non-OpenShift clusters)")
	}

	// Delete build-api ingress
	ingress := &networkingv1.Ingress{}
	ingress.Name = "ado-build-api"
	ingress.Namespace = operatorNamespace
	if err := r.Delete(ctx, ingress); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api ingress: %w", err)
	}

	// Delete build-api OAuth secret
	secret := &corev1.Secret{}
	secret.Name = "ado-build-api-oauth-proxy"
	secret.Namespace = operatorNamespace
	if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete build-api OAuth secret: %w", err)
	}

	return nil
}

func (r *OperatorConfigReconciler) createOrUpdate(ctx context.Context, obj client.Object, owner *automotivev1alpha1.OperatorConfig) error {
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

	// Resource exists, update it
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

func (r *OperatorConfigReconciler) deployOSBuilds(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Starting OSBuilds deployment")

	// Deploy build-api (required for CLI access to builds)
	if err := r.deployBuildAPI(ctx, config); err != nil {
		return fmt.Errorf("failed to deploy build-api: %w", err)
	}

	// Convert OSBuildsConfig to BuildConfig for task generation
	var buildConfig *tasks.BuildConfig
	if config.Spec.OSBuilds != nil {
		buildConfig = &tasks.BuildConfig{
			UseMemoryVolumes: config.Spec.OSBuilds.UseMemoryVolumes,
			MemoryVolumeSize: config.Spec.OSBuilds.MemoryVolumeSize,
			PVCSize:          config.Spec.OSBuilds.PVCSize,
			RuntimeClassName: config.Spec.OSBuilds.RuntimeClassName,
			ServeExpiryHours: config.Spec.OSBuilds.ServeExpiryHours,
		}
	}

	// Generate and deploy Tekton tasks
	tektonTasks := []*tektonv1.Task{
		tasks.GenerateBuildAutomotiveImageTask(operatorNamespace, buildConfig, ""),
		tasks.GeneratePushArtifactRegistryTask(operatorNamespace),
		tasks.GeneratePrepareBuilderTask(operatorNamespace),
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
	pipeline := tasks.GenerateTektonPipeline("automotive-build-pipeline", operatorNamespace)
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

func (r *OperatorConfigReconciler) cleanupOSBuilds(ctx context.Context) error {
	r.Log.Info("Cleaning up OSBuilds resources")

	// Delete Tekton tasks
	taskNames := []string{"build-automotive-image", "push-artifact-registry"}
	for _, taskName := range taskNames {
		task := &tektonv1.Task{}
		task.Name = taskName
		task.Namespace = operatorNamespace
		if err := r.Delete(ctx, task); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete task %s: %w", taskName, err)
		}
		r.Log.Info("Task deleted", "name", taskName)
	}

	// Delete Tekton pipeline
	pipeline := &tektonv1.Pipeline{}
	pipeline.Name = "automotive-build-pipeline"
	pipeline.Namespace = operatorNamespace
	if err := r.Delete(ctx, pipeline); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete pipeline: %w", err)
	}
	r.Log.Info("Pipeline deleted")

	// Cleanup build-api
	if err := r.cleanupBuildAPI(ctx); err != nil {
		return fmt.Errorf("failed to cleanup build-api: %w", err)
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

	pipeline.ResourceVersion = existingPipeline.ResourceVersion
	return r.Update(ctx, pipeline)
}

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
