package operatorconfig

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

// OperatorConfigReconciler reconciles an OperatorConfig object
type OperatorConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=operatorconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;pipelines;pipelineruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=console.openshift.io,resources=consoleplugins,verbs=get;list;watch;create;update;patch;delete

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
		if err := r.cleanupOSBuilds(ctx); err != nil {
			log.Error(err, "Failed to cleanup OSBuilds")
			return ctrl.Result{}, err
		}
		if err := r.cleanupConsolePlugin(ctx); err != nil {
			log.Error(err, "Failed to cleanup ConsolePlugin")
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

	// Always deploy build-api
	log.Info("Deploying build-api")
	if err := r.deployBuildAPI(ctx, config); err != nil {
		log.Error(err, "Failed to deploy build-api")
		config.Status.Phase = "Failed"
		config.Status.Message = fmt.Sprintf("Failed to deploy build-api: %v", err)
		_ = r.Status().Update(ctx, config)
		return ctrl.Result{}, err
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

	// Reconcile ConsolePlugin
	log.Info("Processing ConsolePlugin configuration", "consolePlugin", config.Spec.ConsolePlugin, "generation", config.Generation)
	if config.Spec.ConsolePlugin != nil && config.Spec.ConsolePlugin.Enabled {
		if err := r.deployConsolePlugin(ctx, config); err != nil {
			log.Error(err, "Failed to deploy ConsolePlugin")
			if config.Status.Phase != "Failed" || config.Status.ConsolePluginDeployed {
				config.Status.Phase = "Failed"
				config.Status.Message = fmt.Sprintf("Failed to deploy ConsolePlugin: %v", err)
				config.Status.ConsolePluginDeployed = false
				statusChanged = true
			}
			if statusChanged {
				_ = r.Status().Update(ctx, config)
			}
			return ctrl.Result{}, err
		}
		if !config.Status.ConsolePluginDeployed {
			config.Status.ConsolePluginDeployed = true
			config.Status.Phase = "Ready"
			config.Status.Message = "ConsolePlugin deployed successfully"
			statusChanged = true
		}
	} else {
		if err := r.cleanupConsolePlugin(ctx); err != nil {
			log.Error(err, "Failed to cleanup ConsolePlugin")
			if config.Status.Phase != "Failed" {
				config.Status.Phase = "Failed"
				config.Status.Message = fmt.Sprintf("Failed to cleanup ConsolePlugin: %v", err)
				statusChanged = true
			}
			if statusChanged {
				_ = r.Status().Update(ctx, config)
			}
			return ctrl.Result{}, err
		}
		if config.Status.ConsolePluginDeployed {
			config.Status.ConsolePluginDeployed = false
			statusChanged = true
		}
	}

	if statusChanged {
		log.Info("Updating status", "phase", config.Status.Phase, "osBuildsDeployed", config.Status.OSBuildsDeployed, "consolePluginDeployed", config.Status.ConsolePluginDeployed)
		if err := r.Status().Update(ctx, config); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
	}

	log.Info("=== Reconciliation completed successfully ===")
	return ctrl.Result{}, nil
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

	// Skip update if task is marked as unmanaged
	if existingTask.Annotations != nil && existingTask.Annotations["automotive.sdv.cloud.redhat.com/unmanaged"] == "true" {
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
	if existingPipeline.Annotations != nil && existingPipeline.Annotations["automotive.sdv.cloud.redhat.com/unmanaged"] == "true" {
		r.Log.Info("Skipping update for unmanaged pipeline", "name", pipeline.Name)
		return nil
	}

	pipeline.ResourceVersion = existingPipeline.ResourceVersion
	return r.Update(ctx, pipeline)
}

func (r *OperatorConfigReconciler) deployBuildAPI(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Starting build-api deployment")

	// Create/update nginx configuration
	nginxConfig := r.buildBuildAPINginxConfigMap()
	if err := r.createOrUpdate(ctx, nginxConfig, config); err != nil {
		r.Log.Error(err, "Failed to create/update build-api nginx config")
		return fmt.Errorf("failed to create/update build-api nginx config: %w", err)
	}
	r.Log.Info("Build-API nginx config created/updated successfully")

	// Create/update build-api deployment
	deployment := r.buildBuildAPIDeployment()
	if err := r.createOrUpdate(ctx, deployment, config); err != nil {
		r.Log.Error(err, "Failed to create/update build-api deployment")
		return fmt.Errorf("failed to create/update build-api deployment: %w", err)
	}
	r.Log.Info("Build-API deployment created/updated successfully")

	// Create/update build-api service
	service := r.buildBuildAPIService()
	if err := r.createOrUpdate(ctx, service, config); err != nil {
		r.Log.Error(err, "Failed to create/update build-api service")
		return fmt.Errorf("failed to create/update build-api service: %w", err)
	}
	r.Log.Info("Build-API service created/updated successfully")

	r.Log.Info("Build-API deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.OperatorConfig{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&tektonv1.Task{}).
		Owns(&tektonv1.Pipeline{}).
		Complete(r)
}
