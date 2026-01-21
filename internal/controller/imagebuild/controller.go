package imagebuild

import (
	"context"
	"fmt"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	pod "github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	OperatorNamespace = "automotive-dev-operator-system"
)

// getFormatExtension returns the file extension for an export format
func getFormatExtension(format string) string {
	switch format {
	case "image":
		return ".raw"
	case "qcow2":
		return ".qcow2"
	default:
		if format != "" {
			return "." + format
		}
		return ".raw"
	}
}

// getCompressionExtension returns the file extension for a compression algorithm
func getCompressionExtension(compression string) string {
	if compression == "" || compression == "none" {
		return ""
	}

	switch compression {
	case "gzip":
		return ".gz"
	case "lz4":
		return ".lz4"
	case "xz":
		return ".xz"
	default:
		return ""
	}
}

// buildArtifactFilename constructs the artifact filename with proper extensions
func buildArtifactFilename(distro, target, exportFormat, compression string) string {
	baseFormat := getFormatExtension(exportFormat)
	compressionExt := getCompressionExtension(compression)

	return fmt.Sprintf("%s-%s%s%s", distro, target, baseFormat, compressionExt)
}

// ImageBuildReconciler reconciles a ImageBuild object
type ImageBuildReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,verbs=get;list;watch;create;update;patch;delete;use
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;pipelines;pipelineruns;taskruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete

// Reconcile ImageBuild
func (r *ImageBuildReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", req.NamespacedName)

	imageBuild := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, req.NamespacedName, imageBuild); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch imageBuild.Status.Phase {
	case "":
		return r.handleInitialState(ctx, imageBuild)
	case "Uploading":
		return r.handleUploadingState(ctx, imageBuild)
	case "Building":
		return r.handleBuildingState(ctx, imageBuild)
	case "Pushing":
		return r.handlePushingState(ctx, imageBuild)
	case "Completed":
		return r.handleCompletedState(ctx, imageBuild)
	case "Failed":
		return ctrl.Result{}, nil
	default:
		log.Info("Unknown phase", "phase", imageBuild.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *ImageBuildReconciler) handleInitialState(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	if imageBuild.Spec.InputFilesServer {
		if err := r.createUploadPod(ctx, imageBuild); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create upload server: %w", err)
		}
		if err := r.updateStatus(ctx, imageBuild, "Uploading", "Waiting for file uploads"); err != nil {
			log.Error(err, "Failed to update status to Uploading")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.updateStatus(ctx, imageBuild, "Building", "Build started"); err != nil {
		log.Error(err, "Failed to update status to Building")
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

func (r *ImageBuildReconciler) handleUploadingState(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	uploadsComplete := imageBuild.Annotations != nil &&
		imageBuild.Annotations["automotive.sdv.cloud.redhat.com/uploads-complete"] == "true"

	if !uploadsComplete {
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	if err := r.shutdownUploadPod(ctx, imageBuild); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to shutdown upload server: %w", err)
	}

	if err := r.updateStatus(ctx, imageBuild, "Building", "Build started"); err != nil {
		log.Error(err, "Failed to update status to Building")
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

func (r *ImageBuildReconciler) handleBuildingState(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	if imageBuild.Status.PipelineRunName != "" {
		return r.checkBuildProgress(ctx, imageBuild)
	}

	// Look for existing PipelineRuns for this ImageBuild
	pipelineRunList := &tektonv1.PipelineRunList{}
	if err := r.List(ctx, pipelineRunList,
		client.InNamespace(imageBuild.Namespace),
		client.MatchingLabels{
			"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
		}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list existing pipeline runs: %w", err)
	}

	for _, pr := range pipelineRunList.Items {
		if pr.DeletionTimestamp == nil {
			log.Info("Found existing PipelineRun for this ImageBuild", "pipelineRun", pr.Name)

			latestImageBuild := &automotivev1alpha1.ImageBuild{}
			if err := r.Get(ctx, types.NamespacedName{
				Name:      imageBuild.Name,
				Namespace: imageBuild.Namespace,
			}, latestImageBuild); err != nil {
				log.Error(err, "Failed to get latest ImageBuild")
				return ctrl.Result{}, err
			}

			// Only update status if PipelineRunName is not already set
			if latestImageBuild.Status.PipelineRunName != pr.Name {
				latestImageBuild.Status.PipelineRunName = pr.Name
				if err := r.Status().Update(ctx, latestImageBuild); err != nil {
					log.Error(err, "Failed to update ImageBuild with PipelineRun name")
					return ctrl.Result{}, err
				}
			}

			// Update local imageBuild and immediately check build progress
			imageBuild.Status.PipelineRunName = pr.Name
			return r.checkBuildProgress(ctx, imageBuild)
		}
	}

	return r.startNewBuild(ctx, imageBuild)
}

func (r *ImageBuildReconciler) handleCompletedState(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	if !imageBuild.Spec.ServeArtifact {
		return ctrl.Result{}, nil
	}

	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	expiryHours := int32(24)
	if imageBuild.Spec.ServeExpiryHours > 0 {
		expiryHours = imageBuild.Spec.ServeExpiryHours
	}

	if imageBuild.Status.CompletionTime == nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	expiryAt := imageBuild.Status.CompletionTime.Time.Add(time.Duration(expiryHours) * time.Hour)
	now := time.Now()
	if now.Before(expiryAt) {
		return ctrl.Result{RequeueAfter: time.Until(expiryAt)}, nil
	}

	svcName := fmt.Sprintf("%s-artifact-service", imageBuild.Name)
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: imageBuild.Namespace}}
	if err := r.Delete(ctx, svc); err != nil && !errors.IsNotFound(err) {
		log.Error(err, "failed to delete artifact Service", "service", svcName)
	}

	routeName := fmt.Sprintf("%s-artifacts", imageBuild.Name)
	route := &routev1.Route{ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: imageBuild.Namespace}}
	if err := r.Delete(ctx, route); err != nil && !errors.IsNotFound(err) {
		log.Error(err, "failed to delete artifact Route", "route", routeName)
	}

	podName := fmt.Sprintf("%s-artifact-pod", imageBuild.Name)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: imageBuild.Namespace}}
	if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
		log.Error(err, "failed to delete artifact Pod", "pod", podName)
	}

	cmName := fmt.Sprintf("%s-nginx-config", imageBuild.Name)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: imageBuild.Namespace}}
	if err := r.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
		log.Error(err, "failed to delete nginx ConfigMap", "configMap", cmName)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err == nil {
		patch := client.MergeFrom(fresh.DeepCopy())
		fresh.Status.ArtifactURL = ""
		fresh.Status.ArtifactFileName = ""
		fresh.Status.ArtifactPath = ""
		fresh.Status.Message = "Build expired"
		if err := r.Status().Patch(ctx, fresh, patch); err != nil {
			log.Error(err, "failed to update ImageBuild status after expiry cleanup")
		}
	}

	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) checkBuildProgress(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	pipelineRun := &tektonv1.PipelineRun{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Status.PipelineRunName,
		Namespace: imageBuild.Namespace,
	}, pipelineRun)
	if err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		return r.startNewBuild(ctx, imageBuild)
	}

	if !isPipelineRunCompleted(pipelineRun) {
		return ctrl.Result{RequeueAfter: time.Second * 30}, nil
	}

	if isPipelineRunSuccessful(pipelineRun) {
		var artifactFileName string
		// Get results from the build-image task in the pipeline
		for _, childStatus := range pipelineRun.Status.ChildReferences {
			if childStatus.PipelineTaskName == "build-image" {
				taskRun := &tektonv1.TaskRun{}
				if err := r.Get(ctx, types.NamespacedName{Name: childStatus.Name, Namespace: imageBuild.Namespace}, taskRun); err == nil {
					for _, res := range taskRun.Status.TaskRunStatusFields.Results {
						if res.Name == "artifact-filename" && res.Value.StringVal != "" {
							artifactFileName = res.Value.StringVal
							break
						}
					}
				}
				break
			}
		}

		if imageBuild.Spec.ServeArtifact {
			if err := r.createArtifactPod(ctx, imageBuild); err != nil {
				return ctrl.Result{}, err
			}

			if imageBuild.Spec.ExposeRoute {
				if err := r.createArtifactServingResources(ctx, imageBuild); err != nil {
					return ctrl.Result{}, err
				}
			}
		}

		fresh := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
			return ctrl.Result{}, err
		}

		patch := client.MergeFrom(fresh.DeepCopy())

		if artifactFileName != "" {
			fresh.Status.ArtifactFileName = artifactFileName
		}

		// Check if push is configured
		if imageBuild.Spec.Publishers != nil && imageBuild.Spec.Publishers.Registry != nil {
			// Start push task
			if err := r.createPushTaskRun(ctx, imageBuild); err != nil {
				log.Error(err, "Failed to create push TaskRun")
				fresh.Status.Phase = "Failed"
				fresh.Status.Message = fmt.Sprintf("Failed to start push: %v", err)
				if patchErr := r.Status().Patch(ctx, fresh, patch); patchErr != nil {
					log.Error(patchErr, "Failed to patch status after push TaskRun creation failure")
					return ctrl.Result{}, patchErr
				}
				return ctrl.Result{}, nil
			}

			fresh.Status.Phase = "Pushing"
			fresh.Status.Message = "Pushing artifact to registry"
			if err := r.Status().Patch(ctx, fresh, patch); err != nil {
				log.Error(err, "Failed to patch status to Pushing")
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Second * 10}, nil
		}

		fresh.Status.Phase = "Completed"
		fresh.Status.Message = "Build completed successfully"
		if fresh.Status.CompletionTime == nil {
			now := metav1.Now()
			fresh.Status.CompletionTime = &now
		}

		if err := r.Status().Patch(ctx, fresh, patch); err != nil {
			log.Error(err, "Failed to patch status to Completed")
			return ctrl.Result{}, err
		}

		// Cleanup transient secrets
		r.cleanupTransientSecrets(ctx, imageBuild, r.Log)

		// Update artifact info after status is set
		if imageBuild.Spec.ServeArtifact {
			return r.updateArtifactInfo(ctx, imageBuild)
		}

		return ctrl.Result{}, nil
	}

	// Build failed - cleanup transient secrets
	r.cleanupTransientSecrets(ctx, imageBuild, r.Log)

	if err := r.updateStatus(ctx, imageBuild, "Failed", "Build failed"); err != nil {
		log.Error(err, "Failed to update status to Failed")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) startNewBuild(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	pvcName, err := r.getOrCreateWorkspacePVC(ctx, imageBuild)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get or create workspace PVC: %w", err)
	}

	if imageBuild.Status.PVCName != pvcName {
		fresh := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to get fresh ImageBuild: %w", err)
		}

		fresh.Status.PVCName = pvcName
		if err := r.Status().Update(ctx, fresh); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update ImageBuild status with PVC name: %w", err)
		}

		imageBuild.Status.PVCName = pvcName
	}

	if err := r.createBuildTaskRun(ctx, imageBuild); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create build task run: %w", err)
	}

	return ctrl.Result{RequeueAfter: time.Second * 30}, nil
}

func (r *ImageBuildReconciler) createBuildTaskRun(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})
	log.Info("Creating PipelineRun for ImageBuild")

	// Fetch OperatorConfig from the operator namespace to get build configuration
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: OperatorNamespace}, operatorConfig)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get OperatorConfig configuration: %w", err)
	}

	var buildConfig *tasks.BuildConfig
	if err == nil && operatorConfig.Spec.OSBuilds != nil {
		// Convert OSBuildsConfig to BuildConfig
		buildConfig = &tasks.BuildConfig{
			UseMemoryVolumes: operatorConfig.Spec.OSBuilds.UseMemoryVolumes,
			MemoryVolumeSize: operatorConfig.Spec.OSBuilds.MemoryVolumeSize,
			PVCSize:          operatorConfig.Spec.OSBuilds.PVCSize,
			RuntimeClassName: operatorConfig.Spec.OSBuilds.RuntimeClassName,
			ServeExpiryHours: operatorConfig.Spec.OSBuilds.ServeExpiryHours,
		}
	}
	_ = buildConfig // buildConfig used for PVC sizing if needed

	if imageBuild.Status.PVCName == "" {
		workspacePVCName, err := r.getOrCreateWorkspacePVC(ctx, imageBuild)
		if err != nil {
			return err
		}

		fresh := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
			return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
		}

		fresh.Status.PVCName = workspacePVCName
		if err := r.Status().Update(ctx, fresh); err != nil {
			return fmt.Errorf("failed to update ImageBuild status with PVC name: %w", err)
		}

		imageBuild.Status.PVCName = workspacePVCName
	}

	workspacePVCName := imageBuild.Status.PVCName

	params := []tektonv1.Param{
		{
			Name: "arch",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Architecture,
			},
		},
		{
			Name: "distro",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Distro,
			},
		},
		{
			Name: "target",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Target,
			},
		},
		{
			Name: "mode",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Mode,
			},
		},
		{
			Name: "export-format",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.ExportFormat,
			},
		},
		{
			Name: "automotive-image-builder",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.AutomotiveImageBuilder,
			},
		},
		{
			Name: "compression",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Compression,
			},
		},
		{
			Name: "container-push",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.ContainerPush,
			},
		},
		{
			Name: "build-disk-image",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.BuildDiskImage),
			},
		},
		{
			Name: "export-oci",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.ExportOCI,
			},
		},
		{
			Name: "builder-image",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.BuilderImage,
			},
		},
		{
			Name: "secret-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.EnvSecretRef,
			},
		},
	}

	clusterRegistryRoute := ""
	if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.ClusterRegistryRoute != "" {
		clusterRegistryRoute = operatorConfig.Spec.OSBuilds.ClusterRegistryRoute
	} else {
		route := &routev1.Route{}
		if err := r.Get(ctx, types.NamespacedName{Name: "default-route", Namespace: "openshift-image-registry"}, route); err == nil {
			clusterRegistryRoute = route.Spec.Host
			log.Info("Auto-detected cluster registry route", "route", clusterRegistryRoute)
		}
	}
	if clusterRegistryRoute != "" {
		params = append(params, tektonv1.Param{
			Name: "cluster-registry-route",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: clusterRegistryRoute,
			},
		})

		// Let prepare-builder task handle building the image automatically
		// when builder-image is empty for bootc builds
	}

	// Add container-ref param for disk mode
	if imageBuild.Spec.ContainerRef != "" {
		params = append(params, tektonv1.Param{
			Name: "container-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.ContainerRef,
			},
		})
	}

	pipelineWorkspaces := []tektonv1.WorkspaceBinding{
		{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: workspacePVCName,
			},
		},
		{
			Name: "manifest-config-workspace",
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: imageBuild.Spec.ManifestConfigMap,
				},
			},
		},
	}

	if imageBuild.Spec.EnvSecretRef != "" {
		pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
			Name: "registry-auth",
			Secret: &corev1.SecretVolumeSource{
				SecretName: imageBuild.Spec.EnvSecretRef,
			},
		})
	}

	nodeAffinity := &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{
					MatchExpressions: []corev1.NodeSelectorRequirement{
						{
							Key:      corev1.LabelArchStable,
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{imageBuild.Spec.Architecture},
						},
					},
				},
			},
		},
	}

	// prepare podTemplate with runtime class fallback
	podTemplate := &pod.PodTemplate{
		Affinity: &corev1.Affinity{NodeAffinity: nodeAffinity},
	}
	if buildConfig != nil && buildConfig.RuntimeClassName != "" {
		podTemplate.RuntimeClassName = &buildConfig.RuntimeClassName
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.NodeSelector) > 0 {
		podTemplate.NodeSelector = operatorConfig.Spec.OSBuilds.NodeSelector
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.Tolerations) > 0 {
		podTemplate.Tolerations = operatorConfig.Spec.OSBuilds.Tolerations
	}
	if imageBuild.Spec.RuntimeClassName != "" {
		log.Info("Setting RuntimeClassName from ImageBuild spec", "runtimeClassName", imageBuild.Spec.RuntimeClassName)
		podTemplate.RuntimeClassName = &imageBuild.Spec.RuntimeClassName
	}
	pipelineRun := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-build-", imageBuild.Name),
			Namespace:    imageBuild.Namespace,
			Labels: map[string]string{
				tektonv1.ManagedByLabelKey:                        "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: imageBuild.APIVersion,
					Kind:       imageBuild.Kind,
					Name:       imageBuild.Name,
					UID:        imageBuild.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: tektonv1.PipelineRunSpec{
			PipelineRef: &tektonv1.PipelineRef{
				Name: "automotive-build-pipeline",
			},
			Params:     params,
			Workspaces: pipelineWorkspaces,
			TaskRunTemplate: tektonv1.PipelineTaskRunTemplate{
				PodTemplate: podTemplate,
			},
		},
	}

	if err := r.Create(ctx, pipelineRun); err != nil {
		return fmt.Errorf("failed to create PipelineRun: %w", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
	}

	fresh.Status.PipelineRunName = pipelineRun.Name
	if err := r.Status().Update(ctx, fresh); err != nil {
		return fmt.Errorf("failed to update ImageBuild with PipelineRun name: %w", err)
	}

	log.Info("Successfully created PipelineRun", "name", pipelineRun.Name)
	return nil
}

func (r *ImageBuildReconciler) createPushTaskRun(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})
	log.Info("Creating push TaskRun for ImageBuild")

	if imageBuild.Spec.Publishers == nil || imageBuild.Spec.Publishers.Registry == nil {
		return fmt.Errorf("no registry publisher configured")
	}

	pushTask := tasks.GeneratePushArtifactRegistryTask(OperatorNamespace)

	params := []tektonv1.Param{
		{
			Name: "distro",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Distro,
			},
		},
		{
			Name: "target",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Target,
			},
		},
		{
			Name: "export-format",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.ExportFormat,
			},
		},
		{
			Name: "secret-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.EnvSecretRef,
			},
		},
	}

	workspaces := []tektonv1.WorkspaceBinding{
		{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: imageBuild.Status.PVCName,
			},
		},
	}

	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-push-", imageBuild.Name),
			Namespace:    imageBuild.Namespace,
			Labels: map[string]string{
				tektonv1.ManagedByLabelKey:                        "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
				"automotive.sdv.cloud.redhat.com/task-type":       "push",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: imageBuild.APIVersion,
					Kind:       imageBuild.Kind,
					Name:       imageBuild.Name,
					UID:        imageBuild.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskSpec:   &pushTask.Spec,
			Params:     params,
			Workspaces: workspaces,
		},
	}

	if err := r.Create(ctx, taskRun); err != nil {
		return fmt.Errorf("failed to create push TaskRun: %w", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
	}

	fresh.Status.PushTaskRunName = taskRun.Name
	if err := r.Status().Update(ctx, fresh); err != nil {
		return fmt.Errorf("failed to update ImageBuild with push TaskRun name: %w", err)
	}

	log.Info("Successfully created push TaskRun", "name", taskRun.Name)
	return nil
}

func (r *ImageBuildReconciler) handlePushingState(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	if imageBuild.Status.PushTaskRunName == "" {
		// No push TaskRun yet, create one
		if err := r.createPushTaskRun(ctx, imageBuild); err != nil {
			log.Error(err, "Failed to create push TaskRun")
			if statusErr := r.updateStatus(ctx, imageBuild, "Failed", fmt.Sprintf("Failed to create push TaskRun: %v", err)); statusErr != nil {
				log.Error(statusErr, "Failed to update status after push TaskRun creation failure")
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	// Check push TaskRun status
	taskRun := &tektonv1.TaskRun{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Status.PushTaskRunName,
		Namespace: imageBuild.Namespace,
	}, taskRun)
	if err != nil {
		if errors.IsNotFound(err) {
			// TaskRun was deleted, try to recreate
			imageBuild.Status.PushTaskRunName = ""
			if statusErr := r.Status().Update(ctx, imageBuild); statusErr != nil {
				log.Error(statusErr, "Failed to clear PushTaskRunName in status")
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	if !isTaskRunCompleted(taskRun) {
		return ctrl.Result{RequeueAfter: time.Second * 15}, nil
	}

	// Push completed - cleanup transient secrets and update status
	r.cleanupTransientSecrets(ctx, imageBuild, log)

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(fresh.DeepCopy())

	if isTaskRunSuccessful(taskRun) {
		fresh.Status.Phase = "Completed"
		fresh.Status.Message = "Build and push completed successfully"
	} else {
		fresh.Status.Phase = "Failed"
		fresh.Status.Message = "Push to registry failed"
	}

	if fresh.Status.CompletionTime == nil {
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
	}

	if err := r.Status().Patch(ctx, fresh, patch); err != nil {
		log.Error(err, "Failed to patch status after push completion")
		return ctrl.Result{}, err
	}

	// Update artifact info if serving
	if imageBuild.Spec.ServeArtifact && isTaskRunSuccessful(taskRun) {
		return r.updateArtifactInfo(ctx, imageBuild)
	}

	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) updateArtifactInfo(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (ctrl.Result, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	latestImageBuild := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, latestImageBuild); err != nil {
		log.Error(err, "Failed to get latest ImageBuild")
		return ctrl.Result{}, err
	}

	pvcName := latestImageBuild.Status.PVCName
	if pvcName == "" {
		log.Error(nil, "No PVC name found in ImageBuild status")
		return ctrl.Result{}, fmt.Errorf("no PVC name found in ImageBuild status")
	}

	// Only set ArtifactFileName if it's not already set (from Tekton results)
	if latestImageBuild.Status.ArtifactFileName == "" {
		fileName := buildArtifactFilename(
			latestImageBuild.Spec.Distro,
			latestImageBuild.Spec.Target,
			latestImageBuild.Spec.ExportFormat,
			latestImageBuild.Spec.Compression,
		)
		latestImageBuild.Status.ArtifactFileName = fileName
	}

	log.Info("Setting artifact info", "pvc", pvcName, "fileName", latestImageBuild.Status.ArtifactFileName)

	patch := client.MergeFrom(latestImageBuild.DeepCopy())

	latestImageBuild.Status.ArtifactPath = "/"

	if err := r.Status().Patch(ctx, latestImageBuild, patch); err != nil {
		log.Error(err, "Failed to patch status with artifact info")
		return ctrl.Result{RequeueAfter: time.Second * 5}, nil
	}

	if latestImageBuild.Spec.ExposeRoute {
		routeName := "ado-build-api"
		route := &routev1.Route{}
		if err := r.Get(ctx, client.ObjectKey{Name: routeName, Namespace: latestImageBuild.Namespace}, route); err != nil {
			log.Error(err, "Error getting route, will retry")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		if len(route.Status.Ingress) == 0 || route.Status.Ingress[0].Host == "" {
			log.Info("route status not yet populated with host", "route", routeName)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		scheme := "https"
		if route.Spec.TLS == nil {
			scheme = "http"
			log.Info("TLS is not enabled")
		}

		artifactURL := fmt.Sprintf("%s://%s", scheme, route.Status.Ingress[0].Host)
		log.Info("setting artifact URL in status", "url", artifactURL)

		freshBuild := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: latestImageBuild.Name, Namespace: latestImageBuild.Namespace}, freshBuild); err != nil {
			log.Error(err, "Failed to get fresh ImageBuild for URL update")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		urlPatch := client.MergeFrom(freshBuild.DeepCopy())
		freshBuild.Status.ArtifactURL = artifactURL

		if err := r.Status().Patch(ctx, freshBuild, urlPatch); err != nil {
			log.Error(err, "failed to update ImageBuild status with route URL")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}

		log.Info("artifact serving resources created and status updated", "route", route.Status.Ingress[0].Host)
	}

	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) createArtifactPod(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	podName := fmt.Sprintf("%s-artifact-pod", imageBuild.Name)
	existingPod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      podName,
		Namespace: imageBuild.Namespace,
	}, existingPod)

	if err == nil {
		if existingPod.Status.Phase == corev1.PodRunning {
			log.Info("Artifact pod already exists and is running", "pod", podName)
			return nil
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("error checking for existing pod: %w", err)
	}

	workspacePVCName := imageBuild.Status.PVCName
	if workspacePVCName == "" {
		var err error
		workspacePVCName, err = r.getOrCreateWorkspacePVC(ctx, imageBuild)
		if err != nil {
			return err
		}

		fresh := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
			return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
		}

		fresh.Status.PVCName = workspacePVCName
		if err := r.Status().Update(ctx, fresh); err != nil {
			return fmt.Errorf("failed to update ImageBuild status with PVC name: %w", err)
		}

		imageBuild.Status.PVCName = workspacePVCName
	}

	nginxConfigMapName, err := r.createNginxConfigMap(ctx, imageBuild)
	if err != nil {
		return fmt.Errorf("failed to create nginx config map: %w", err)
	}

	labels := map[string]string{
		"app.kubernetes.io/managed-by":                    "automotive-dev-operator",
		"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
		"app.kubernetes.io/name":                          "artifact-pod",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: imageBuild.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         imageBuild.APIVersion,
					Kind:               imageBuild.Kind,
					Name:               imageBuild.Name,
					UID:                imageBuild.UID,
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
					Name:  "fileserver",
					Image: "quay.io/nginx/nginx-unprivileged:latest",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8080,
							Protocol:      corev1.ProtocolTCP,
						},
					},
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
							Name:      "artifacts",
							MountPath: "/workspace/shared",
							ReadOnly:  true,
						},
						{
							Name:      "nginx-config",
							MountPath: "/etc/nginx/conf.d",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "artifacts",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: workspacePVCName,
						},
					},
				},
				{
					Name: "nginx-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: nginxConfigMapName,
							},
						},
					},
				},
			},
		},
	}

	if err := r.Create(ctx, pod); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create artifact pod: %w", err)
	}

	log.Info("Created artifact pod, will check status on next reconciliation", "pod", podName)
	return nil
}

func (r *ImageBuildReconciler) createNginxConfigMap(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (string, error) {
	configMapName := fmt.Sprintf("%s-nginx-config", imageBuild.Name)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: imageBuild.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         imageBuild.APIVersion,
					Kind:               imageBuild.Kind,
					Name:               imageBuild.Name,
					UID:                imageBuild.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Data: map[string]string{
			"default.conf": `
server {
    listen 8080;
    server_name localhost;

    # Serve artifacts directly from the mounted PVC
    root /workspace/shared;
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;

    location / {
        try_files $uri =404;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
    `,
		},
	}

	if err := r.Create(ctx, configMap); err != nil {
		if errors.IsAlreadyExists(err) {
			return configMapName, nil
		}
		return "", fmt.Errorf("failed to create nginx config ConfigMap: %w", err)
	}

	return configMapName, nil
}

// cleanupTransientSecrets deletes any transient secrets created for this build
// Uses retry logic to handle transient API errors
func (r *ImageBuildReconciler) cleanupTransientSecrets(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild, log logr.Logger) {
	// Cleanup registry auth secret (EnvSecretRef)
	if imageBuild.Spec.EnvSecretRef != "" {
		r.deleteSecretWithRetry(ctx, imageBuild.Namespace, imageBuild.Spec.EnvSecretRef, "registry auth", log)
	}

	// Cleanup push secret (Publishers.Registry.Secret)
	if imageBuild.Spec.Publishers != nil && imageBuild.Spec.Publishers.Registry != nil {
		secretName := imageBuild.Spec.Publishers.Registry.Secret
		if secretName != "" {
			r.deleteSecretWithRetry(ctx, imageBuild.Namespace, secretName, "push", log)
		}
	}
}

// deleteSecretWithRetry attempts to delete a secret with exponential backoff retry
func (r *ImageBuildReconciler) deleteSecretWithRetry(ctx context.Context, namespace, secretName, secretType string, log logr.Logger) {
	maxRetries := 3
	backoff := 100 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
		}
		err := r.Delete(ctx, secret)
		if err == nil {
			log.Info("Deleted "+secretType+" secret", "secret", secretName)
			return
		}
		if errors.IsNotFound(err) {
			// Already deleted, nothing to do
			return
		}

		// Transient error - retry with backoff
		if attempt < maxRetries {
			log.V(1).Info("Retrying secret deletion", "secret", secretName, "attempt", attempt, "error", err.Error())
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff
		} else {
			log.Error(err, "Failed to delete "+secretType+" secret after retries (manual cleanup may be required)", "secret", secretName, "attempts", maxRetries)
		}
	}
}

func (r *ImageBuildReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageBuild{}).
		Owns(&tektonv1.PipelineRun{}).
		Owns(&tektonv1.TaskRun{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{})

	// Only add Route ownership if the Route CRD is available (OpenShift only)
	_, err := mgr.GetRESTMapper().RESTMapping(routev1.GroupVersion.WithKind("Route").GroupKind())
	if err == nil {
		builder = builder.Owns(&routev1.Route{})
	}

	return builder.Complete(r)
}

func isTaskRunCompleted(taskRun *tektonv1.TaskRun) bool {
	return taskRun.Status.CompletionTime != nil
}

func isPipelineRunCompleted(pipelineRun *tektonv1.PipelineRun) bool {
	return pipelineRun.Status.CompletionTime != nil
}

func isPipelineRunSuccessful(pipelineRun *tektonv1.PipelineRun) bool {
	conditions := pipelineRun.Status.Conditions
	if len(conditions) == 0 {
		return false
	}

	for _, condition := range conditions {
		if condition.Type == "Succeeded" {
			return condition.Status == "True"
		}
	}
	return false
}

func isTaskRunSuccessful(taskRun *tektonv1.TaskRun) bool {
	conditions := taskRun.Status.Conditions
	if len(conditions) == 0 {
		return false
	}

	return conditions[0].Status == corev1.ConditionTrue
}

func (r *ImageBuildReconciler) createUploadPod(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	podName := fmt.Sprintf("%s-upload-pod", imageBuild.Name)
	existingPod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      podName,
		Namespace: imageBuild.Namespace,
	}, existingPod)

	if err == nil {
		if existingPod.Status.Phase == corev1.PodRunning {
			log.Info("Upload pod already exists and is running", "pod", podName)
			return nil
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("error checking for existing pod: %w", err)
	}

	workspacePVCName, err := r.getOrCreateWorkspacePVC(ctx, imageBuild)
	if err != nil {
		return err
	}

	if imageBuild.Status.PVCName != workspacePVCName {
		fresh := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
			return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
		}

		fresh.Status.PVCName = workspacePVCName
		if err := r.Status().Update(ctx, fresh); err != nil {
			return fmt.Errorf("failed to update ImageBuild status with PVC name: %w", err)
		}

		imageBuild.Status.PVCName = workspacePVCName
	}

	labels := map[string]string{
		"app.kubernetes.io/managed-by":                    "automotive-dev-operator",
		"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
		"app.kubernetes.io/name":                          "upload-pod",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: imageBuild.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         imageBuild.APIVersion,
					Kind:               imageBuild.Kind,
					Name:               imageBuild.Name,
					UID:                imageBuild.UID,
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

	log.Info("Created upload pod, will check status on next reconciliation", "pod", podName)
	return nil
}

func (r *ImageBuildReconciler) updateStatus(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild, phase, message string) error {
	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Name,
		Namespace: imageBuild.Namespace,
	}, fresh); err != nil {
		return err
	}

	patch := client.MergeFrom(fresh.DeepCopy())

	fresh.Status.Phase = phase
	fresh.Status.Message = message

	if phase == "Building" && fresh.Status.StartTime == nil {
		now := metav1.Now()
		fresh.Status.StartTime = &now
	} else if (phase == "Completed" || phase == "Failed") && fresh.Status.CompletionTime == nil {
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
	}

	return r.Status().Patch(ctx, fresh, patch)
}

func (r *ImageBuildReconciler) getOrCreateWorkspacePVC(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) (string, error) {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	if imageBuild.Status.PVCName != "" {
		existingPVC := &corev1.PersistentVolumeClaim{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      imageBuild.Status.PVCName,
			Namespace: imageBuild.Namespace,
		}, existingPVC)

		if err == nil && existingPVC.DeletionTimestamp == nil {
			log.Info("Using existing workspace PVC from status", "pvc", imageBuild.Status.PVCName)
			return imageBuild.Status.PVCName, nil
		}

		log.Info("PVC from status is not available, creating a new one",
			"old-pvc", imageBuild.Status.PVCName)
	}

	// Fetch OperatorConfig to get PVC size configuration
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: OperatorNamespace}, operatorConfig)

	storageSize := resource.MustParse("8Gi")
	if err == nil && operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.PVCSize != "" {
		storageSize = resource.MustParse(operatorConfig.Spec.OSBuilds.PVCSize)
		log.Info("Using OSBuilds PVCSize", "size", operatorConfig.Spec.OSBuilds.PVCSize)
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	uniquePVCName := fmt.Sprintf("%s-ws-%s", imageBuild.Name, timestamp)

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uniquePVCName,
			Namespace: imageBuild.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                    "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         imageBuild.APIVersion,
					Kind:               imageBuild.Kind,
					Name:               imageBuild.Name,
					UID:                imageBuild.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: storageSize,
				},
			},
		},
	}

	if imageBuild.Spec.StorageClass != "" {
		pvc.Spec.StorageClassName = &imageBuild.Spec.StorageClass
	}

	if err := r.Create(ctx, pvc); err != nil {
		return "", fmt.Errorf("failed to create workspace PVC: %w", err)
	}

	log.Info("Created new workspace PVC with unique name", "pvc", uniquePVCName)
	return uniquePVCName, nil
}

func (r *ImageBuildReconciler) shutdownUploadPod(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	podName := fmt.Sprintf("%s-upload-pod", imageBuild.Name)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: imageBuild.Namespace,
		},
	}

	if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete upload pod: %w", err)
	}

	log.Info("Upload pod deleted")
	return nil
}

func (r *ImageBuildReconciler) createArtifactServingResources(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})

	podList := &corev1.PodList{}
	if err := r.List(ctx, podList,
		client.InNamespace(imageBuild.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/name":                          "artifact-pod",
			"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
		}); err != nil {
		return fmt.Errorf("failed to list artifact pods: %w", err)
	}

	if len(podList.Items) == 0 {
		return fmt.Errorf("no existing artifact pod found for ImageBuild %s", imageBuild.Name)
	}
	artifactPod := &podList.Items[0]

	svcName := fmt.Sprintf("%s-artifact-service", imageBuild.Name)
	svc := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: imageBuild.Namespace}, svc)
	if errors.IsNotFound(err) {
		log.Info("Creating artifact service", "name", svcName)
		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: imageBuild.Namespace,
				Labels:    artifactPod.Labels,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         imageBuild.APIVersion,
						Kind:               imageBuild.Kind,
						Name:               imageBuild.Name,
						UID:                imageBuild.UID,
						Controller:         ptr.To(true),
						BlockOwnerDeletion: ptr.To(true),
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Selector: artifactPod.Labels,
				Ports: []corev1.ServicePort{
					{
						Name:       "http",
						Port:       8080,
						TargetPort: intstr.FromInt(8080),
					},
				},
			},
		}
		if err := r.Create(ctx, svc); err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check for existing service: %w", err)
	} else {
		log.Info("Artifact service already exists", "name", svcName)
	}

	routeName := fmt.Sprintf("%s-artifacts", imageBuild.Name)
	route := &routev1.Route{}
	err = r.Get(ctx, types.NamespacedName{Name: routeName, Namespace: imageBuild.Namespace}, route)
	if errors.IsNotFound(err) {
		log.Info("Creating artifact route", "name", routeName)
		route = &routev1.Route{
			ObjectMeta: metav1.ObjectMeta{
				Name:      routeName,
				Namespace: imageBuild.Namespace,
				Labels:    artifactPod.Labels,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         imageBuild.APIVersion,
						Kind:               imageBuild.Kind,
						Name:               imageBuild.Name,
						UID:                imageBuild.UID,
						Controller:         ptr.To(true),
						BlockOwnerDeletion: ptr.To(true),
					},
				},
			},
			Spec: routev1.RouteSpec{
				To: routev1.RouteTargetReference{
					Kind: "Service",
					Name: svcName,
				},
				Port: &routev1.RoutePort{
					TargetPort: intstr.FromInt(8080),
				},
			},
		}
		if err := r.Create(ctx, route); err != nil {
			return fmt.Errorf("failed to create route: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check for existing route: %w", err)
	} else {
		log.Info("Artifact route already exists", "name", routeName)
	}

	return nil
}
