package imagebuild

import (
	"fmt"
	"strconv"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/jumpstarter"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	pod "github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const buildPipelineName = "automotive-build-pipeline"

func stringParam(name, value string) tektonv1.Param {
	return tektonv1.Param{Name: name, Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: value}}
}

func boolParam(name string, value bool) tektonv1.Param {
	return stringParam(name, strconv.FormatBool(value))
}

type flashTarget struct {
	selector string
	command  string
	imageRef string
}

// pipelineRunInputs contains resolved values; constructing a run does no I/O.
type pipelineRunInputs struct {
	build             *automotivev1alpha1.ImageBuild
	operatorConfig    *automotivev1alpha1.OperatorConfig
	buildConfig       *tasks.BuildConfig
	exportFormat      string
	extraArgs         []string
	registryRoute     string
	flash             *flashTarget
	manifestConfigMap string
	flashAuthSecret   string
}

func newPipelineRun(in pipelineRunInputs) (*tektonv1.PipelineRun, error) {
	params := baseParams(in.build, in.operatorConfig, in.exportFormat, in.extraArgs, in.buildConfig)
	params = append(params, registryParams(in.build, in.registryRoute)...)
	if in.flash != nil {
		params = append(params, flashParams(in.build, in.operatorConfig, in.flash)...)
	}
	shared, err := sharedWorkspace(in.build, in.operatorConfig)
	if err != nil {
		return nil, err
	}
	workspaces := workspaceBindings(in.build, in.flash, shared, in.manifestConfigMap, in.flashAuthSecret)
	return pipelineRunObject(in.build, in.operatorConfig, in.buildConfig, params, workspaces), nil
}

func resolveFlashTarget(imageBuild *automotivev1alpha1.ImageBuild, operatorConfig *automotivev1alpha1.OperatorConfig, registryRoute string) (*flashTarget, error) {
	if !imageBuild.Spec.IsFlashEnabled() {
		return nil, nil
	}
	selector := imageBuild.Spec.GetFlashExporterSelector()
	command := ""
	target := imageBuild.Spec.GetTarget()
	if operatorConfig.Spec.Jumpstarter != nil {
		if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[target]; ok {
			if selector == "" {
				selector = mapping.Selector
			}
			command = mapping.FlashCmd
		}
	}
	if selector == "" {
		return nil, fmt.Errorf("flash enabled but no Jumpstarter target mapping found for target %q; "+
			"configure OperatorConfig.spec.jumpstarter.targetMappings[%q] with selector and flashCmd, "+
			"or set flash.exporterSelector directly: %w", target, target, errTerminalConfig)
	}
	if userCommand := imageBuild.Spec.GetFlashCmd(); userCommand != "" {
		command = userCommand
	}
	if imageBuild.Spec.GetUseServiceAccountAuth() && registryRoute == "" {
		return nil, fmt.Errorf("flash with internal registry requires an external registry route; "+
			"set OperatorConfig.spec.osBuilds.clusterRegistryRoute or expose openshift-image-registry/default-route: %w", errTerminalConfig)
	}
	imageRef := imageBuild.Spec.GetExportOCI()
	if imageBuild.Spec.GetUseServiceAccountAuth() && imageRef != "" {
		imageRef = strings.Replace(imageRef, tasks.DefaultInternalRegistryURL, registryRoute, 1)
	}
	return &flashTarget{selector: selector, command: command, imageRef: imageRef}, nil
}

// buildConfigFromOperatorConfig translates operator settings without accessing the cluster.
func buildConfigFromOperatorConfig(operatorConfig *automotivev1alpha1.OperatorConfig) *tasks.BuildConfig {
	if operatorConfig == nil || operatorConfig.Spec.OSBuilds == nil {
		return nil
	}
	buildConfig := &tasks.BuildConfig{
		UseMemoryVolumes:            operatorConfig.Spec.OSBuilds.UseMemoryVolumes,
		MemoryVolumeSize:            operatorConfig.Spec.OSBuilds.MemoryVolumeSize,
		PVCSize:                     operatorConfig.Spec.OSBuilds.PVCSize,
		RuntimeClassName:            operatorConfig.Spec.OSBuilds.RuntimeClassName,
		AutomotiveImageBuilderImage: operatorConfig.Spec.GetImages().GetAutomotiveImageBuilderImage(),
		YQHelperImage:               operatorConfig.Spec.GetImages().GetYQHelperImage(),
		HermetoImage:                operatorConfig.Spec.GetImages().GetHermetoImage(),
		HermetoPrefetch:             operatorConfig.Spec.OSBuilds.HermetoPrefetch,
		GitCloneImage:               operatorConfig.Spec.GetImages().GetGitCloneImage(),
		BuildTimeoutMinutes:         operatorConfig.Spec.OSBuilds.GetBuildTimeoutMinutes(),
		FlashTimeoutMinutes:         operatorConfig.Spec.OSBuilds.GetFlashTimeoutMinutes(),
		DefaultLeaseDuration:        operatorConfig.Spec.Jumpstarter.GetDefaultLeaseDuration(),
		UsePVCScratchVolumes:        operatorConfig.Spec.OSBuilds.GetUsePVCScratchVolumes(),
	}
	controllerutils.ApplyTrustedCABundleFromOSBuilds(buildConfig, operatorConfig.Spec.OSBuilds)

	controllerutils.ApplyOCIVolumesConfig(buildConfig, &operatorConfig.Spec)
	return buildConfig
}

// baseParams builds the stable Tekton parameter set.
func baseParams(imageBuild *automotivev1alpha1.ImageBuild, operatorConfig *automotivev1alpha1.OperatorConfig, exportFormat string, extraArgs []string, buildConfig *tasks.BuildConfig) []tektonv1.Param {
	params := []tektonv1.Param{
		stringParam("arch", imageBuild.Spec.Architecture),
		stringParam("distro", imageBuild.Spec.GetDistro()),
		stringParam("target", imageBuild.Spec.GetTarget()),
		stringParam("mode", imageBuild.Spec.GetMode()),
		stringParam("export-format", exportFormat),
		stringParam("automotive-image-builder", imageBuild.Spec.GetAIBImage()),
		boolParam("resolve-only", imageBuild.Spec.GetResolveOnly()),
		boolParam("hermeto-prefetch", buildConfig != nil && buildConfig.HermetoPrefetch),
		stringParam("hermeto-image", operatorConfig.Spec.GetImages().GetHermetoImage()),
		stringParam("compression", imageBuild.Spec.GetCompression()),
		stringParam("container-push", imageBuild.Spec.GetContainerPush()),
		boolParam("build-disk-image", imageBuild.Spec.GetBuildDiskImage()),
		stringParam("export-oci", imageBuild.Spec.GetExportOCI()),
		stringParam("s3-bucket", imageBuild.Spec.GetS3Bucket()),
		stringParam("s3-prefix", s3Prefix(imageBuild)),
		stringParam("s3-endpoint", imageBuild.Spec.GetS3Endpoint()),
		stringParam("s3-region", imageBuild.Spec.GetS3Region()),
		boolParam("s3-insecure-skip-tls-verify", imageBuild.Spec.GetS3InsecureSkipTLSVerify()),
		stringParam("builder-image", imageBuild.Spec.GetBuilderImage()),
		boolParam("rebuild-builder", imageBuild.Spec.GetRebuildBuilder()),
		stringParam("builder-cache-policy", imageBuild.Spec.GetBuilderCachePolicy()),
		stringParam("secret-ref", imageBuild.Spec.SecretRef),
		boolParam("use-persistent-cache", imageBuild.Spec.BuildCachePVC != ""),
		boolParam("secure-build", imageBuild.Spec.SecureBuild),
		boolParam("insecure-registry", operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.InsecureRegistry),
		boolParam("reproducible", imageBuild.Spec.Reproducible),
		stringParam("task-bundle-ref", imageBuild.Spec.TaskBundleRef),
		stringParam("restore-sources-ref", imageBuild.Spec.RestoreSourcesRef),
		stringParam("custom-defines", strings.Join(imageBuild.Spec.GetCustomDefs(), "\n")),
		stringParam("aib-extra-args", strings.Join(extraArgs, "\n")),
		stringParam("trace-id", getTraceID(imageBuild)),
	}

	return params
}

func registryParams(imageBuild *automotivev1alpha1.ImageBuild, clusterRegistryRoute string) []tektonv1.Param {
	params := []tektonv1.Param{}
	if clusterRegistryRoute != "" {
		params = append(params, stringParam("cluster-registry-route", clusterRegistryRoute))
	}

	// Add container-ref param for disk mode
	if imageBuild.Spec.GetContainerRef() != "" {
		params = append(params, stringParam("container-ref", imageBuild.Spec.GetContainerRef()))
	}

	return params
}

func flashParams(imageBuild *automotivev1alpha1.ImageBuild, operatorConfig *automotivev1alpha1.OperatorConfig, flash *flashTarget) []tektonv1.Param {
	return []tektonv1.Param{
		stringParam("flash-enabled", "true"),
		stringParam("flash-image-ref", flash.imageRef),
		stringParam("flash-exporter-selector", flash.selector),
		stringParam("flash-cmd", flash.command),
		stringParam("flash-lease-duration", imageBuild.Spec.GetFlashLeaseDuration()),
		stringParam("flash-lease-name", imageBuild.Spec.GetFlashLeaseName()),
		stringParam("flash-lease-tags", jumpstarter.BuildLeaseTags(operatorConfig.Spec.Jumpstarter.GetDefaultLeaseTags(), imageBuild.Name, imageBuild.Spec.GetFlashLeaseTags())),
		stringParam("jumpstarter-image", operatorConfig.Spec.Jumpstarter.GetJumpstarterImage()),
	}
}

// sharedWorkspace selects an existing PVC or a claim template.
func sharedWorkspace(imageBuild *automotivev1alpha1.ImageBuild, operatorConfig *automotivev1alpha1.OperatorConfig) (tektonv1.WorkspaceBinding, error) {
	// Determine the shared-workspace binding:
	// - If BuildCachePVC is set, use it as the shared workspace for build cache persistence
	// - If InputFilesServer is enabled and a PVC already exists (from upload phase), use it
	// - Otherwise, use VolumeClaimTemplate to create a new PVC with proper zone affinity
	var sharedWorkspaceBinding tektonv1.WorkspaceBinding
	if imageBuild.Spec.BuildCachePVC != "" {
		sharedWorkspaceBinding = tektonv1.WorkspaceBinding{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: imageBuild.Spec.BuildCachePVC,
			},
		}
	} else if (imageBuild.Spec.GetInputFilesServer() || imageBuild.Spec.GetGitSource() != nil) && imageBuild.Status.PVCName != "" {
		// Use existing PVC that contains uploaded files
		sharedWorkspaceBinding = tektonv1.WorkspaceBinding{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: imageBuild.Status.PVCName,
			},
		}
	} else {
		// Create new PVC via VolumeClaimTemplate for proper zone affinity
		storageSize := resource.MustParse("8Gi")
		if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.PVCSize != "" {
			var err error
			storageSize, err = resource.ParseQuantity(operatorConfig.Spec.OSBuilds.PVCSize)
			if err != nil {
				return tektonv1.WorkspaceBinding{}, fmt.Errorf("invalid build PVC size %q: %w: %w", operatorConfig.Spec.OSBuilds.PVCSize, err, errTerminalConfig)
			}
		}
		var storageClassName *string
		if imageBuild.Spec.StorageClass != "" {
			storageClassName = new(imageBuild.Spec.StorageClass)
		} else if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.StorageClass != "" {
			storageClassName = new(operatorConfig.Spec.OSBuilds.StorageClass)
		}
		sharedWorkspaceBinding = tektonv1.WorkspaceBinding{
			Name: "shared-workspace",
			VolumeClaimTemplate: &corev1.PersistentVolumeClaim{
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					StorageClassName: storageClassName,
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: storageSize,
						},
					},
				},
			},
		}
	}

	return sharedWorkspaceBinding, nil
}

// workspaceBindings assembles every PipelineRun workspace mount.
func workspaceBindings(imageBuild *automotivev1alpha1.ImageBuild, flash *flashTarget, sharedWorkspaceBinding tektonv1.WorkspaceBinding, manifestConfigMapName, flashOCIAuthSecretName string) []tektonv1.WorkspaceBinding {
	pipelineWorkspaces := []tektonv1.WorkspaceBinding{
		sharedWorkspaceBinding,
		{
			Name: "manifest-config-workspace",
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: manifestConfigMapName,
				},
			},
		},
	}

	if imageBuild.Spec.SecretRef != "" {
		pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
			Name: "registry-auth",
			Secret: &corev1.SecretVolumeSource{
				SecretName: imageBuild.Spec.SecretRef,
			},
		})
	}

	if imageBuild.Spec.GetS3CredentialsSecret() != "" {
		pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
			Name: "s3-auth",
			Secret: &corev1.SecretVolumeSource{
				SecretName: imageBuild.Spec.GetS3CredentialsSecret(),
			},
		})
	}

	if flash != nil {
		pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
			Name: "jumpstarter-client",
			Secret: &corev1.SecretVolumeSource{
				SecretName: imageBuild.Spec.GetFlashClientConfigSecretRef(),
			},
		})
		if flashOCIAuthSecretName != "" {
			pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
				Name:   "flash-oci-auth",
				Secret: &corev1.SecretVolumeSource{SecretName: flashOCIAuthSecretName},
			})
		}
	}

	return pipelineWorkspaces
}

// pipelineRunObject constructs the Tekton object from resolved inputs.
func pipelineRunObject(imageBuild *automotivev1alpha1.ImageBuild, operatorConfig *automotivev1alpha1.OperatorConfig, buildConfig *tasks.BuildConfig, params []tektonv1.Param, pipelineWorkspaces []tektonv1.WorkspaceBinding) *tektonv1.PipelineRun {
	nodeAffinity := &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{
					MatchExpressions: []corev1.NodeSelectorRequirement{
						{
							Key:      corev1.LabelArchStable,
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{controllerutils.NormalizeArchToK8s(imageBuild.Spec.Architecture)},
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
		podTemplate.RuntimeClassName = new(buildConfig.RuntimeClassName)
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.NodeSelector) > 0 {
		podTemplate.NodeSelector = operatorConfig.Spec.OSBuilds.NodeSelector
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.Tolerations) > 0 {
		podTemplate.Tolerations = operatorConfig.Spec.OSBuilds.Tolerations
	}
	if imageBuild.Spec.RuntimeClassName != "" {
		podTemplate.RuntimeClassName = new(imageBuild.Spec.RuntimeClassName)
	}
	podTemplate.Volumes = append(podTemplate.Volumes, tasks.OCIVolumes(buildConfig)...)
	podTemplate.Volumes = append(podTemplate.Volumes, ociRepoVolumes(imageBuild.Spec.GetOCIRepoImages())...)
	pipelineRunSpec := tektonv1.PipelineRunSpec{
		Params:     params,
		Workspaces: pipelineWorkspaces,
		TaskRunTemplate: tektonv1.PipelineTaskRunTemplate{
			PodTemplate:        podTemplate,
			ServiceAccountName: automotivev1alpha1.BuildServiceAccountName,
		},
	}

	if buildConfig != nil && buildConfig.TaskResolver == tasks.TaskResolverBundle {
		pipelineRunSpec.PipelineRef = &tektonv1.PipelineRef{
			ResolverRef: tektonv1.ResolverRef{
				Resolver: tektonv1.ResolverName(tasks.TektonResolverBundles),
				Params: tektonv1.Params{
					stringParam("bundle", buildConfig.TaskBundleRef),
					stringParam("name", buildPipelineName),
					stringParam("kind", "pipeline"),
				},
			},
		}
	} else {
		pipelineRunSpec.PipelineRef = &tektonv1.PipelineRef{
			Name: buildPipelineName,
		}
	}

	pipelineRun := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: safeDerivedName(imageBuild.Name, "-build-"),
			Namespace:    imageBuild.Namespace,
			Labels:       buildLabels(imageBuild, "build"),
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(imageBuild, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
			},
		},
		Spec: pipelineRunSpec,
	}

	return pipelineRun
}
