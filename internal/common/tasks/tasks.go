package tasks

import (
	_ "embed" // Required for go:embed directives
	"fmt"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// BuildConfig defines configuration options for build operations
// This is an internal type used for task generation
type BuildConfig struct {
	UseMemoryVolumes            bool
	MemoryVolumeSize            string
	PVCSize                     string
	RuntimeClassName            string
	AutomotiveImageBuilderImage string
	YQHelperImage               string
	BuildTimeoutMinutes         int32
	FlashTimeoutMinutes         int32
	DefaultLeaseDuration        string
}

// getAutomotiveImageBuilderImage returns the AIB image from config or the default constant
func (c *BuildConfig) getAutomotiveImageBuilderImage() string {
	if c != nil && c.AutomotiveImageBuilderImage != "" {
		return c.AutomotiveImageBuilderImage
	}
	return automotivev1alpha1.DefaultAutomotiveImageBuilderImage
}

// getYQHelperImage returns the yq helper image from config or the default constant
func (c *BuildConfig) getYQHelperImage() string {
	if c != nil && c.YQHelperImage != "" {
		return c.YQHelperImage
	}
	return automotivev1alpha1.DefaultYQHelperImage
}

// getBuildTimeoutMinutes returns the build timeout from config or the default
func (c *BuildConfig) getBuildTimeoutMinutes() int32 {
	if c != nil && c.BuildTimeoutMinutes > 0 {
		return c.BuildTimeoutMinutes
	}
	return automotivev1alpha1.DefaultBuildTimeoutMinutes
}

// getFlashTimeoutMinutes returns the flash timeout from config or the default
func (c *BuildConfig) getFlashTimeoutMinutes() int32 {
	if c != nil && c.FlashTimeoutMinutes > 0 {
		return c.FlashTimeoutMinutes
	}
	return automotivev1alpha1.DefaultFlashTimeoutMinutes
}

// getDefaultLeaseDuration returns the default lease duration from config or the default
func (c *BuildConfig) getDefaultLeaseDuration() string {
	if c != nil && c.DefaultLeaseDuration != "" {
		return c.DefaultLeaseDuration
	}
	return automotivev1alpha1.DefaultFlashLeaseDuration
}

// DefaultInternalRegistryURL is the standard in-cluster URL for the OpenShift internal image registry.
const DefaultInternalRegistryURL = "image-registry.openshift-image-registry.svc:5000"

// GeneratePushArtifactRegistryTask creates a Tekton Task for pushing artifacts to a registry
func GeneratePushArtifactRegistryTask(namespace string, buildConfig *BuildConfig) *tektonv1.Task {
	return &tektonv1.Task{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "tekton.dev/v1",
			Kind:       "Task",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "push-artifact-registry",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
				"app.kubernetes.io/part-of":    "automotive-dev",
			},
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{
					Name:        "distro",
					Type:        tektonv1.ParamTypeString,
					Description: "Distribution to build",
				},
				{
					Name:        "target",
					Type:        tektonv1.ParamTypeString,
					Description: "Build target",
				},
				{
					Name:        "arch",
					Type:        tektonv1.ParamTypeString,
					Description: "Target architecture",
				},
				{
					Name:        "export-format",
					Type:        tektonv1.ParamTypeString,
					Description: "Export format for the build",
				},
				{
					Name:        "repository-url",
					Type:        tektonv1.ParamTypeString,
					Description: "URL of the artifact registry",
				},
				{
					Name:        "secret-ref",
					Type:        tektonv1.ParamTypeString,
					Description: "Name of the secret containing registry credentials",
				},
				{
					Name:        "artifact-filename",
					Type:        tektonv1.ParamTypeString,
					Description: "Filename of the artifact to push",
				},
				{
					Name:        "builder-image",
					Type:        tektonv1.ParamTypeString,
					Description: "The builder image used for the build",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
			},
			Workspaces: []tektonv1.WorkspaceDeclaration{
				{
					Name:        "shared-workspace",
					Description: "Workspace containing the build artifacts",
					MountPath:   "/workspace/shared",
				},
			},
			Steps: []tektonv1.Step{
				{
					Name:  "push-artifact",
					Image: buildConfig.getYQHelperImage(),
					Env: []corev1.EnvVar{
						{
							Name:  "DOCKER_CONFIG",
							Value: "/docker-config",
						},
					},
					Script:     PushArtifactScript,
					WorkingDir: "/workspace/shared",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "docker-config",
							MountPath: "/docker-config/config.json",
							SubPath:   ".dockerconfigjson",
						},
						{
							Name:      "target-defaults",
							MountPath: "/etc/target-defaults",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "docker-config",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "$(params.secret-ref)",
						},
					},
				},
				{
					Name: "target-defaults",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "aib-target-defaults",
							},
							Optional: ptr.To(true),
						},
					},
				},
			},
		},
	}
}

// GenerateBuildAutomotiveImageTask creates a Tekton Task for building automotive images
func GenerateBuildAutomotiveImageTask(namespace string, buildConfig *BuildConfig, envSecretRef string) *tektonv1.Task {
	task := &tektonv1.Task{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "tekton.dev/v1",
			Kind:       "Task",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "build-automotive-image",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
				"app.kubernetes.io/part-of":    "automotive-dev",
			},
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{
					Name:        "target-architecture",
					Type:        tektonv1.ParamTypeString,
					Description: "Target architecture for the build",
				},
				{
					Name:        "distro",
					Type:        tektonv1.ParamTypeString,
					Description: "Distribution to build",
				},
				{
					Name:        "target",
					Type:        tektonv1.ParamTypeString,
					Description: "Build target",
				},
				{
					Name:        "mode",
					Type:        tektonv1.ParamTypeString,
					Description: "Build mode",
				},
				{
					Name:        "export-format",
					Type:        tektonv1.ParamTypeString,
					Description: "Export format for the build",
				},
				{
					Name:        "compression",
					Type:        tektonv1.ParamTypeString,
					Description: "Compression algorithm for artifacts (lz4, gzip)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "gzip",
					},
				},
				{
					Name:        "automotive-image-builder",
					Type:        tektonv1.ParamTypeString,
					Description: "automotive-image-builder container image to use",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: buildConfig.getAutomotiveImageBuilderImage(),
					},
				},
				{
					Name:        "container-push",
					Type:        tektonv1.ParamTypeString,
					Description: "Registry URL to push bootc container to",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "build-disk-image",
					Type:        tektonv1.ParamTypeString,
					Description: "Whether to build disk image from bootc container (true/false)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "false",
					},
				},
				{
					Name:        "export-oci",
					Type:        tektonv1.ParamTypeString,
					Description: "Registry URL to push disk as OCI artifact",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "builder-image",
					Type:        tektonv1.ParamTypeString,
					Description: "Builder container image for disk builds",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "cluster-registry-route",
					Type:        tektonv1.ParamTypeString,
					Description: "External route for cluster image registry (for builder image lookup)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "container-ref",
					Type:        tektonv1.ParamTypeString,
					Description: "Container reference for disk mode (aib to-disk-image)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "rebuild-builder",
					Type:        tektonv1.ParamTypeString,
					Description: "Force rebuild of the bootc builder image (true/false)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "false",
					},
				},
			},
			Results: []tektonv1.TaskResult{
				{
					Name:        "manifest-file-path",
					Description: "Path to the manifest file used for building",
				},
				{
					Name:        "artifact-filename",
					Description: "artifact filename placed in the shared workspace",
				},
				{
					Name:        "builder-image",
					Description: "The builder image used for the build",
				},
			},
			Workspaces: []tektonv1.WorkspaceDeclaration{
				{
					Name:        "shared-workspace",
					Description: "Workspace for sharing data between steps",
					MountPath:   "/workspace/shared",
				},
				{
					Name:        "manifest-config-workspace",
					Description: "Workspace for manifest configuration",
					MountPath:   "/workspace/manifest-config",
				},
				{
					Name:        "registry-auth",
					Description: "Optional: Secret containing registry credentials",
					MountPath:   "/workspace/registry-auth",
					Optional:    true,
				},
			},
			Steps: []tektonv1.Step{
				{
					Name:   "find-manifest-file",
					Image:  buildConfig.getYQHelperImage(),
					Script: FindManifestScript,
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "manifest-work",
							MountPath: "/manifest-work",
						},
					},
				},
				{
					Name:  "build-image",
					Image: "$(params.automotive-image-builder)",
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
						SELinuxOptions: &corev1.SELinuxOptions{
							Type: "unconfined_t",
						},
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{},
						},
					},
					Script:  BuildImageScript,
					EnvFrom: buildEnvFrom(envSecretRef),
					Env: []corev1.EnvVar{
						{
							Name:  "BUILDER_IMAGE",
							Value: "$(params.builder-image)",
						},
						{
							Name:  "TARGET_ARCH",
							Value: "$(params.target-architecture)",
						},
						{
							Name:  "USE_MEMORY_VOLUMES",
							Value: fmt.Sprintf("%t", buildConfig != nil && buildConfig.UseMemoryVolumes),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "build-dir",
							MountPath: "/_build",
						},
						{
							Name:      "output-dir",
							MountPath: "/output",
						},
						{
							Name:      "run-dir",
							MountPath: "/run/osbuild",
						},
						{
							Name:      "dev",
							MountPath: "/dev",
						},
						{
							Name:      "manifest-work",
							MountPath: "/manifest-work",
						},
						{
							Name:      "container-storage",
							MountPath: "/var/lib/containers/storage",
						},
						{
							Name:      "custom-ca",
							MountPath: "/etc/pki/ca-trust/custom",
							ReadOnly:  true,
						},
						{
							Name:      "sysfs",
							MountPath: "/sys",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "manifest-work",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "build-dir",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "output-dir",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "run-dir",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "container-storage",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "dev",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/dev",
						},
					},
				},
				{
					Name: "custom-ca",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "rhivos-ca-bundle",
							},
							Optional: ptr.To(true),
						},
					},
				},
				{
					Name: "sysfs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/sys",
						},
					},
				},
			},
		},
	}

	if buildConfig != nil && buildConfig.UseMemoryVolumes {
		for i := range task.Spec.Volumes {
			vol := &task.Spec.Volumes[i]

			if vol.Name == "build-dir" || vol.Name == "run-dir" || vol.Name == "container-storage" {
				vol.EmptyDir = &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				}

				if buildConfig.MemoryVolumeSize != "" {
					sizeLimit := resource.MustParse(buildConfig.MemoryVolumeSize)
					vol.EmptyDir.SizeLimit = &sizeLimit
				}
			}
		}
	}

	return task
}

// GenerateTektonPipeline creates a Tekton Pipeline for automotive building process
func GenerateTektonPipeline(name, namespace string, buildConfig *BuildConfig) *tektonv1.Pipeline {
	pipeline := &tektonv1.Pipeline{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "tekton.dev/v1",
			Kind:       "Pipeline",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
			},
		},
		Spec: tektonv1.PipelineSpec{
			Params: []tektonv1.ParamSpec{
				{
					Name: "distro",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "autosd",
					},
					Description: "Build for this distro specification",
				},
				{
					Name: "target",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "qemu",
					},
					Description: "Build for this target",
				},
				{
					Name: "arch",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "aarch64",
					},
					Description: "Build for this architecture",
				},
				{
					Name: "export-format",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "image",
					},
					Description: "Export format for the image (qcow2, image)",
				},
				{
					Name: "mode",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "image",
					},
					Description: "Build this image mode (package, image)",
				},
				{
					Name: "compression",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "lz4",
					},
					Description: "Compression algorithm for artifacts (lz4, gzip)",
				},
				{
					Name:        "storage-class",
					Type:        tektonv1.ParamTypeString,
					Description: "Storage class for the PVC to build on (optional, uses cluster default if not specified)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name: "automotive-image-builder",
					Type: tektonv1.ParamTypeString,
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: buildConfig.getAutomotiveImageBuilderImage(),
					},
					Description: "automotive-image-builder container image to use for building",
				},
				{
					Name:        "secret-ref",
					Type:        tektonv1.ParamTypeString,
					Description: "Secret reference for registry credentials",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "container-push",
					Type:        tektonv1.ParamTypeString,
					Description: "Registry URL to push bootc container to",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "build-disk-image",
					Type:        tektonv1.ParamTypeString,
					Description: "Whether to build disk image from bootc container (true/false)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "false",
					},
				},
				{
					Name:        "export-oci",
					Type:        tektonv1.ParamTypeString,
					Description: "Registry URL to push disk as OCI artifact",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "builder-image",
					Type:        tektonv1.ParamTypeString,
					Description: "Custom builder image (skips auto-build if set)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "cluster-registry-route",
					Type:        tektonv1.ParamTypeString,
					Description: "External route for cluster image registry",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "rebuild-builder",
					Type:        tektonv1.ParamTypeString,
					Description: "Force rebuild of the bootc builder image (true/false)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "false",
					},
				},
				{
					Name:        "container-ref",
					Type:        tektonv1.ParamTypeString,
					Description: "Container reference for disk mode (aib to-disk-image)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				// Flash (Jumpstarter) parameters
				{
					Name:        "flash-enabled",
					Type:        tektonv1.ParamTypeString,
					Description: "Enable flashing the image to hardware via Jumpstarter (true/false)",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "false",
					},
				},
				{
					Name:        "flash-image-ref",
					Type:        tektonv1.ParamTypeString,
					Description: "OCI image reference to flash to the device",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "flash-exporter-selector",
					Type:        tektonv1.ParamTypeString,
					Description: "Jumpstarter exporter selector label (e.g., 'board=j784s4evm')",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "flash-cmd",
					Type:        tektonv1.ParamTypeString,
					Description: "Custom flash command (default: j storage flash ${IMAGE_REF})",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "flash-lease-duration",
					Type:        tektonv1.ParamTypeString,
					Description: "Jumpstarter lease duration in HH:MM:SS format",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: buildConfig.getDefaultLeaseDuration(),
					},
				},
				{
					Name:        "jumpstarter-image",
					Type:        tektonv1.ParamTypeString,
					Description: "Container image for Jumpstarter CLI operations",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: automotivev1alpha1.DefaultJumpstarterImage,
					},
				},
			},
			Workspaces: []tektonv1.PipelineWorkspaceDeclaration{
				{Name: "shared-workspace"},
				{Name: "manifest-config-workspace"},
				{Name: "registry-auth", Optional: true},
				{Name: "flash-oci-auth", Optional: true},
				{Name: "jumpstarter-client", Optional: true},
			},
			Results: []tektonv1.PipelineResult{
				{
					Name:        "artifact-filename",
					Description: "The final artifact filename produced by the build",
					Value:       tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks.build-image.results.artifact-filename)"},
				},
				{
					Name:        "builder-image",
					Description: "The builder image reference used for the build",
					Value:       tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks.build-image.results.builder-image)"},
				},
				{
					Name:        "lease-id",
					Description: "The Jumpstarter lease ID acquired during flash (empty if flash not enabled)",
					Value:       tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks.flash-image.results.lease-id)"},
				},
			},
			Tasks: []tektonv1.PipelineTask{
				{
					Name: "build-image",
					TaskRef: &tektonv1.TaskRef{
						ResolverRef: tektonv1.ResolverRef{
							Resolver: "cluster",
							Params: []tektonv1.Param{
								{
									Name: "kind",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: "task",
									},
								},
								{
									Name: "name",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: "build-automotive-image",
									},
								},
								{
									Name: "namespace",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: namespace,
									},
								},
							},
						},
					},
					Params: []tektonv1.Param{
						{
							Name: "target-architecture",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.arch)",
							},
						},
						{
							Name: "distro",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.distro)",
							},
						},
						{
							Name: "target",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.target)",
							},
						},
						{
							Name: "mode",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.mode)",
							},
						},
						{
							Name: "export-format",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.export-format)",
							},
						},
						{
							Name: "compression",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.compression)",
							},
						},
						{
							Name: "automotive-image-builder",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.automotive-image-builder)",
							},
						},
						{
							Name: "container-push",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.container-push)",
							},
						},
						{
							Name: "build-disk-image",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.build-disk-image)",
							},
						},
						{
							Name: "export-oci",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.export-oci)",
							},
						},
						{
							Name: "builder-image",
							Value: tektonv1.ParamValue{
								Type: tektonv1.ParamTypeString,
								// Use pipeline param directly - controller sets this based on mode
								// For bootc: points to cluster registry where build-image cached the builder
								// For traditional: empty (not needed)
								StringVal: "$(params.builder-image)",
							},
						},
						{
							Name: "cluster-registry-route",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.cluster-registry-route)",
							},
						},
						{
							Name: "container-ref",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.container-ref)",
							},
						},
						{
							Name: "rebuild-builder",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.rebuild-builder)",
							},
						},
					},
					Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
						{Name: "shared-workspace", Workspace: "shared-workspace"},
						{Name: "manifest-config-workspace", Workspace: "manifest-config-workspace"},
						{Name: "registry-auth", Workspace: "registry-auth"},
					},
					Timeout: &metav1.Duration{Duration: time.Duration(buildConfig.getBuildTimeoutMinutes()) * time.Minute},
				},
				{
					Name: "push-disk-artifact",
					TaskRef: &tektonv1.TaskRef{
						ResolverRef: tektonv1.ResolverRef{
							Resolver: "cluster",
							Params: []tektonv1.Param{
								{
									Name: "kind",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: "task",
									},
								},
								{
									Name: "name",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: "push-artifact-registry",
									},
								},
								{
									Name: "namespace",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: namespace,
									},
								},
							},
						},
					},
					Params: []tektonv1.Param{
						{
							Name: "distro",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.distro)",
							},
						},
						{
							Name: "target",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.target)",
							},
						},
						{
							Name: "arch",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.arch)",
							},
						},
						{
							Name: "export-format",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.export-format)",
							},
						},
						{
							Name: "repository-url",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.export-oci)",
							},
						},
						{
							Name: "secret-ref",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.secret-ref)",
							},
						},
						{
							Name: "artifact-filename",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(tasks.build-image.results.artifact-filename)",
							},
						},
						{
							Name: "builder-image",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(tasks.build-image.results.builder-image)",
							},
						},
					},
					Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
						{Name: "shared-workspace", Workspace: "shared-workspace"},
					},
					RunAfter: []string{"build-image"},
					When: []tektonv1.WhenExpression{
						{
							Input:    "$(params.export-oci)",
							Operator: "notin",
							Values:   []string{"", "null"},
						},
						{
							Input:    "$(params.secret-ref)",
							Operator: "notin",
							Values:   []string{"", "null"},
						},
					},
				},
				{
					Name: "flash-image",
					TaskRef: &tektonv1.TaskRef{
						ResolverRef: tektonv1.ResolverRef{
							Resolver: "cluster",
							Params: []tektonv1.Param{
								{
									Name: "kind",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: "task",
									},
								},
								{
									Name: "name",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: "flash-image",
									},
								},
								{
									Name: "namespace",
									Value: tektonv1.ParamValue{
										Type:      tektonv1.ParamTypeString,
										StringVal: namespace,
									},
								},
							},
						},
					},
					Params: []tektonv1.Param{
						{
							Name: "image-ref",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.flash-image-ref)",
							},
						},
						{
							Name: "exporter-selector",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.flash-exporter-selector)",
							},
						},
						{
							Name: "flash-cmd",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.flash-cmd)",
							},
						},
						{
							Name: "lease-duration",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.flash-lease-duration)",
							},
						},
						{
							Name: "jumpstarter-image",
							Value: tektonv1.ParamValue{
								Type:      tektonv1.ParamTypeString,
								StringVal: "$(params.jumpstarter-image)",
							},
						},
					},
					Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
						{Name: "jumpstarter-client", Workspace: "jumpstarter-client"},
						{Name: "flash-oci-auth", Workspace: "flash-oci-auth"},
					},
					// Flash runs after push-disk-artifact (if it ran) or build-image
					RunAfter: []string{"push-disk-artifact"},
					When: []tektonv1.WhenExpression{
						{
							Input:    "$(params.flash-enabled)",
							Operator: "in",
							Values:   []string{"true"},
						},
						{
							Input:    "$(params.flash-exporter-selector)",
							Operator: "notin",
							Values:   []string{"", "null"},
						},
					},
					Timeout: &metav1.Duration{Duration: time.Duration(buildConfig.getFlashTimeoutMinutes()) * time.Minute},
				},
			},
		},
	}

	return pipeline
}

func buildEnvFrom(envSecretRef string) []corev1.EnvFromSource {
	if envSecretRef == "" {
		return nil
	}

	return []corev1.EnvFromSource{
		{
			SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: envSecretRef,
				},
			},
		},
	}
}

// GenerateFlashTask creates a Tekton Task for flashing images to hardware via Jumpstarter
func GenerateFlashTask(namespace string, buildConfig *BuildConfig) *tektonv1.Task {
	return &tektonv1.Task{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "tekton.dev/v1",
			Kind:       "Task",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "flash-image",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
				"app.kubernetes.io/part-of":    "automotive-dev",
			},
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{
					Name:        "image-ref",
					Type:        tektonv1.ParamTypeString,
					Description: "OCI image reference to flash to the device",
				},
				{
					Name:        "exporter-selector",
					Type:        tektonv1.ParamTypeString,
					Description: "Jumpstarter exporter selector label (e.g., 'board=j784s4evm')",
				},
				{
					Name:        "flash-cmd",
					Type:        tektonv1.ParamTypeString,
					Description: "Command to run for flashing (default: j storage flash ${IMAGE_REF})",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: "",
					},
				},
				{
					Name:        "lease-duration",
					Type:        tektonv1.ParamTypeString,
					Description: "Lease duration in HH:MM:SS format",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: buildConfig.getDefaultLeaseDuration(),
					},
				},
				{
					Name:        "jumpstarter-image",
					Type:        tektonv1.ParamTypeString,
					Description: "Container image for Jumpstarter CLI operations",
					Default: &tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: automotivev1alpha1.DefaultJumpstarterImage,
					},
				},
			},
			Results: []tektonv1.TaskResult{
				{
					Name:        "lease-id",
					Type:        tektonv1.ResultsTypeString,
					Description: "The Jumpstarter lease ID acquired for the device",
				},
			},
			Workspaces: []tektonv1.WorkspaceDeclaration{
				{
					Name:        "jumpstarter-client",
					Description: "Workspace containing the Jumpstarter client config (client.yaml)",
					MountPath:   "/workspace/jumpstarter-client",
					Optional:    true,
				},
				{
					Name:        "flash-oci-auth",
					Description: "Workspace containing OCI credentials (username, password) for flash image pull",
					MountPath:   "/workspace/flash-oci-auth",
					Optional:    true,
				},
			},
			Steps: []tektonv1.Step{
				{
					Name:  "flash",
					Image: "$(params.jumpstarter-image)",
					Env: []corev1.EnvVar{
						{
							Name:  "IMAGE_REF",
							Value: "$(params.image-ref)",
						},
						{
							Name:  "EXPORTER_SELECTOR",
							Value: "$(params.exporter-selector)",
						},
						{
							Name:  "FLASH_CMD",
							Value: "$(params.flash-cmd)",
						},
						{
							Name:  "LEASE_DURATION",
							Value: "$(params.lease-duration)",
						},
						{
							Name:  "JMP_CLIENT_CONFIG",
							Value: "/workspace/jumpstarter-client/client.yaml",
						},
						{
							Name:  "FLASH_OCI_AUTH_PATH",
							Value: "/workspace/flash-oci-auth",
						},
						{
							Name:  "RESULTS_LEASE_ID_PATH",
							Value: "$(results.lease-id.path)",
						},
					},
					Script:  FlashImageScript,
					Timeout: &metav1.Duration{Duration: time.Duration(buildConfig.getFlashTimeoutMinutes()) * time.Minute},
				},
			},
		},
	}
}

// GenerateBuildBuilderJob creates a Job to build the aib-build helper container
func GenerateBuildBuilderJob(namespace, distro, targetRegistry, aibImage string) *corev1.Pod {
	if aibImage == "" {
		aibImage = automotivev1alpha1.DefaultAutomotiveImageBuilderImage
	}

	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "build-helper-" + distro + "-",
			Namespace:    namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":           "automotive-dev-operator",
				"app.kubernetes.io/component":            "build-helper",
				"automotive.sdv.cloud.redhat.com/distro": distro,
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:      corev1.RestartPolicyNever,
			ServiceAccountName: "pipeline",
			Containers: []corev1.Container{
				{
					Name:  "build-helper",
					Image: aibImage,
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
						SELinuxOptions: &corev1.SELinuxOptions{
							Type: "unconfined_t",
						},
					},
					Command: []string{"/bin/sh", "-c"},
					Args:    []string{BuildBuilderScript},
					Env: []corev1.EnvVar{
						{
							Name:  "DISTRO",
							Value: distro,
						},
						{
							Name:  "TARGET_REGISTRY",
							Value: targetRegistry,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "dev",
							MountPath: "/dev",
						},
						{
							Name:      "container-storage",
							MountPath: "/var/lib/containers/storage",
						},
						{
							Name:      "run-osbuild",
							MountPath: "/run/osbuild",
						},
						{
							Name:      "var-tmp",
							MountPath: "/var/tmp",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "dev",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/dev",
						},
					},
				},
				{
					Name: "container-storage",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumMemory,
						},
					},
				},
				{
					Name: "run-osbuild",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumMemory,
						},
					},
				},
				{
					Name: "var-tmp",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumMemory,
						},
					},
				},
			},
		},
	}
}
