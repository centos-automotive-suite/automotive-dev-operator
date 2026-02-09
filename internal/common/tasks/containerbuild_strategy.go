package tasks

import (
	shipwrightv1beta1 "github.com/shipwright-io/build/pkg/apis/build/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	// ContainerBuildStrategyName is the name of the ClusterBuildStrategy for container builds
	ContainerBuildStrategyName = "automotive-buildah"
)

// GenerateContainerBuildStrategy creates a Shipwright ClusterBuildStrategy for building
// container images using buildah from an uploaded build context.
func GenerateContainerBuildStrategy() *shipwrightv1beta1.ClusterBuildStrategy {
	dockerfileDefault := "Containerfile"
	buildArgsDefault := ""

	return &shipwrightv1beta1.ClusterBuildStrategy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "shipwright.io/v1beta1",
			Kind:       "ClusterBuildStrategy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: ContainerBuildStrategyName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
				"app.kubernetes.io/part-of":    "automotive-dev",
			},
		},
		Spec: shipwrightv1beta1.BuildStrategySpec{
			Parameters: []shipwrightv1beta1.Parameter{
				{
					Name:        "dockerfile",
					Description: "Path to the Containerfile/Dockerfile within the build context",
					Default:     &dockerfileDefault,
				},
				{
					Name:        "build-args",
					Description: "Comma-separated list of build arguments (KEY=VALUE,...)",
					Default:     &buildArgsDefault,
				},
			},
			Volumes: []shipwrightv1beta1.BuildStrategyVolume{
				{
					Overridable: ptr.To(true),
					Name:        "build-context",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
			Steps: []shipwrightv1beta1.Step{
				{
					Name:    "build-and-push",
					Image:   "quay.io/containers/buildah:latest",
					Command: []string{"/bin/bash", "-c"},
					Args:    []string{ContainerBuildScript},
					Env: []corev1.EnvVar{
						{
							Name:  "CONTEXT_DIR",
							Value: "/workspace/source",
						},
						{
							Name:  "DOCKERFILE",
							Value: "$(params.dockerfile)",
						},
						{
							Name:  "OUTPUT_IMAGE",
							Value: "$(params.shp-output-image)",
						},
						{
							Name:  "BUILD_ARGS",
							Value: "$(params.build-args)",
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "build-context",
							MountPath: "/workspace/source",
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
					},
				},
			},
		},
	}
}
