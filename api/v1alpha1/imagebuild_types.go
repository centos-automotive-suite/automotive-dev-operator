/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ImageBuildSpec defines the desired state of ImageBuild
// +kubebuilder:printcolumn:name="StorageClass",type=string,JSONPath=`.spec.storageClass`
type ImageBuildSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Distro specifies the distribution to build for (e.g., "cs9")
	Distro string `json:"distro,omitempty"`

	// Target specifies the build target (e.g., "qemu")
	Target string `json:"target,omitempty"`

	// Architecture specifies the target architecture
	Architecture string `json:"architecture,omitempty"`

	// ExportFormat specifies the output format (image, qcow2)
	ExportFormat string `json:"exportFormat,omitempty"`

	// Mode specifies the build mode (package, image)
	Mode string `json:"mode,omitempty"`

	// StorageClass is the name of the storage class to use for the build PVC
	StorageClass string `json:"storageClass,omitempty"`

	// AutomotiveImageBuilder specifies the image to use for building
	AutomotiveImageBuilder string `json:"automotiveImageBuilder,omitempty"`

	// ManifestConfigMap specifies the name of the ConfigMap containing the manifest configuration
	ManifestConfigMap string `json:"manifestConfigMap,omitempty"`

	// Publishers defines where to publish the built artifacts
	Publishers *Publishers `json:"publishers,omitempty"`

	// RuntimeClassName specifies the runtime class to use for the build pod
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// ServeArtifact determines whether to make the built artifact available for download
	ServeArtifact bool `json:"serveArtifact,omitempty"`

	// ServeExpiryHours specifies how long to serve the artifact before cleanup (default: 24)
	ServeExpiryHours int32 `json:"serveExpiryHours,omitempty"`

	// InputFilesServer indicates if there's a server for files referenced locally in the manifest
	InputFilesServer bool `json:"inputFilesServer,omitempty"`

	// ExposeRoute indicates whether to expose the a route for the artifacts
	ExposeRoute bool `json:"exposeRoute,omitempty"`

	// EnvSecretRef is the name of the secret containing environment variables for the build
	// These environment variables will be available during the build process and can be used
	// for private registry authentication (e.g., REGISTRY_USERNAME, REGISTRY_PASSWORD, REGISTRY_AUTH_FILE)
	EnvSecretRef string `json:"envSecretRef,omitempty"`

	// Compression specifies the compression algorithm for artifacts
	// +kubebuilder:validation:Enum=lz4;gzip;xz
	// +kubebuilder:default=gzip
	Compression string `json:"compression,omitempty"`

	// ContainerPush is the registry URL to push the bootc container image
	ContainerPush string `json:"containerPush,omitempty"`

	// BuildDiskImage indicates whether to build a disk image from the bootc container
	BuildDiskImage bool `json:"buildDiskImage,omitempty"`

	// ExportOCI is the registry URL to push the disk image as an OCI artifact
	ExportOCI string `json:"exportOci,omitempty"`

	// BuilderImage is a custom builder image to use
	BuilderImage string `json:"builderImage,omitempty"`
}

// Publishers defines the configuration for artifact publishing
type Publishers struct {
	// Registry configuration for publishing to an OCI registry
	Registry *RegistryPublisher `json:"registry,omitempty"`
}

// RegistryPublisher defines the configuration for publishing to an OCI registry
type RegistryPublisher struct {
	// RepositoryURL is the URL of the OCI registry repository
	RepositoryURL string `json:"repositoryUrl"`

	// Secret is the name of the secret containing registry credentials
	Secret string `json:"secret"`
}

// ImageBuildStatus defines the observed state of ImageBuild
type ImageBuildStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase represents the current phase of the build (Building, Completed, Failed)
	// +kubebuilder:validation:Enum=Pending;Uploading;Building;Pushing;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// StartTime is when the build started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the build finished
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Message provides more detail about the current phase
	Message string `json:"message,omitempty"`

	// PVCName is the name of the PVC where the artifact is stored
	PVCName string `json:"pvcName,omitempty"`

	// ArtifactPath is the path inside the PVC where the artifact is stored
	ArtifactPath string `json:"artifactPath,omitempty"`

	// ArtifactFileName is the name of the artifact file inside the PVC
	ArtifactFileName string `json:"artifactFileName,omitempty"`

	// PipelineRunName is the name of the active PipelineRun for this build
	PipelineRunName string `json:"pipelineRunName,omitempty"`

	// PushTaskRunName is the name of the TaskRun for pushing artifacts to registry
	PushTaskRunName string `json:"pushTaskRunName,omitempty"`

	// PushTaskRunName is the name of the TaskRun for pushing artifacts to registry
	PushTaskRunName string `json:"pushTaskRunName,omitempty"`

	// ArtifactURL is the route URL created to expose the artifacts
	ArtifactURL string `json:"artifactURL,omitempty"`

	// Conditions represent the latest available observations of the ImageBuild's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ImageBuild is the Schema for the imagebuilds API
type ImageBuild struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageBuildSpec   `json:"spec,omitempty"`
	Status ImageBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageBuildList contains a list of ImageBuild
type ImageBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageBuild{}, &ImageBuildList{})
}
