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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuildConfig defines configuration options for build operations
// This type is used internally for compatibility with task generation
type BuildConfig struct {
	// UseMemoryVolumes determines whether to use memory-backed volumes for build operations
	UseMemoryVolumes bool `json:"useMemoryVolumes,omitempty"`

	// MemoryVolumeSize specifies the size limit for memory-backed volumes (required if UseMemoryVolumes is true)
	// Example: "2Gi"
	MemoryVolumeSize string `json:"memoryVolumeSize,omitempty"`

	// PVCSize specifies the size for persistent volume claims created for build workspaces
	// Default: "8Gi"
	// +optional
	PVCSize string `json:"pvcSize,omitempty"`

	// RuntimeClassName specifies the runtime class to use for the build pod
	// More info: https://kubernetes.io/docs/concepts/containers/runtime-class/
	// +optional
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// ServeExpiryHours specifies how long to serve build artifacts before automatic cleanup
	// Default: 24
	// +optional
	ServeExpiryHours int32 `json:"serveExpiryHours,omitempty"`
}

// BuildAPIConfig defines configuration for the Build API server
type BuildAPIConfig struct {
	// MaxManifestSize is the maximum allowed manifest size in bytes
	// Default: 10485760 (10MB)
	// +optional
	MaxManifestSize int64 `json:"maxManifestSize,omitempty"`

	// MaxUploadFileSize is the maximum size for individual uploaded files in bytes
	// Default: 1073741824 (1GB)
	// +optional
	MaxUploadFileSize int64 `json:"maxUploadFileSize,omitempty"`

	// MaxTotalUploadSize is the maximum total upload size per request in bytes
	// Default: 2147483648 (2GB)
	// +optional
	MaxTotalUploadSize int64 `json:"maxTotalUploadSize,omitempty"`

	// MaxLogStreamDurationMinutes is the maximum duration for log streaming in minutes
	// Default: 120 (2 hours)
	// +optional
	MaxLogStreamDurationMinutes int32 `json:"maxLogStreamDurationMinutes,omitempty"`
}

// OperatorConfigSpec defines the desired state of OperatorConfig
type OperatorConfigSpec struct {
	// OSBuilds defines the configuration for OS build operations
	// +optional
	OSBuilds *OSBuildsConfig `json:"osBuilds,omitempty"`

	// BuildAPI defines configuration for the Build API server
	// +optional
	BuildAPI *BuildAPIConfig `json:"buildAPI,omitempty"`
}

// OSBuildsConfig defines configuration for OS build operations
type OSBuildsConfig struct {
	// Enabled determines if Tekton tasks for OS builds should be deployed
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// UseMemoryVolumes determines whether to use memory-backed volumes for build operations
	// +optional
	UseMemoryVolumes bool `json:"useMemoryVolumes,omitempty"`

	// MemoryVolumeSize specifies the size limit for memory-backed volumes (required if UseMemoryVolumes is true)
	// Example: "2Gi"
	// +optional
	MemoryVolumeSize string `json:"memoryVolumeSize,omitempty"`

	// PVCSize specifies the size for persistent volume claims created for build workspaces
	// Default: "8Gi"
	// +optional
	PVCSize string `json:"pvcSize,omitempty"`

	// RuntimeClassName specifies the runtime class to use for the build pod
	// More info: https://kubernetes.io/docs/concepts/containers/runtime-class/
	// +optional
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// ServeExpiryHours specifies how long to serve build artifacts before automatic cleanup
	// Default: 24
	// +optional
	ServeExpiryHours int32 `json:"serveExpiryHours,omitempty"`

	// ClusterRegistryRoute is the external route for the cluster's internal image registry
	// Required for bootc builds to allow nested containers to pull builder images
	// Example: "default-route-openshift-image-registry.apps.mycluster.example.com"
	// +optional
	ClusterRegistryRoute string `json:"clusterRegistryRoute,omitempty"`

	// NodeSelector specifies node labels that build pods must match for scheduling
	// These labels are added to the pod template used by Tekton PipelineRuns
	// Example: {"dedicated": "builds", "disktype": "ssd"}
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations specifies tolerations to be added to build pods
	// Enables scheduling on tainted nodes for dedicated/exclusive access
	// Example: [{"key": "automotive.sdv.cloud.redhat.com/dedicated", "operator": "Equal", "value": "builds", "effect": "NoSchedule"}]
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// OperatorConfigStatus defines the observed state of OperatorConfig
type OperatorConfigStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase represents the current phase (Ready, Reconciling, Failed)
	Phase string `json:"phase,omitempty"`

	// Message provides detail about the current phase
	Message string `json:"message,omitempty"`

	// OSBuildsDeployed indicates if the OS Builds Tekton tasks are currently deployed
	OSBuildsDeployed bool `json:"osBuildsDeployed,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="OS Builds",type="boolean",JSONPath=".spec.osBuilds.enabled"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// OperatorConfig is the Schema for the operatorconfigs API
type OperatorConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OperatorConfigSpec   `json:"spec,omitempty"`
	Status OperatorConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OperatorConfigList contains a list of OperatorConfig
type OperatorConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OperatorConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OperatorConfig{}, &OperatorConfigList{})
}
