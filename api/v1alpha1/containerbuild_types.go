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

// ContainerBuildSpec defines the desired state of ContainerBuild
type ContainerBuildSpec struct {
	// Dockerfile is the path to the Containerfile/Dockerfile within the build context
	// +kubebuilder:default="Containerfile"
	Dockerfile string `json:"dockerfile,omitempty"`

	// Output is the registry URL to push the built image (e.g., quay.io/org/image:tag)
	// +kubebuilder:validation:Required
	Output string `json:"output"`

	// BuildArgs are optional KEY=VALUE pairs passed as build arguments
	BuildArgs []string `json:"buildArgs,omitempty"`

	// Architecture specifies the target architecture (e.g., "amd64", "arm64")
	Architecture string `json:"architecture,omitempty"`

	// StorageClass is the name of the storage class to use for the build context PVC
	StorageClass string `json:"storageClass,omitempty"`

	// RuntimeClassName specifies the runtime class to use for the build pod
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// SecretRef is the name of a kubernetes.io/dockerconfigjson secret for registry auth
	SecretRef string `json:"secretRef,omitempty"`
}

// ContainerBuildStatus defines the observed state of ContainerBuild
type ContainerBuildStatus struct {
	// Phase represents the current phase of the container build
	// +kubebuilder:validation:Enum=Pending;Uploading;Building;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// Message provides more detail about the current phase
	Message string `json:"message,omitempty"`

	// BuildRunName is the name of the Shipwright BuildRun for this build
	BuildRunName string `json:"buildRunName,omitempty"`

	// PVCName is the name of the PVC where the build context is stored
	PVCName string `json:"pvcName,omitempty"`

	// StartTime is when the build started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the build finished
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Conditions represent the latest available observations of the ContainerBuild's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Output",type=string,JSONPath=`.spec.output`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ContainerBuild is the Schema for the containerbuilds API
type ContainerBuild struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ContainerBuildSpec   `json:"spec,omitempty"`
	Status ContainerBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ContainerBuildList contains a list of ContainerBuild
type ContainerBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ContainerBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ContainerBuild{}, &ContainerBuildList{})
}
