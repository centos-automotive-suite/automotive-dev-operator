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

// SoftwareBuildSourceType identifies where source code is obtained from.
type SoftwareBuildSourceType string

// SoftwareBuildSourceType values.
const (
	SoftwareBuildSourceGit SoftwareBuildSourceType = "git"
	SoftwareBuildSourcePVC SoftwareBuildSourceType = "pvc"
)

// SoftwareBuildDestinationType identifies where build artifacts are stored.
type SoftwareBuildDestinationType string

// SoftwareBuildDestinationType values.
const (
	SoftwareBuildDestSharedFolder SoftwareBuildDestinationType = "sharedFolder"
)

// SoftwareBuildPhase represents the current lifecycle phase.
type SoftwareBuildPhase string

// SoftwareBuildPhase values.
const (
	SoftwareBuildPhasePending   SoftwareBuildPhase = "Pending"
	SoftwareBuildPhaseRunning   SoftwareBuildPhase = "Running"
	SoftwareBuildPhaseSucceeded SoftwareBuildPhase = "Succeeded"
	SoftwareBuildPhaseFailed    SoftwareBuildPhase = "Failed"
)

// SoftwareBuildSecretReference points to a Kubernetes Secret.
type SoftwareBuildSecretReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +optional
	Key string `json:"key,omitempty"`
}

// SoftwareBuildRuntimeSpec configures the container environment used for every
// pipeline stage unless overridden per-stage.
type SoftwareBuildRuntimeSpec struct {
	// Image is the container image that provides the build toolchain.
	// +kubebuilder:default="ubuntu:24.04"
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image,omitempty"`

	// ServiceAccountName is the Kubernetes SA the build pod runs as.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
}

// SoftwareBuildGitSource describes a Git repository to clone.
type SoftwareBuildGitSource struct {
	// +kubebuilder:validation:Pattern=`^https?://[^\s;|&$'"]+$`
	URL string `json:"url"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._/-]+$`
	// +kubebuilder:default=main
	Revision string `json:"revision,omitempty"`
	// CredentialsSecretRef references a secret for private repo access (not yet implemented).
	// +optional
	CredentialsSecretRef *SoftwareBuildSecretReference `json:"credentialsSecretRef,omitempty"`
}

// SoftwareBuildPVCSource references an existing PVC.
type SoftwareBuildPVCSource struct {
	// +kubebuilder:validation:MinLength=1
	ClaimName string `json:"claimName"`
	// +kubebuilder:default=/
	Path string `json:"path,omitempty"`
}

// SoftwareBuildSourceSpec identifies the code location.
// +kubebuilder:validation:XValidation:rule="self.type != 'git' || has(self.git)",message="git source details required when type is git"
// +kubebuilder:validation:XValidation:rule="self.type != 'pvc' || has(self.pvc)",message="pvc source details required when type is pvc"
type SoftwareBuildSourceSpec struct {
	// +kubebuilder:validation:Enum=git;pvc
	Type SoftwareBuildSourceType `json:"type"`
	// +optional
	Git *SoftwareBuildGitSource `json:"git,omitempty"`
	// +optional
	PVC *SoftwareBuildPVCSource `json:"pvc,omitempty"`
}

// SoftwareBuildStageSpec defines a single pipeline stage.
type SoftwareBuildStageSpec struct {
	// Command is executed via bash inside the runtime image.
	// +kubebuilder:validation:MinLength=1
	Command string `json:"command"`
	// Image overrides the runtime image for this stage only.
	// +optional
	Image string `json:"image,omitempty"`
}

// SoftwareBuildPipelineStages groups the five sequential stages.
type SoftwareBuildPipelineStages struct {
	Fetch     SoftwareBuildStageSpec `json:"fetch"`
	Prebuild  SoftwareBuildStageSpec `json:"prebuild"`
	Build     SoftwareBuildStageSpec `json:"build"`
	Postbuild SoftwareBuildStageSpec `json:"postbuild"`
	Deploy    SoftwareBuildStageSpec `json:"deploy"`
}

// SoftwareBuildDestinationSpec describes where artifacts go.
type SoftwareBuildDestinationSpec struct {
	// +kubebuilder:validation:Enum=sharedFolder
	Type SoftwareBuildDestinationType `json:"type"`
	// +optional
	Path string `json:"path,omitempty"`
}

// SoftwareBuildSpec defines the desired state of SoftwareBuild.
type SoftwareBuildSpec struct {
	// +optional
	Runtime     SoftwareBuildRuntimeSpec     `json:"runtime,omitempty"`
	Source      SoftwareBuildSourceSpec      `json:"source"`
	Stages      SoftwareBuildPipelineStages  `json:"stages"`
	Destination SoftwareBuildDestinationSpec `json:"destination"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	TimeoutSeconds int64 `json:"timeoutSeconds,omitempty"`
}

// SoftwareBuildStageStatus captures per-stage progress.
type SoftwareBuildStageStatus struct {
	Name string `json:"name,omitempty"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	FinishedAt *metav1.Time `json:"finishedAt,omitempty"`
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

// SoftwareBuildStatus defines the observed state of SoftwareBuild.
type SoftwareBuildStatus struct {
	// +optional
	Phase SoftwareBuildPhase `json:"phase,omitempty"`
	// +optional
	PipelineRunName string `json:"pipelineRunName,omitempty"`
	// +optional
	ArtifactURI string `json:"artifactURI,omitempty"`
	// +optional
	FailureReason string `json:"failureReason,omitempty"`
	// +optional
	Stages []SoftwareBuildStageStatus `json:"stages,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=softwarebuilds,scope=Namespaced,shortName=sb
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.runtime.image`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SoftwareBuild is the Schema for the softwarebuilds API.
// It drives a generic, stage-based Tekton pipeline that can build software
// for any target OS or toolchain by specifying a runtime container image and
// five sequential shell commands.
type SoftwareBuild struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SoftwareBuildSpec   `json:"spec,omitempty"`
	Status SoftwareBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SoftwareBuildList contains a list of SoftwareBuild.
type SoftwareBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SoftwareBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SoftwareBuild{}, &SoftwareBuildList{})
}
