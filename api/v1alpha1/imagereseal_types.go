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

// ImageResealSpec defines the desired state of ImageReseal
type ImageResealSpec struct {
	// Operation is the AIB sealed operation when running a single stage (ignored if Stages is set).
	// +kubebuilder:validation:Enum=prepare-reseal;reseal;extract-for-signing;inject-signed
	Operation string `json:"operation,omitempty"`

	// Stages is an ordered list of operations to run as a pipeline. If set, Operation is ignored.
	// Example: [prepare-reseal, extract-for-signing, inject-signed, reseal]
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Stages []string `json:"stages,omitempty"`

	// InputRef is the OCI reference to the input disk image
	// +kubebuilder:validation:Required
	InputRef string `json:"inputRef"`

	// OutputRef is the OCI reference where to push the result (optional for extract-for-signing)
	OutputRef string `json:"outputRef,omitempty"`

	// SignedRef is the OCI reference to signed artifacts; required when operation is inject-signed
	SignedRef string `json:"signedRef,omitempty"`

	// AIBImage is the automotive-image-builder container image to use
	AIBImage string `json:"aibImage,omitempty"`

	// BuilderImage is the osbuild builder container image to use (needed for prepare-reseal and reseal).
	// If empty, a default is computed from architecture and the internal registry.
	BuilderImage string `json:"builderImage,omitempty"`

	// Architecture overrides the target architecture for the builder image (e.g., "amd64", "arm64").
	// If empty, auto-detected from the node running the task.
	Architecture string `json:"architecture,omitempty"`

	// StorageClass for the workspace (optional)
	StorageClass string `json:"storageClass,omitempty"`

	// SecretRef is the name of the secret containing registry credentials
	// (REGISTRY_URL, REGISTRY_USERNAME, REGISTRY_PASSWORD)
	SecretRef string `json:"secretRef,omitempty"`

	// KeySecretRef is the name of a secret containing the sealing key.
	// The secret must have a data key named "private-key" with the PEM-encoded key.
	// Optional for prepare-reseal and reseal: if not set, aib may use an ephemeral key.
	KeySecretRef string `json:"keySecretRef,omitempty"`

	// KeyPasswordSecretRef is the name of a secret containing the password for an encrypted key.
	// The secret must have a data key named "password". Optional.
	KeyPasswordSecretRef string `json:"keyPasswordSecretRef,omitempty"`

	// AIBExtraArgs are extra arguments to pass to AIB
	AIBExtraArgs []string `json:"aibExtraArgs,omitempty"`
}

// ImageResealStatus defines the observed state of ImageReseal
type ImageResealStatus struct {
	// Phase represents the current phase of the sealed operation
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// Message provides additional details about the current phase
	Message string `json:"message,omitempty"`

	// TaskRunName is the name of the Tekton TaskRun (single-stage runs)
	TaskRunName string `json:"taskRunName,omitempty"`

	// PipelineRunName is the name of the Tekton PipelineRun (multi-stage runs)
	PipelineRunName string `json:"pipelineRunName,omitempty"`

	// OutputRef is the OCI reference where the result was pushed (after completion)
	OutputRef string `json:"outputRef,omitempty"`

	// StartTime is when the sealed operation started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the sealed operation completed
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Operation",type=string,JSONPath=`.spec.operation`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageReseal is the Schema for the imagereseals API.
// It triggers an AIB sealed operation (prepare-reseal, reseal, extract-for-signing, inject-signed) on a disk image.
type ImageReseal struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageResealSpec   `json:"spec,omitempty"`
	Status ImageResealStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageResealList contains a list of ImageReseal
type ImageResealList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageReseal `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageReseal{}, &ImageResealList{})
}

// GetAIBImage returns the AIB container image, or default if not set
func (s *ImageResealSpec) GetAIBImage() string {
	if s.AIBImage != "" {
		return s.AIBImage
	}
	return "quay.io/centos-sig-automotive/automotive-image-builder:latest"
}

// GetStages returns the ordered list of stages to run. Uses Stages if set, otherwise []string{Operation}.
// Returns nil if neither is set (invalid spec).
func (s *ImageResealSpec) GetStages() []string {
	if len(s.Stages) > 0 {
		return s.Stages
	}
	if s.Operation != "" {
		return []string{s.Operation}
	}
	return nil
}
