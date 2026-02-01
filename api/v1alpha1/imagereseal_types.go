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
	// SourceContainer is the bootc container image to reseal
	// +kubebuilder:validation:Required
	SourceContainer string `json:"sourceContainer"`

	// TargetContainer is the registry URL to push the resealed container
	// +kubebuilder:validation:Required
	TargetContainer string `json:"targetContainer"`

	// SealKeySecretRef references a secret containing the Ed25519 private key
	// The secret should have a key named "private-key" with the PEM-encoded key
	// If not provided, an ephemeral key will be generated for one-time use
	SealKeySecretRef string `json:"sealKeySecretRef,omitempty"`

	// SealKeyPasswordSecretRef references a secret containing the password for encrypted keys
	// The secret should have a key named "password"
	SealKeyPasswordSecretRef string `json:"sealKeyPasswordSecretRef,omitempty"`

	// AutomotiveImageBuilder is the AIB container image to use for the reseal operation
	// +kubebuilder:default="quay.io/centos-sig-automotive/automotive-image-builder:latest"
	AutomotiveImageBuilder string `json:"automotiveImageBuilder,omitempty"`

	// BuilderImage is the osbuild builder container image to use
	// Required for reseal operations - the builder runs rpm-ostree compose
	// +kubebuilder:validation:Required
	BuilderImage string `json:"builderImage"`

	// EnvSecretRef references a secret containing registry credentials
	// The secret can contain REGISTRY_URL, REGISTRY_USERNAME, REGISTRY_PASSWORD
	EnvSecretRef string `json:"envSecretRef,omitempty"`

	// StorageClass for the workspace PVC used during reseal
	StorageClass string `json:"storageClass,omitempty"`
}

// ImageResealStatus defines the observed state of ImageReseal
type ImageResealStatus struct {
	// Phase represents the current phase of the reseal operation
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// Message provides additional details about the current phase
	Message string `json:"message,omitempty"`

	// TaskRunName is the name of the Tekton TaskRun executing this reseal
	TaskRunName string `json:"taskRunName,omitempty"`

	// SealedContainer is the URL of the resealed container after completion
	SealedContainer string `json:"sealedContainer,omitempty"`

	// StartTime is when the reseal operation started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the reseal operation completed
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Source",type="string",JSONPath=".spec.sourceContainer"
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.targetContainer"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ImageReseal is the Schema for the imagereseals API
// It triggers a reseal operation on a bootc container image, re-signing it with a new Ed25519 key
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

// ─── Helper methods ───

// GetAIBImage returns the AIB container image, or default if not set
func (s *ImageResealSpec) GetAIBImage() string {
	if s.AutomotiveImageBuilder != "" {
		return s.AutomotiveImageBuilder
	}
	return "quay.io/centos-sig-automotive/automotive-image-builder:latest"
}

// HasSealKey returns true if a seal key secret is configured
func (s *ImageResealSpec) HasSealKey() bool {
	return s.SealKeySecretRef != ""
}

// HasSealKeyPassword returns true if a seal key password secret is configured
func (s *ImageResealSpec) HasSealKeyPassword() bool {
	return s.SealKeyPasswordSecretRef != ""
}
