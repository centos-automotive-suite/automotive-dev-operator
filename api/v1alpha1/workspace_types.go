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

// WorkspaceSpec defines the desired state of a developer workspace.
type WorkspaceSpec struct {
	// Architecture is the target architecture (e.g., "arm64", "amd64")
	Architecture string `json:"architecture,omitempty"`

	// Image is the toolchain container image to use
	Image string `json:"image,omitempty"`

	// LeaseID is the Jumpstarter lease ID for board access
	LeaseID string `json:"leaseID,omitempty"`

	// Owner is the authenticated user who created this workspace
	Owner string `json:"owner"`

	// ClientConfigSecretRef is the name of the Secret containing the Jumpstarter client config
	// The secret should have a key "client.yaml"
	ClientConfigSecretRef string `json:"clientConfigSecretRef,omitempty"`

	// PVCSize is the size of the persistent volume for workspace storage
	// +kubebuilder:default="10Gi"
	PVCSize string `json:"pvcSize,omitempty"`

	// StorageClass is the storage class for workspace PVCs
	// If empty, the cluster default storage class is used
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// Resources defines the CPU and memory requests/limits for the workspace container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// WorkspaceStatus defines the observed state of a Workspace.
type WorkspaceStatus struct {
	// Phase is the current phase of the workspace
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Failed;Terminating
	Phase string `json:"phase,omitempty"`

	// PodName is the name of the workspace pod
	PodName string `json:"podName,omitempty"`

	// PVCName is the generated name of the workspace PVC
	PVCName string `json:"pvcName,omitempty"`

	// Message provides additional detail about the current phase
	Message string `json:"message,omitempty"`

	// BuildCachePVCName is the name of the PVC used for build cache storage.
	// Created lazily on first build referencing this workspace.
	// +optional
	BuildCachePVCName string `json:"buildCachePVCName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Owner",type=string,JSONPath=`.spec.owner`
// +kubebuilder:printcolumn:name="Arch",type=string,JSONPath=`.spec.architecture`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Lease",type=string,JSONPath=`.spec.leaseID`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Workspace is the Schema for the workspaces API
type Workspace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkspaceSpec   `json:"spec,omitempty"`
	Status WorkspaceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WorkspaceList contains a list of Workspace
type WorkspaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Workspace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Workspace{}, &WorkspaceList{})
}
