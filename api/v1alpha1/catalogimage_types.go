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

// CatalogImageSpec defines the desired state of CatalogImage
type CatalogImageSpec struct {
	// RegistryURL is the full URL to the image in the container registry
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*:[a-zA-Z0-9_][a-zA-Z0-9._-]*$|^[a-z0-9]+([._-][a-z0-9]+)*\.[a-z]{2,}(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)*:[a-zA-Z0-9_][a-zA-Z0-9._-]*$|^[a-z0-9]+([._-][a-z0-9]+)*\.[a-z]{2,}(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$`
	RegistryURL string `json:"registryUrl"`

	// Digest is the immutable content-addressable identifier (sha256:...)
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +optional
	Digest string `json:"digest,omitempty"`

	// Tags are mutable labels for categorization
	// +optional
	Tags []string `json:"tags,omitempty"`

	// AuthSecretRef references the secret containing registry credentials
	// +optional
	AuthSecretRef *AuthSecretReference `json:"authSecretRef,omitempty"`

	// VerificationInterval specifies how often to verify registry accessibility
	// +kubebuilder:default="1h"
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	// +optional
	VerificationInterval string `json:"verificationInterval,omitempty"`

	// Metadata contains automotive-specific image metadata
	// +optional
	Metadata *CatalogImageMetadata `json:"metadata,omitempty"`
}

// AuthSecretReference references a secret containing registry credentials
type AuthSecretReference struct {
	// Name is the name of the secret containing registry credentials
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace is the namespace of the secret (defaults to CatalogImage namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// CatalogImageMetadata contains automotive-specific platform information
type CatalogImageMetadata struct {
	// Architecture is the CPU architecture
	// Supports both AIB canonical values (x86_64, aarch64) and OCI standard names (amd64, arm64)
	// +optional
	Architecture string `json:"architecture,omitempty"`

	// OS is the operating system (defaults to linux)
	// +kubebuilder:default="linux"
	// +optional
	OS string `json:"os,omitempty"`

	// Variant is the architecture variant (e.g., v7 for armv7)
	// +optional
	Variant string `json:"variant,omitempty"`

	// Distro is the distribution identifier
	// Common values include: autosd, autosd10-sig, autosd9, cs8, fedora-39, fedora-40, rhel9, rhel8
	// Run 'aib list-dist' to see all available distributions
	// +optional
	Distro string `json:"distro,omitempty"`

	// DistroVersion is the distribution version
	// +optional
	DistroVersion string `json:"distroVersion,omitempty"`

	// Targets lists compatible hardware targets
	// +optional
	Targets []HardwareTarget `json:"targets,omitempty"`

	// Bootc indicates if this is a bootc-compatible image
	// +optional
	Bootc bool `json:"bootc,omitempty"`

	// BuildMode indicates the AIB build mode used (bootc, image, package)
	// +kubebuilder:validation:Enum=bootc;image;package
	// +optional
	BuildMode string `json:"buildMode,omitempty"`

	// ExportFormat indicates the disk image format produced by AIB
	// Common values include: qcow2, raw, image, vmdk, iso, vhd, tar
	// +optional
	ExportFormat string `json:"exportFormat,omitempty"`
}

// HardwareTarget represents a hardware platform the image supports
type HardwareTarget struct {
	// Name is the target hardware identifier
	// Common values include: qemu, raspberry-pi, beaglebone, generic
	// Run 'aib list-targets' to see all available hardware targets
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Verified indicates if the image has been tested on this target
	// +kubebuilder:default=false
	// +optional
	Verified bool `json:"verified,omitempty"`

	// Notes contains target-specific information
	// +optional
	Notes string `json:"notes,omitempty"`
}

// CatalogImagePhase represents the current lifecycle phase
// +kubebuilder:validation:Enum=Pending;Verifying;Available;Unavailable;Failed
type CatalogImagePhase string

const (
	// CatalogImagePhasePending indicates the image is newly created
	CatalogImagePhasePending CatalogImagePhase = "Pending"
	// CatalogImagePhaseVerifying indicates the controller is checking registry accessibility
	CatalogImagePhaseVerifying CatalogImagePhase = "Verifying"
	// CatalogImagePhaseAvailable indicates the image is accessible and metadata extracted
	CatalogImagePhaseAvailable CatalogImagePhase = "Available"
	// CatalogImagePhaseUnavailable indicates temporary registry issues, will retry
	CatalogImagePhaseUnavailable CatalogImagePhase = "Unavailable"
	// CatalogImagePhaseFailed indicates permanent error requiring user intervention
	CatalogImagePhaseFailed CatalogImagePhase = "Failed"
)

// CatalogImageStatus defines the observed state of CatalogImage
type CatalogImageStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase represents the current lifecycle phase
	// +optional
	Phase CatalogImagePhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RegistryMetadata contains metadata extracted from the registry
	// +optional
	RegistryMetadata *RegistryMetadata `json:"registryMetadata,omitempty"`

	// LastVerificationTime is when the registry was last verified
	// +optional
	LastVerificationTime *metav1.Time `json:"lastVerificationTime,omitempty"`

	// AccessCount tracks how many times this image has been accessed
	// +optional
	AccessCount int64 `json:"accessCount,omitempty"`

	// PublishedAt is when this image was published to the catalog
	// +optional
	PublishedAt *metav1.Time `json:"publishedAt,omitempty"`

	// SourceImageBuild references the ImageBuild that created this catalog entry
	// +optional
	SourceImageBuild string `json:"sourceImageBuild,omitempty"`

	// ArtifactRefs contains references to downloadable artifacts
	// +optional
	ArtifactRefs []ArtifactReference `json:"artifactRefs,omitempty"`
}

// ArtifactReference represents a downloadable artifact associated with the image
type ArtifactReference struct {
	// Type is the artifact type (e.g., qcow2, raw, vmdk, container, iso)
	// +kubebuilder:validation:Required
	Type string `json:"type"`

	// URL is the download URL for the artifact
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// Digest is the content digest for verification (sha256:...)
	// +optional
	Digest string `json:"digest,omitempty"`

	// SizeBytes is the size of the artifact in bytes
	// +optional
	SizeBytes int64 `json:"sizeBytes,omitempty"`

	// Format contains format-specific information
	// +optional
	Format string `json:"format,omitempty"`
}

// RegistryMetadata contains metadata extracted from the container registry
type RegistryMetadata struct {
	// ResolvedDigest is the digest resolved from the registry
	// +optional
	ResolvedDigest string `json:"resolvedDigest,omitempty"`

	// MediaType is the OCI manifest media type
	// +optional
	MediaType string `json:"mediaType,omitempty"`

	// SizeBytes is the total image size in bytes
	// +optional
	SizeBytes int64 `json:"sizeBytes,omitempty"`

	// LayerCount is the number of image layers
	// +optional
	LayerCount int `json:"layerCount,omitempty"`

	// Platform contains platform information from the manifest
	// +optional
	Platform *PlatformInfo `json:"platform,omitempty"`

	// CreatedAt is when the image was created in the registry
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	// IsMultiArch indicates if this is a multi-architecture manifest list
	// +optional
	IsMultiArch bool `json:"isMultiArch,omitempty"`

	// PlatformVariants contains information about available platform variants
	// Only populated for multi-arch images
	// +optional
	PlatformVariants []PlatformVariant `json:"platformVariants,omitempty"`
}

// PlatformVariant represents a platform-specific variant in a multi-arch image
type PlatformVariant struct {
	// Architecture is the CPU architecture (amd64, arm64, etc.)
	// +optional
	Architecture string `json:"architecture,omitempty"`

	// OS is the operating system
	// +optional
	OS string `json:"os,omitempty"`

	// Variant is the architecture variant (v7, v8, etc.)
	// +optional
	Variant string `json:"variant,omitempty"`

	// Digest is the digest for this specific platform variant
	// +optional
	Digest string `json:"digest,omitempty"`

	// SizeBytes is the size of this variant in bytes
	// +optional
	SizeBytes int64 `json:"sizeBytes,omitempty"`
}

// PlatformInfo contains platform information from the OCI manifest
type PlatformInfo struct {
	// Architecture is the platform architecture
	// +optional
	Architecture string `json:"architecture,omitempty"`

	// OS is the platform operating system
	// +optional
	OS string `json:"os,omitempty"`

	// Variant is the platform variant
	// +optional
	Variant string `json:"variant,omitempty"`
}

// Condition types for CatalogImage
const (
	// CatalogImageConditionAvailable indicates the image is available in the registry
	CatalogImageConditionAvailable = "Available"
	// CatalogImageConditionVerified indicates the image was successfully verified
	CatalogImageConditionVerified = "Verified"
	// CatalogImageConditionReady indicates the image is ready for use
	CatalogImageConditionReady = "Ready"
)

// Label keys for CatalogImage
const (
	// LabelArchitecture is the label key for architecture
	LabelArchitecture = "automotive.sdv.cloud.redhat.com/architecture"
	// LabelDistro is the label key for distribution
	LabelDistro = "automotive.sdv.cloud.redhat.com/distro"
	// LabelTarget is the label key for hardware target
	LabelTarget = "automotive.sdv.cloud.redhat.com/target"
	// LabelBootc is the label key for bootc compatibility
	LabelBootc = "automotive.sdv.cloud.redhat.com/bootc"
	// LabelRegistryType is the label key for registry type
	LabelRegistryType = "automotive.sdv.cloud.redhat.com/registry-type"
	// LabelSourceType is the label key for source type
	LabelSourceType = "automotive.sdv.cloud.redhat.com/source-type"
)

// Finalizer for CatalogImage
const (
	// CatalogImageFinalizer is the finalizer for CatalogImage cleanup
	CatalogImageFinalizer = "catalogimage.automotive.sdv.cloud.redhat.com/finalizer"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registryUrl`,priority=0
// +kubebuilder:printcolumn:name="Architecture",type=string,JSONPath=`.spec.metadata.architecture`,priority=0
// +kubebuilder:printcolumn:name="Distro",type=string,JSONPath=`.spec.metadata.distro`,priority=0
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`,priority=0
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,priority=0

// CatalogImage is the Schema for the catalogimages API
type CatalogImage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CatalogImageSpec   `json:"spec,omitempty"`
	Status CatalogImageStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CatalogImageList contains a list of CatalogImage
type CatalogImageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CatalogImage `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CatalogImage{}, &CatalogImageList{})
}
