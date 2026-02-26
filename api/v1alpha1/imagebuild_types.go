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
	// ─── Common fields ───

	// Architecture specifies the target architecture (e.g., "amd64", "arm64")
	Architecture string `json:"architecture,omitempty"`

	// StorageClass is the name of the storage class to use for the build PVC
	StorageClass string `json:"storageClass,omitempty"`

	// RuntimeClassName specifies the runtime class to use for the build pod
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// SecretRef is the name of the secret containing credentials for registry operations
	// The secret should contain keys like REGISTRY_AUTH_FILE for authentication
	SecretRef string `json:"secretRef,omitempty"`

	// PushSecretRef is the name of the kubernetes.io/dockerconfigjson secret for pushing artifacts
	// This is separate from SecretRef because push operations require docker config format
	PushSecretRef string `json:"pushSecretRef,omitempty"`

	// ─── Nested configuration ───

	// AIB contains automotive-image-builder specific configuration
	AIB *AIBSpec `json:"aib,omitempty"`

	// Export contains configuration for exporting build artifacts
	Export *ExportSpec `json:"export,omitempty"`

	// Flash contains configuration for flashing the built image to hardware via Jumpstarter
	Flash *FlashSpec `json:"flash,omitempty"`
}

// FlashSpec defines configuration for flashing images to hardware via Jumpstarter
// The exporter selector and flash command are derived from OperatorConfig's JumpstarterTargetMappings
// based on the AIB target field
type FlashSpec struct {
	// ClientConfigSecretRef is the name of the secret containing the Jumpstarter client config
	// The secret should have a key "client.yaml" with the config contents
	// If set, flash is enabled automatically
	ClientConfigSecretRef string `json:"clientConfigSecretRef,omitempty"`

	// LeaseDuration is the duration for the device lease in HH:MM:SS format
	// +kubebuilder:default="03:00:00"
	LeaseDuration string `json:"leaseDuration,omitempty"`
}

// AIBSpec defines the automotive-image-builder configuration
type AIBSpec struct {
	// Distro specifies the distribution to build for (e.g., "autosd")
	// +kubebuilder:validation:Required
	Distro string `json:"distro"`

	// Target specifies the build target platform (e.g., "qemu", "aws")
	// +kubebuilder:validation:Required
	Target string `json:"target"`

	// Mode specifies the build mode
	// +kubebuilder:validation:Enum=package;image;bootc;disk
	// +kubebuilder:default=image
	Mode string `json:"mode,omitempty"`

	// Manifest holds the inline AIB manifest YAML content
	Manifest string `json:"manifest,omitempty" yaml:"manifest,omitempty"`

	// ManifestFileName is the original filename of the manifest, used for naming the file
	// when writing it to disk before invoking automotive-image-builder
	ManifestFileName string `json:"manifestFileName,omitempty" yaml:"manifestFileName,omitempty"`

	// Image specifies the automotive-image-builder container image to use
	// If not specified, the default from OperatorConfig is used
	Image string `json:"image,omitempty"`

	// BuilderImage specifies a custom osbuild builder container image
	// If not specified for bootc builds, one is automatically built and cached
	BuilderImage string `json:"builderImage,omitempty"`

	// RebuildBuilder forces rebuilding the bootc builder image even if a cached version exists in the registry.
	RebuildBuilder bool `json:"rebuildBuilder,omitempty"`

	// InputFilesServer indicates if an upload server should be created for local file references
	// When true, the build waits in "Uploading" phase until files are uploaded
	InputFilesServer bool `json:"inputFilesServer,omitempty"`

	// ContainerRef is the reference to an existing bootc container image
	// Required when mode=disk to create a disk image from an existing container
	ContainerRef string `json:"containerRef,omitempty"`

	// CustomDefs are custom environment variable definitions for the build
	CustomDefs []string `json:"customDefs,omitempty"`

	// AIBExtraArgs are extra arguments to pass to automotive-image-builder
	AIBExtraArgs []string `json:"aibExtraArgs,omitempty"`
}

// ExportSpec defines the configuration for exporting build artifacts
type ExportSpec struct {
	// Format specifies the disk image output format (e.g., raw, qcow2, simg, or any AIB-supported format)
	// +kubebuilder:default=qcow2
	Format string `json:"format,omitempty"`

	// Compression specifies the compression algorithm for artifacts
	// +kubebuilder:validation:Enum=lz4;gzip;xz
	// +kubebuilder:default=gzip
	Compression string `json:"compression,omitempty"`

	// BuildDiskImage indicates whether to build a disk image from the bootc container
	BuildDiskImage bool `json:"buildDiskImage,omitempty"`

	// Container is the OCI registry URL to push the bootc container image
	Container string `json:"container,omitempty"`

	// UseServiceAccountAuth indicates the build should authenticate to the registry
	// using a service account token instead of explicit credentials
	UseServiceAccountAuth bool `json:"useServiceAccountAuth,omitempty"`

	// Disk contains configuration for disk image export
	Disk *DiskExport `json:"disk,omitempty"`
}

// DiskExport defines where to export the disk image
// Currently supports OCI registries, extensible for future storage types
type DiskExport struct {
	// OCI is the registry URL to push the disk image as an OCI artifact
	OCI string `json:"oci,omitempty"`

	// Future storage options:
	// S3 *S3Export `json:"s3,omitempty"`
	// PVC *PVCExport `json:"pvc,omitempty"`
}

// ImageBuildStatus defines the observed state of ImageBuild
type ImageBuildStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase represents the current phase of the build (Building, Completed, Failed)
	// +kubebuilder:validation:Enum=Pending;Uploading;Building;Pushing;Flashing;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// StartTime is when the build started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the build finished
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Message provides more detail about the current phase
	Message string `json:"message,omitempty"`

	// PVCName is the name of the PVC where the artifact is stored
	PVCName string `json:"pvcName,omitempty"`

	// PipelineRunName is the name of the active PipelineRun for this build
	PipelineRunName string `json:"pipelineRunName,omitempty"`

	// PushTaskRunName is the name of the TaskRun for pushing artifacts to registry
	PushTaskRunName string `json:"pushTaskRunName,omitempty"`

	// FlashTaskRunName is the name of the TaskRun for flashing to hardware
	FlashTaskRunName string `json:"flashTaskRunName,omitempty"`

	// Conditions represent the latest available observations of the ImageBuild's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ─── Provenance ───

	// AIBImageUsed is the automotive-image-builder container image that was used for the build
	// +optional
	AIBImageUsed string `json:"aibImageUsed,omitempty"`

	// BuilderImageUsed is the osbuild builder container image that was used for the build
	// This is particularly useful for bootc builds where the builder may be auto-generated
	// +optional
	BuilderImageUsed string `json:"builderImageUsed,omitempty"`

	// LeaseID is the Jumpstarter lease ID acquired during flash
	// +optional
	LeaseID string `json:"leaseId,omitempty"`
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

// ─── Helper methods for safe access to nested fields ───

// GetDistro returns the distro from AIB spec, or empty string if not set
func (s *ImageBuildSpec) GetDistro() string {
	if s.AIB != nil {
		return s.AIB.Distro
	}
	return ""
}

// GetTarget returns the target from AIB spec, or empty string if not set
func (s *ImageBuildSpec) GetTarget() string {
	if s.AIB != nil {
		return s.AIB.Target
	}
	return ""
}

// GetMode returns the mode from AIB spec, or "image" as default
func (s *ImageBuildSpec) GetMode() string {
	if s.AIB != nil && s.AIB.Mode != "" {
		return s.AIB.Mode
	}
	return "image"
}

// GetManifest returns the inline manifest YAML content from AIB spec
func (s *ImageBuildSpec) GetManifest() string {
	if s.AIB != nil {
		return s.AIB.Manifest
	}
	return ""
}

// GetManifestFileName returns the manifest filename from AIB spec
func (s *ImageBuildSpec) GetManifestFileName() string {
	if s.AIB != nil {
		return s.AIB.ManifestFileName
	}
	return ""
}

// GetAIBImage returns the AIB container image from AIB spec
func (s *ImageBuildSpec) GetAIBImage() string {
	if s.AIB != nil {
		return s.AIB.Image
	}
	return ""
}

// GetBuilderImage returns the builder image from AIB spec
func (s *ImageBuildSpec) GetBuilderImage() string {
	if s.AIB != nil {
		return s.AIB.BuilderImage
	}
	return ""
}

// GetInputFilesServer returns whether input files server is enabled
func (s *ImageBuildSpec) GetInputFilesServer() bool {
	if s.AIB != nil {
		return s.AIB.InputFilesServer
	}
	return false
}

// GetContainerRef returns the container reference from AIB spec
func (s *ImageBuildSpec) GetContainerRef() string {
	if s.AIB != nil {
		return s.AIB.ContainerRef
	}
	return ""
}

// GetCustomDefs returns the custom environment variable definitions from AIB spec
func (s *ImageBuildSpec) GetCustomDefs() []string {
	if s.AIB != nil {
		return s.AIB.CustomDefs
	}
	return nil
}

// GetAIBExtraArgs returns extra arguments to pass to automotive-image-builder
func (s *ImageBuildSpec) GetAIBExtraArgs() []string {
	if s.AIB != nil {
		return s.AIB.AIBExtraArgs
	}
	return nil
}

// GetExportFormat returns the export format, or "qcow2" as default
func (s *ImageBuildSpec) GetExportFormat() string {
	if s.Export != nil && s.Export.Format != "" {
		return s.Export.Format
	}
	return "qcow2"
}

// GetCompression returns the compression algorithm, or "gzip" as default
func (s *ImageBuildSpec) GetCompression() string {
	if s.Export != nil && s.Export.Compression != "" {
		return s.Export.Compression
	}
	return "gzip"
}

// GetBuildDiskImage returns whether to build a disk image
func (s *ImageBuildSpec) GetBuildDiskImage() bool {
	if s.Export != nil {
		return s.Export.BuildDiskImage
	}
	return false
}

// GetContainerPush returns the container push URL from Export spec
func (s *ImageBuildSpec) GetContainerPush() string {
	if s.Export != nil {
		return s.Export.Container
	}
	return ""
}

// GetPushSecretRef returns the push secret reference for docker config auth
func (s *ImageBuildSpec) GetPushSecretRef() string {
	return s.PushSecretRef
}

// GetExportOCI returns the disk OCI export URL
func (s *ImageBuildSpec) GetExportOCI() string {
	if s.Export != nil && s.Export.Disk != nil {
		return s.Export.Disk.OCI
	}
	return ""
}

// GetUseServiceAccountAuth returns whether service account auth is enabled for registry push
func (s *ImageBuildSpec) GetUseServiceAccountAuth() bool {
	return s.Export != nil && s.Export.UseServiceAccountAuth
}

// HasDiskExport returns true if any disk export is configured
// Includes backward compatibility for legacy ImageBuilds
func (s *ImageBuildSpec) HasDiskExport() bool {
	// New structure: check export.disk.oci
	if s.Export != nil && s.Export.Disk != nil && s.Export.Disk.OCI != "" {
		return true
	}

	// Legacy compatibility: if this appears to be an old ImageBuild structure,
	// assume disk export is wanted (old behavior was to always export)
	// We detect old structure by checking if Export is nil but other top-level fields exist
	if s.Export == nil && s.AIB == nil {
		// This appears to be a legacy flat structure ImageBuild
		return true
	}

	return false
}

// GetLegacyExportURL attempts to determine the export URL for legacy ImageBuilds
// This is a temporary compatibility function
func (s *ImageBuildSpec) GetLegacyExportURL() string {
	// For legacy builds, we don't have access to the old Publishers field anymore
	// since we removed it from the type. The best we can do is provide a reasonable default
	// or require the user to update their ImageBuild to the new structure.

	// If this is a new structure build, use the proper export URL
	if url := s.GetExportOCI(); url != "" {
		return url
	}

	// For legacy builds, we need the user to migrate to the new structure
	// Return empty string to force an error that guides them to update
	return ""
}

// IsFlashEnabled returns true if flash is configured
func (s *ImageBuildSpec) IsFlashEnabled() bool {
	return s.Flash != nil && s.Flash.ClientConfigSecretRef != ""
}

// GetFlashClientConfigSecretRef returns the flash client config secret reference
func (s *ImageBuildSpec) GetFlashClientConfigSecretRef() string {
	if s.Flash != nil {
		return s.Flash.ClientConfigSecretRef
	}
	return ""
}

// GetRebuildBuilder returns whether the builder image should be forcibly rebuilt
func (s *ImageBuildSpec) GetRebuildBuilder() bool {
	if s.AIB != nil {
		return s.AIB.RebuildBuilder
	}
	return false
}

// GetFlashLeaseDuration returns the flash lease duration, or default
func (s *ImageBuildSpec) GetFlashLeaseDuration() string {
	if s.Flash != nil && s.Flash.LeaseDuration != "" {
		return s.Flash.LeaseDuration
	}
	return DefaultFlashLeaseDuration
}
