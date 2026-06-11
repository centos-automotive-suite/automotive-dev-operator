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
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
)

const (
	// DefaultAutomotiveImageBuilderImage is the default container image for automotive-image-builder
	DefaultAutomotiveImageBuilderImage = "quay.io/centos-sig-automotive/automotive-image-builder:1.3.2"

	// DefaultYQHelperImage is the default yq helper image used in Tekton task steps
	DefaultYQHelperImage = "quay.io/konflux-ci/yq:latest"

	// DefaultOAuthProxyImage is the default OAuth proxy sidecar image for OpenShift
	DefaultOAuthProxyImage = "registry.redhat.io/openshift4/ose-oauth-proxy:latest"

	// DefaultOperatorImage is the default operator container image
	DefaultOperatorImage = "quay.io/rh-sdv-cloud/automotive-dev-operator:latest"

	// DefaultBuildTimeoutMinutes is the default timeout for build-image pipeline tasks
	DefaultBuildTimeoutMinutes int32 = 90

	// DefaultFlashTimeoutMinutes is the default timeout for flash-image pipeline tasks
	DefaultFlashTimeoutMinutes int32 = 240

	// DefaultClientTokenExpiryDays is the default expiry for client tokens in days
	DefaultClientTokenExpiryDays int32 = 30

	// DefaultFlashLeaseDuration is the default Jumpstarter lease duration in HH:MM:SS format
	DefaultFlashLeaseDuration = "03:00:00"

	// DefaultToolchainImage is the default container image for workspace toolchains
	DefaultToolchainImage = "quay.io/rh-sdv-cloud/autosd-toolchain:latest"

	// DefaultWorkspaceArch is the default target architecture for workspaces
	DefaultWorkspaceArch = "arm64"

	// DefaultWorkspacePVCSize is the default PVC size for workspace storage
	DefaultWorkspacePVCSize = "10Gi"

	// DefaultAutoPauseTimeoutMinutes is the default idle timeout in minutes before a workspace is auto-paused
	DefaultAutoPauseTimeoutMinutes int32 = 30

	// DefaultBuildTTL is the default time-to-live for builds (all phases, including in-progress).
	DefaultBuildTTL = "24h"

	// DefaultRegistryTokenLifetimeSeconds is the default SA token lifetime for internal registry auth.
	DefaultRegistryTokenLifetimeSeconds int64 = 4 * 3600 // 4 hours

	// NoExpireAnnotation prevents automatic expiry when set to "true" on an ImageBuild
	NoExpireAnnotation = "automotive.sdv.cloud.redhat.com/no-expire"

	// BuildServiceAccountName is the dedicated SA used by build pods and token minting.
	// Using a dedicated SA avoids collisions with the shared "pipeline" SA.
	BuildServiceAccountName = "ado-build"
)

// ImagesConfig defines container image references used by the operator
type ImagesConfig struct {
	// AutomotiveImageBuilder is the container image for automotive-image-builder
	// +optional
	AutomotiveImageBuilder string `json:"automotiveImageBuilder,omitempty"`

	// YQHelper is the yq helper image used in Tekton task steps
	// +optional
	YQHelper string `json:"yqHelper,omitempty"`

	// OAuthProxy is the OAuth proxy sidecar image for OpenShift deployments
	// +optional
	OAuthProxy string `json:"oauthProxy,omitempty"`

	// Operator is the operator container image (overridden by OPERATOR_IMAGE env var when set)
	// +optional
	Operator string `json:"operator,omitempty"`
}

// GetAutomotiveImageBuilderImage returns the AIB image, falling back to the default
func (c *ImagesConfig) GetAutomotiveImageBuilderImage() string {
	if c != nil && c.AutomotiveImageBuilder != "" {
		return c.AutomotiveImageBuilder
	}
	return DefaultAutomotiveImageBuilderImage
}

// GetYQHelperImage returns the yq helper image, falling back to the default
func (c *ImagesConfig) GetYQHelperImage() string {
	if c != nil && c.YQHelper != "" {
		return c.YQHelper
	}
	return DefaultYQHelperImage
}

// GetOAuthProxyImage returns the OAuth proxy image, falling back to the default
func (c *ImagesConfig) GetOAuthProxyImage() string {
	if c != nil && c.OAuthProxy != "" {
		return c.OAuthProxy
	}
	return DefaultOAuthProxyImage
}

// GetOperatorImage returns the operator image, falling back to the default
func (c *ImagesConfig) GetOperatorImage() string {
	if c != nil && c.Operator != "" {
		return c.Operator
	}
	return DefaultOperatorImage
}

// BuildAPIResourcesConfig defines resource requirements for Build API components
type BuildAPIResourcesConfig struct {
	// BuildAPI defines resource requirements for the Build API container
	// +optional
	BuildAPI *corev1.ResourceRequirements `json:"buildAPI,omitempty"`

	// OAuthProxy defines resource requirements for the OAuth proxy sidecar
	// +optional
	OAuthProxy *corev1.ResourceRequirements `json:"oauthProxy,omitempty"`

	// BuildController defines resource requirements for the build controller container
	// +optional
	BuildController *corev1.ResourceRequirements `json:"buildController,omitempty"`
}

// GetBuildAPIResources returns the Build API resource requirements with defaults
func (c *BuildAPIResourcesConfig) GetBuildAPIResources() corev1.ResourceRequirements {
	if c != nil && c.BuildAPI != nil {
		return *c.BuildAPI
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("200m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

// GetOAuthProxyResources returns the OAuth proxy resource requirements with defaults
func (c *BuildAPIResourcesConfig) GetOAuthProxyResources() corev1.ResourceRequirements {
	if c != nil && c.OAuthProxy != nil {
		return *c.OAuthProxy
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("10m"),
			corev1.ResourceMemory: resource.MustParse("32Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}
}

// GetBuildControllerResources returns the build controller resource requirements with defaults
func (c *BuildAPIResourcesConfig) GetBuildControllerResources() corev1.ResourceRequirements {
	if c != nil && c.BuildController != nil {
		return *c.BuildController
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1000m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

// GetImages returns the ImagesConfig, returning an empty struct if nil (so getters fall back to defaults)
func (s *OperatorConfigSpec) GetImages() *ImagesConfig {
	if s.Images != nil {
		return s.Images
	}
	return &ImagesConfig{}
}

// JumpstarterTargetMapping defines the Jumpstarter configuration for a specific build target
type JumpstarterTargetMapping struct {
	// Selector is the label selector for matching Jumpstarter exporters
	// Example: "board-type=j784s4evm"
	Selector string `json:"selector"`

	// FlashCmd is the command template for flashing the device
	// Example: "j storage flash ${IMAGE}"
	// +optional
	FlashCmd string `json:"flashCmd,omitempty"`
}

// DefaultJumpstarterImage is the default container image for Jumpstarter CLI operations
const DefaultJumpstarterImage = "quay.io/jumpstarter-dev/jumpstarter:latest"

// JumpstarterConfig defines configuration for Jumpstarter device flashing integration
type JumpstarterConfig struct {
	// Image is the container image for Jumpstarter CLI operations
	// +kubebuilder:default="quay.io/jumpstarter-dev/jumpstarter:latest"
	// +optional
	Image string `json:"image,omitempty"`

	// Namespace is the OpenShift namespace where Jumpstarter is installed
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// DefaultLeaseDuration is the cluster-wide default lease duration in HH:MM:SS format
	// Can be overridden per-ImageBuild via FlashSpec.LeaseDuration
	// Default: "03:00:00"
	// +optional
	DefaultLeaseDuration string `json:"defaultLeaseDuration,omitempty"`

	// TargetMappings maps build targets to Jumpstarter exporter configurations
	// +optional
	TargetMappings map[string]JumpstarterTargetMapping `json:"targetMappings,omitempty"`
}

// GetJumpstarterImage returns the Jumpstarter image to use, falling back to the default
func (c *JumpstarterConfig) GetJumpstarterImage() string {
	if c != nil && c.Image != "" {
		return c.Image
	}
	return DefaultJumpstarterImage
}

// GetDefaultLeaseDuration returns the default flash lease duration, falling back to the constant default
func (c *JumpstarterConfig) GetDefaultLeaseDuration() string {
	if c != nil && c.DefaultLeaseDuration != "" {
		return c.DefaultLeaseDuration
	}
	return DefaultFlashLeaseDuration
}

// BuildAPIConfig defines configuration for the Build API server
type BuildAPIConfig struct {
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

	// ClientTokenExpiryDays is the number of days before client tokens expire
	// Default: 30
	// +optional
	ClientTokenExpiryDays int32 `json:"clientTokenExpiryDays,omitempty"`

	// Resources defines resource requirements for Build API components
	// +optional
	Resources *BuildAPIResourcesConfig `json:"resources,omitempty"`

	// Authentication configuration for the Build API server.
	// +optional
	Authentication *AuthenticationConfig `json:"authentication,omitempty"`
}

// GetClientTokenExpiryDays returns the client token expiry in days, falling back to the default
func (c *BuildAPIConfig) GetClientTokenExpiryDays() int32 {
	if c != nil && c.ClientTokenExpiryDays > 0 {
		return c.ClientTokenExpiryDays
	}
	return DefaultClientTokenExpiryDays
}

// AuthenticationConfig defines authentication methods for the Build API.
type AuthenticationConfig struct {
	// Internal authentication configuration.
	// +optional
	Internal *InternalAuthConfig `json:"internal,omitempty"`

	// JWT authentication configuration for OIDC providers.
	// +optional
	JWT []apiserverv1beta1.JWTAuthenticator `json:"jwt,omitempty"`

	// OIDC client ID for caib CLI.
	// +optional
	ClientID string `json:"clientId,omitempty"`
}

// InternalAuthConfig defines the built-in authentication configuration.
type InternalAuthConfig struct {
	// Prefix to add to the subject claim of issued tokens.
	// +kubebuilder:default="internal:"
	// +optional
	Prefix string `json:"prefix,omitempty"`
}

// ContainerBuildsConfig defines configuration for container build operations
type ContainerBuildsConfig struct {
	// UploadTimeoutMinutes is the maximum time in minutes to wait for source uploads
	// before failing the build. Increase this for large build contexts.
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +optional
	UploadTimeoutMinutes int32 `json:"uploadTimeoutMinutes,omitempty"`

	// DefaultBuildTTL is the default time-to-live for container builds.
	// After this duration past completion, a build transitions to Expired
	// and its BuildRun is cleaned up. Uses Go duration format (e.g. "24h").
	// Set to "0" to disable expiry by default.
	// +optional
	DefaultBuildTTL string `json:"defaultBuildTTL,omitempty"`
}

// GetDefaultBuildTTL returns the configured default TTL for container builds,
// falling back to the shared DefaultBuildTTL constant ("24h").
func (c *ContainerBuildsConfig) GetDefaultBuildTTL() string {
	if c != nil && c.DefaultBuildTTL != "" {
		return c.DefaultBuildTTL
	}
	return DefaultBuildTTL
}

// WorkspacesConfig defines configuration for developer workspaces
// +kubebuilder:validation:XValidation:rule="!has(self.imageVerify) || !self.imageVerify || has(self.imageCosignKeyRef)",message="imageCosignKeyRef is required when imageVerify is true"
type WorkspacesConfig struct {
	// ToolchainImage is the container image for workspace toolchains
	// +optional
	ToolchainImage string `json:"toolchainImage,omitempty"`

	// DefaultArchitecture is the default target architecture for workspaces
	// +optional
	DefaultArchitecture string `json:"defaultArchitecture,omitempty"`

	// PVCSize is the size for persistent volume claims created for workspace storage
	// +optional
	PVCSize string `json:"pvcSize,omitempty"`

	// Resources defines the default CPU and memory requests/limits for workspace containers
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// MaxResources defines the maximum CPU and memory that users can request for workspace containers
	// +optional
	MaxResources *corev1.ResourceRequirements `json:"maxResources,omitempty"`

	// StorageClass specifies the storage class for workspace PVCs
	// If empty, the cluster default storage class is used
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// NodeSelector specifies node labels that workspace pods must match for scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations specifies tolerations to be added to workspace pods
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// TmpfsBuildDir allows users to mount a tmpfs-backed emptyDir at /tmp/build in workspace pods
	// When enabled, users can opt-in per workspace via --tmpfs on create
	// +optional
	TmpfsBuildDir bool `json:"tmpfsBuildDir,omitempty"`

	// BuildCacheSize is the size of the PVC created for build cache persistence (default: "20Gi")
	// +optional
	BuildCacheSize string `json:"buildCacheSize,omitempty"`

	// AutoPauseTimeoutMinutes is the cluster-wide default idle timeout in minutes before
	// a workspace is automatically paused. Overridden per-workspace via spec.autoPauseTimeoutMinutes.
	// Must be > 0. To disable auto-pause for a specific workspace, set its
	// spec.autoPauseTimeoutMinutes to 0.
	// Default: 30
	// +optional
	AutoPauseTimeoutMinutes int32 `json:"autoPauseTimeoutMinutes,omitempty"`

	// ImagePullSecrets is a list of secret references for pulling private workspace images
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// AllowedImages restricts which container images users may run in workspaces.
	// Supports exact matches and prefix globs (e.g., "quay.io/my-org/*").
	// When empty, only the configured toolchain image is allowed.
	// The toolchain image is always implicitly permitted.
	// +optional
	AllowedImages []string `json:"allowedImages,omitempty"`

	// ImageVerify enables cosign signature verification for workspace images.
	// When true, images must be signed with the key in ImageCosignKeyRef.
	// +optional
	ImageVerify bool `json:"imageVerify,omitempty"`

	// ImageCosignKeyRef references a ConfigMap key containing the cosign public key
	// (PEM-encoded) used to verify workspace image signatures.
	// Required when ImageVerify is true.
	// +optional
	ImageCosignKeyRef *corev1.ConfigMapKeySelector `json:"imageCosignKeyRef,omitempty"`
}

// GetToolchainImage returns the toolchain image, falling back to the default
func (c *WorkspacesConfig) GetToolchainImage() string {
	if c != nil && c.ToolchainImage != "" {
		return c.ToolchainImage
	}
	return DefaultToolchainImage
}

// GetDefaultArchitecture returns the default workspace architecture, falling back to the default
func (c *WorkspacesConfig) GetDefaultArchitecture() string {
	if c != nil && c.DefaultArchitecture != "" {
		return c.DefaultArchitecture
	}
	return DefaultWorkspaceArch
}

// GetPVCSize returns the workspace PVC size, falling back to the default
func (c *WorkspacesConfig) GetPVCSize() string {
	if c != nil && c.PVCSize != "" {
		return c.PVCSize
	}
	return DefaultWorkspacePVCSize
}

// GetTmpfsBuildDir returns whether tmpfs build directories are allowed for workspaces
func (c *WorkspacesConfig) GetTmpfsBuildDir() bool {
	return c != nil && c.TmpfsBuildDir
}

// GetStorageClass returns the workspace storage class, or empty string for cluster default
func (c *WorkspacesConfig) GetStorageClass() string {
	if c != nil {
		return c.StorageClass
	}
	return ""
}

// GetNodeSelector returns the workspace node selector labels, or nil if not configured
func (c *WorkspacesConfig) GetNodeSelector() map[string]string {
	if c != nil {
		return c.NodeSelector
	}
	return nil
}

// GetTolerations returns the workspace tolerations, or nil if not configured
func (c *WorkspacesConfig) GetTolerations() []corev1.Toleration {
	if c != nil {
		return c.Tolerations
	}
	return nil
}

// GetAutoPauseTimeoutMinutes returns the global auto-pause timeout in minutes.
// Returns DefaultAutoPauseTimeoutMinutes (30) when not configured.
func (c *WorkspacesConfig) GetAutoPauseTimeoutMinutes() int32 {
	if c != nil && c.AutoPauseTimeoutMinutes > 0 {
		return c.AutoPauseTimeoutMinutes
	}
	return DefaultAutoPauseTimeoutMinutes
}

// GetImagePullSecrets returns the workspace image pull secrets, or nil if not configured
func (c *WorkspacesConfig) GetImagePullSecrets() []corev1.LocalObjectReference {
	if c != nil {
		return c.ImagePullSecrets
	}
	return nil
}

// IsImageAllowed checks whether a container image is permitted for workspace pods.
// The configured toolchain image is always allowed. Other images must match an
// entry in AllowedImages (exact match or prefix glob like "quay.io/org/*").
// Returns false when AllowedImages is empty and the image is not the toolchain image.
func (c *WorkspacesConfig) IsImageAllowed(image string) bool {
	if c == nil {
		return image == DefaultToolchainImage
	}
	if image == c.GetToolchainImage() {
		return true
	}
	if len(c.AllowedImages) == 0 {
		return false
	}
	for _, pattern := range c.AllowedImages {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(image, prefix) {
				return true
			}
		} else if image == pattern {
			return true
		}
	}
	return false
}

// MonitoringConfig defines configuration for Prometheus metrics collection
type MonitoringConfig struct {
	// Enabled determines if a ServiceMonitor should be deployed for Prometheus scraping
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Interval defines the Prometheus scrape interval
	// Default: "30s"
	// +optional
	// +kubebuilder:validation:Pattern=`^(0|(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?)$`
	Interval string `json:"interval,omitempty"`
}

// GetInterval returns the scrape interval, falling back to "30s"
func (c *MonitoringConfig) GetInterval() string {
	if c != nil && c.Interval != "" {
		return c.Interval
	}
	return "30s"
}

// TracingConfig defines configuration for OpenTelemetry distributed tracing
type TracingConfig struct {
	// Enabled determines if the operator should export trace spans
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Endpoint is the OTLP gRPC collector endpoint (e.g. "otel-collector.namespace.svc:4317").
	// Falls back to OTEL_EXPORTER_OTLP_ENDPOINT env var when empty.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// Insecure disables TLS for the OTLP gRPC connection.
	// Default: true (plaintext, appropriate for in-cluster collectors).
	// Set to false when connecting to external/managed tracing backends that require TLS.
	// +optional
	// +kubebuilder:default=true
	Insecure *bool `json:"insecure,omitempty"`

	// SamplingRatio controls the fraction of traces sampled, as a string representation
	// of a decimal between "0" and "1" (e.g. "0.1" for 10%, "1" for 100%).
	// Default: "1" (sample everything).
	// +optional
	// +kubebuilder:validation:Pattern=`^(0(\.\d+)?|1(\.0+)?)$`
	SamplingRatio string `json:"samplingRatio,omitempty"`
}

// IsInsecure returns whether the OTLP connection should use plaintext (default: true)
func (c *TracingConfig) IsInsecure() bool {
	if c != nil && c.Insecure != nil {
		return *c.Insecure
	}
	return true
}

// GetSamplingRatio returns the sampling ratio as a float64, defaulting to 1.0
func (c *TracingConfig) GetSamplingRatio() float64 {
	if c != nil && c.SamplingRatio != "" {
		if v, err := strconv.ParseFloat(c.SamplingRatio, 64); err == nil {
			return v
		}
	}
	return 1.0
}

// GetEndpoint returns the configured endpoint or empty string
func (c *TracingConfig) GetEndpoint() string {
	if c != nil && c.Endpoint != "" {
		return c.Endpoint
	}
	return ""
}

// OperatorConfigSpec defines the desired state of OperatorConfig
type OperatorConfigSpec struct {
	// OSBuilds defines the configuration for OS build operations
	// +optional
	OSBuilds *OSBuildsConfig `json:"osBuilds,omitempty"`

	// ContainerBuilds defines configuration for container build operations
	// +optional
	ContainerBuilds *ContainerBuildsConfig `json:"containerBuilds,omitempty"`

	// BuildAPI defines configuration for the Build API server
	// +optional
	BuildAPI *BuildAPIConfig `json:"buildAPI,omitempty"`

	// Images defines container image references used by the operator
	// +optional
	Images *ImagesConfig `json:"images,omitempty"`

	// Jumpstarter defines configuration for Jumpstarter device flashing integration
	// +optional
	Jumpstarter *JumpstarterConfig `json:"jumpstarter,omitempty"`

	// Workspaces defines configuration for developer workspaces
	// +optional
	Workspaces *WorkspacesConfig `json:"workspaces,omitempty"`

	// Monitoring defines configuration for Prometheus metrics collection
	// +optional
	Monitoring *MonitoringConfig `json:"monitoring,omitempty"`

	// Tracing defines configuration for OpenTelemetry distributed tracing
	// +optional
	Tracing *TracingConfig `json:"tracing,omitempty"`
}

// OSBuildsConfig defines configuration for OS build operations
// +kubebuilder:validation:XValidation:rule="!has(self.taskBundleVerify) || !self.taskBundleVerify || has(self.taskBundleCosignKeyRef)",message="taskBundleCosignKeyRef is required when taskBundleVerify is true"
type OSBuildsConfig struct {
	// Enabled determines if Tekton tasks for OS builds should be deployed
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// UseMemoryVolumes determines whether to use memory-backed volumes for build operations
	// When true, all emptyDir volumes (build-dir, run-dir, container-storage, etc.) use tmpfs
	// Default: false (disk-backed)
	// +optional
	UseMemoryVolumes bool `json:"useMemoryVolumes,omitempty"`

	// MemoryVolumeSize specifies the size limit for memory-backed volumes
	// Only used when UseMemoryVolumes is true
	// Example: "2Gi"
	// +optional
	MemoryVolumeSize string `json:"memoryVolumeSize,omitempty"`

	// PVCSize specifies the size for persistent volume claims created for build workspaces
	// Default: "8Gi"
	// +optional
	PVCSize string `json:"pvcSize,omitempty"`

	// StorageClass specifies the storage class for build PVCs
	// If empty, the cluster default storage class is used
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// UsePVCScratchVolumes moves build scratch directories (build cache, output, container storage)
	// from node-local emptyDir volumes onto the shared workspace PVC.
	// This prevents builds from consuming node ephemeral storage, avoiding node disk exhaustion
	// when running multiple concurrent builds. Requires a larger PVC size (see pvcSize).
	// Default: true
	// +optional
	UsePVCScratchVolumes *bool `json:"usePVCScratchVolumes,omitempty"`

	// RuntimeClassName specifies the runtime class to use for the build pod
	// More info: https://kubernetes.io/docs/concepts/containers/runtime-class/
	// +optional
	RuntimeClassName string `json:"runtimeClassName,omitempty"`

	// ClusterRegistryRoute is the external route for the cluster's internal image registry
	// Required for bootc builds to allow nested containers to pull builder images
	// Example: "default-route-openshift-image-registry.apps.mycluster.example.com"
	// +optional
	ClusterRegistryRoute string `json:"clusterRegistryRoute,omitempty"`

	// InsecureRegistry skips TLS certificate verification for OCI registry operations
	// such as artifact pushes via oras. Required when the target registry uses a
	// self-signed certificate (e.g., CRC/OpenShift internal registry, local Kind
	// registry with generated certs).
	// +optional
	InsecureRegistry bool `json:"insecureRegistry,omitempty"`

	// UploadTimeoutMinutes is the maximum time in minutes to wait for file uploads before failing the build
	// Default: 30
	// +optional
	UploadTimeoutMinutes int32 `json:"uploadTimeoutMinutes,omitempty"`

	// BuildTimeoutMinutes is the timeout for build-image pipeline tasks in minutes
	// Default: 90
	// +optional
	BuildTimeoutMinutes int32 `json:"buildTimeoutMinutes,omitempty"`

	// FlashTimeoutMinutes is the timeout for flash-image pipeline tasks in minutes
	// Default: 240 (4 hours)
	// +optional
	FlashTimeoutMinutes int32 `json:"flashTimeoutMinutes,omitempty"`

	// NodeSelector specifies node labels that build pods must match for scheduling
	// These labels are added to the pod template used by Tekton PipelineRuns
	// Example: {"dedicated": "builds", "disktype": "ssd"}
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations specifies tolerations to be added to build pods
	// Enables scheduling on tainted nodes for dedicated/exclusive access
	// Example: [{"key": "automotive.sdv.cloud.redhat.com/dedicated", "operator": "Equal",
	//           "value": "builds", "effect": "NoSchedule"}]
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Certificates defines trusted certificate configuration for build tasks.
	// +optional
	Certificates *BuildCertificatesConfig `json:"certificates,omitempty"`

	// TaskBundleRef is the OCI reference to a signed Tekton Bundle containing task definitions.
	// When set, builds created with SecureBuild=true will resolve tasks from this bundle
	// instead of the cluster-installed tasks. The bundle should be signed with cosign
	// and contain the same tasks as the operator deploys.
	// Example: "quay.io/rh-sdv-cloud/automotive-dev-tekton-tasks:v0.1.0@sha256:abc123..."
	// +optional
	TaskBundleRef string `json:"taskBundleRef,omitempty"`

	// TaskBundleVerify enables cosign signature verification for Tekton Bundles.
	// When true, all bundle refs (from OperatorConfig or user-provided --task-bundle-ref)
	// must be signed with the key in TaskBundleCosignKeyRef.
	// +optional
	TaskBundleVerify bool `json:"taskBundleVerify,omitempty"`

	// TaskBundleCosignKeyRef references a ConfigMap key containing the cosign public key (PEM-encoded)
	// used to verify Tekton Bundle signatures.
	// Required when TaskBundleVerify is true.
	// +optional
	TaskBundleCosignKeyRef *corev1.ConfigMapKeySelector `json:"taskBundleCosignKeyRef,omitempty"`

	// DefaultBuildTTL is the default time-to-live for builds (all phases, including in-progress).
	// Builds are automatically deleted after this duration. Uses Go duration format (e.g. "24h", "72h").
	// Set to "0" to disable expiry by default.
	// Default: "24h"
	// +optional
	DefaultBuildTTL string `json:"defaultBuildTTL,omitempty"`

	// MaxBuildTTL is the maximum TTL that users can request for individual builds.
	// Build requests specifying a TTL greater than this value are rejected.
	// Set to "0" for no maximum. Uses Go duration format (e.g. "168h" for 1 week).
	// +optional
	MaxBuildTTL string `json:"maxBuildTTL,omitempty"`

	// RegistryTokenLifetimeSeconds is the lifetime in seconds for service account tokens
	// used for internal registry authentication during builds.
	// Default: 14400 (4 hours)
	// +kubebuilder:validation:Minimum=1
	// +optional
	RegistryTokenLifetimeSeconds int64 `json:"registryTokenLifetimeSeconds,omitempty"`
}

// CertificateSourceRef references a Secret or ConfigMap that contains trusted CA certificates.
type CertificateSourceRef struct {
	// Kind indicates the source kind for trusted CA bundle.
	// +kubebuilder:validation:Enum=ConfigMap;Secret
	Kind string `json:"kind"`

	// Name is the name of the Secret or ConfigMap.
	Name string `json:"name"`
}

// BuildCertificatesConfig defines trusted certificate sources for build workloads.
type BuildCertificatesConfig struct {
	// TrustedCABundle references a Secret or ConfigMap mounted into build tasks.
	// +optional
	TrustedCABundle *CertificateSourceRef `json:"trustedCABundle,omitempty"`
}

// GetBuildTimeoutMinutes returns the build timeout in minutes, falling back to the default
func (c *OSBuildsConfig) GetBuildTimeoutMinutes() int32 {
	if c != nil && c.BuildTimeoutMinutes > 0 {
		return c.BuildTimeoutMinutes
	}
	return DefaultBuildTimeoutMinutes
}

// GetFlashTimeoutMinutes returns the flash timeout in minutes, falling back to the default
func (c *OSBuildsConfig) GetFlashTimeoutMinutes() int32 {
	if c != nil && c.FlashTimeoutMinutes > 0 {
		return c.FlashTimeoutMinutes
	}
	return DefaultFlashTimeoutMinutes
}

// GetDefaultBuildTTL returns the default build TTL string, falling back to the hardcoded default
func (c *OSBuildsConfig) GetDefaultBuildTTL() string {
	if c != nil && c.DefaultBuildTTL != "" {
		return c.DefaultBuildTTL
	}
	return DefaultBuildTTL
}

// GetMaxBuildTTL returns the max build TTL string, or empty if no max is set
func (c *OSBuildsConfig) GetMaxBuildTTL() string {
	if c != nil {
		return c.MaxBuildTTL
	}
	return ""
}

// GetRegistryTokenLifetimeSeconds returns the SA token lifetime for internal registry auth
func (c *OSBuildsConfig) GetRegistryTokenLifetimeSeconds() int64 {
	if c != nil && c.RegistryTokenLifetimeSeconds > 0 {
		return c.RegistryTokenLifetimeSeconds
	}
	return DefaultRegistryTokenLifetimeSeconds
}

// GetUsePVCScratchVolumes returns whether to use PVC-backed scratch volumes (default: true)
func (c *OSBuildsConfig) GetUsePVCScratchVolumes() bool {
	if c.UsePVCScratchVolumes != nil {
		return *c.UsePVCScratchVolumes
	}
	return true
}

// Condition types for OperatorConfig
const (
	// OperatorConfigConditionReady indicates the operator configuration has been fully reconciled
	OperatorConfigConditionReady = "Ready"

	// OperatorConfigConditionReconciling indicates the operator is actively reconciling resources
	OperatorConfigConditionReconciling = "Reconciling"

	// OperatorConfigConditionDegraded indicates the operator encountered errors during reconciliation
	OperatorConfigConditionDegraded = "Degraded"
)

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

	// JumpstarterAvailable indicates if Jumpstarter is available (explicitly configured or local CRDs detected)
	JumpstarterAvailable bool `json:"jumpstarterAvailable,omitempty"`

	// UserNamespacesSupported indicates if the cluster supports user namespaces in pods
	// (SCC userNamespaceLevel field). When false, workspace pods use privileged mode.
	UserNamespacesSupported bool `json:"userNamespacesSupported,omitempty"`

	// MonitoringEnabled indicates if the ServiceMonitor is currently deployed
	MonitoringEnabled bool `json:"monitoringEnabled,omitempty"`

	// Conditions represent the latest available observations of the OperatorConfig's state
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// TracingEnabled indicates if tracing is configured and active
	TracingEnabled bool `json:"tracingEnabled,omitempty"`
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
