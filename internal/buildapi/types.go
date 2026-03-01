package buildapi

import (
	"fmt"
	"strings"
)

// Distro represents the OS distribution to build (e.g., cs9, autosd10-sig).
type Distro string

// Target represents the hardware target platform (e.g., qemu, raspberry-pi).
type Target string

// Architecture represents the CPU architecture (e.g., amd64, arm64).
type Architecture string

// ExportFormat represents the disk image format (e.g., qcow2, raw, simg).
type ExportFormat string

// Mode represents the build mode (bootc, image, package, or disk).
type Mode string

const (
	// ModeBootc creates immutable, container-based OS images using bootc (default)
	ModeBootc Mode = "bootc"
	// ModeImage creates traditional ostree-based disk images
	ModeImage Mode = "image"
	// ModePackage creates traditional, mutable, package-based disk images
	ModePackage Mode = "package"
	// ModeDisk creates a disk image from an existing bootc container
	ModeDisk Mode = "disk"
)

// IsValid checks if a string value is non-empty after trimming whitespace
func IsValid(s string) bool {
	return strings.TrimSpace(s) != ""
}

// IsValid returns true if the distro value is non-empty.
func (d Distro) IsValid() bool { return IsValid(string(d)) }

// IsValid returns true if the target value is non-empty.
func (t Target) IsValid() bool { return IsValid(string(t)) }

// IsValid returns true if the architecture value is non-empty.
func (a Architecture) IsValid() bool { return IsValid(string(a)) }

// IsValid returns true if the export format value is non-empty.
func (e ExportFormat) IsValid() bool { return IsValid(string(e)) }

// IsValid returns true if the mode value is non-empty.
func (m Mode) IsValid() bool { return IsValid(string(m)) }

// IsBootc returns true if this is bootc mode
func (m Mode) IsBootc() bool {
	return m == ModeBootc
}

// IsTraditional returns true if this is a traditional (non-bootc) mode
func (m Mode) IsTraditional() bool {
	return m == ModeImage || m == ModePackage
}

// ParseDistro parses a distro string and validates it.
func ParseDistro(s string) (Distro, error) {
	d := Distro(s)
	if !d.IsValid() {
		return "", fmt.Errorf("distro cannot be empty")
	}
	return d, nil
}

// ParseTarget parses a target string and validates it.
func ParseTarget(s string) (Target, error) {
	t := Target(s)
	if !t.IsValid() {
		return "", fmt.Errorf("target cannot be empty")
	}
	return t, nil
}

// ParseArchitecture parses an architecture string and validates it.
func ParseArchitecture(s string) (Architecture, error) {
	a := Architecture(s)
	if !a.IsValid() {
		return "", fmt.Errorf("architecture cannot be empty")
	}
	return a, nil
}

// ParseExportFormat parses an export format string and validates it.
func ParseExportFormat(s string) (ExportFormat, error) {
	e := ExportFormat(s)
	if !e.IsValid() {
		return "", fmt.Errorf("exportFormat cannot be empty")
	}
	return e, nil
}

// ParseMode parses a mode string, defaulting to bootc if empty.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if !m.IsValid() {
		// Default to bootc if not specified
		return ModeBootc, nil
	}
	return m, nil
}

// BuildRequest is the payload to create a build via the REST API
type BuildRequest struct {
	Name             string `json:"name"`
	Manifest         string `json:"manifest,omitempty"`
	ManifestFileName string `json:"manifestFileName,omitempty"`
	// ContainerRef is for disk mode: existing container to convert
	ContainerRef           string               `json:"containerRef,omitempty"`
	Distro                 Distro               `json:"distro"`
	Target                 Target               `json:"target"`
	Architecture           Architecture         `json:"architecture"`
	ExportFormat           ExportFormat         `json:"exportFormat"`
	Mode                   Mode                 `json:"mode"`
	AutomotiveImageBuilder string               `json:"automotiveImageBuilder"`
	StorageClass           string               `json:"storageClass"`
	CustomDefs             []string             `json:"customDefs"`
	AIBExtraArgs           []string             `json:"aibExtraArgs"`
	Compression            string               `json:"compression,omitempty"`
	RegistryCredentials    *RegistryCredentials `json:"registryCredentials,omitempty"`
	PushRepository         string               `json:"pushRepository,omitempty"`

	ContainerPush  string `json:"containerPush,omitempty"`  // Registry URL to push bootc container
	BuildDiskImage bool   `json:"buildDiskImage,omitempty"` // Build disk image from bootc container
	ExportOCI      string `json:"exportOci,omitempty"`      // Registry URL to push disk as OCI artifact
	BuilderImage   string `json:"builderImage,omitempty"`   // Custom builder image
	RebuildBuilder bool   `json:"rebuildBuilder,omitempty"` // Force rebuild of bootc builder image

	// Internal registry push configuration
	UseInternalRegistry       bool   `json:"useInternalRegistry,omitempty"`       // Push to OpenShift internal registry
	InternalRegistryImageName string `json:"internalRegistryImageName,omitempty"` // Override image name (default: build name)
	InternalRegistryTag       string `json:"internalRegistryTag,omitempty"`       // Tag for internal registry image (default: build name)

	// Flash configuration for Jumpstarter device flashing after build
	FlashEnabled       bool   `json:"flashEnabled,omitempty"`       // Enable flashing after build
	FlashClientConfig  string `json:"flashClientConfig,omitempty"`  // Base64-encoded Jumpstarter client config
	FlashLeaseDuration string `json:"flashLeaseDuration,omitempty"` // Lease duration in HH:MM:SS format
}

// RegistryCredentials contains authentication details for container registries.
type RegistryCredentials struct {
	Enabled      bool   `json:"enabled"`
	AuthType     string `json:"authType"`
	RegistryURL  string `json:"registryUrl"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Token        string `json:"token"`
	DockerConfig string `json:"dockerConfig"`
}

// JumpstarterInfo contains information about Jumpstarter device flashing availability
type JumpstarterInfo struct {
	// Available indicates if Jumpstarter is installed in the cluster
	Available bool `json:"available"`
	// ExporterSelector is the label selector for matching Jumpstarter exporters for this build's target
	ExporterSelector string `json:"exporterSelector,omitempty"`
	// FlashCmd is the command for flashing the device
	FlashCmd string `json:"flashCmd,omitempty"`
	// LeaseID is the Jumpstarter lease ID acquired during flash
	LeaseID string `json:"leaseId,omitempty"`
}

// FlashRequest is the payload to flash an image via Jumpstarter
type FlashRequest struct {
	// Name is the flash job name (auto-generated if omitted)
	Name string `json:"name"`
	// ImageRef is the OCI registry reference of the disk image to flash
	ImageRef string `json:"imageRef"`
	// Target is the target platform for exporter lookup from OperatorConfig
	Target string `json:"target,omitempty"`
	// ExporterSelector is the direct label selector for Jumpstarter exporters (alternative to Target)
	ExporterSelector string `json:"exporterSelector,omitempty"`
	// FlashCmd is the command template for flashing (optional, can come from OperatorConfig)
	FlashCmd string `json:"flashCmd,omitempty"`
	// ClientConfig is the base64-encoded Jumpstarter client config file content
	ClientConfig string `json:"clientConfig"`
	// LeaseDuration is the Jumpstarter lease duration in HH:MM:SS format (default: "01:00:00")
	LeaseDuration string `json:"leaseDuration,omitempty"`
}

// FlashResponse is returned by flash operations
type FlashResponse struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
	RequestedBy    string `json:"requestedBy,omitempty"`
	StartTime      string `json:"startTime,omitempty"`
	CompletionTime string `json:"completionTime,omitempty"`
	TaskRunName    string `json:"taskRunName,omitempty"`
}

// FlashListItem represents a flash TaskRun in the list API
type FlashListItem struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
	RequestedBy    string `json:"requestedBy,omitempty"`
	CreatedAt      string `json:"createdAt"`
	CompletionTime string `json:"completionTime,omitempty"`
}

// BuildResponse is returned by POST and GET build operations
type BuildResponse struct {
	Name           string           `json:"name"`
	Phase          string           `json:"phase"`
	Message        string           `json:"message"`
	RequestedBy    string           `json:"requestedBy,omitempty"`
	StartTime      string           `json:"startTime,omitempty"`
	CompletionTime string           `json:"completionTime,omitempty"`
	ContainerImage string           `json:"containerImage,omitempty"`
	DiskImage      string           `json:"diskImage,omitempty"`
	RegistryToken  string           `json:"registryToken,omitempty"`
	Warning        string           `json:"warning,omitempty"`
	Jumpstarter    *JumpstarterInfo `json:"jumpstarter,omitempty"`
	Parameters     *BuildParameters `json:"parameters,omitempty"`
}

// BuildParameters describes the key input parameters that produced an ImageBuild.
type BuildParameters struct {
	Architecture           string `json:"architecture,omitempty"`
	Distro                 string `json:"distro,omitempty"`
	Target                 string `json:"target,omitempty"`
	Mode                   string `json:"mode,omitempty"`
	ExportFormat           string `json:"exportFormat,omitempty"`
	Compression            string `json:"compression,omitempty"`
	StorageClass           string `json:"storageClass,omitempty"`
	AutomotiveImageBuilder string `json:"automotiveImageBuilder,omitempty"`
	BuilderImage           string `json:"builderImage,omitempty"`
	ContainerRef           string `json:"containerRef,omitempty"`
	BuildDiskImage         bool   `json:"buildDiskImage,omitempty"`
	FlashEnabled           bool   `json:"flashEnabled,omitempty"`
	FlashLeaseDuration     string `json:"flashLeaseDuration,omitempty"`
	UseServiceAccountAuth  bool   `json:"useServiceAccountAuth,omitempty"`
}

// BuildListItem represents a build in the list API
type BuildListItem struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
	RequestedBy    string `json:"requestedBy,omitempty"`
	CreatedAt      string `json:"createdAt"`
	StartTime      string `json:"startTime,omitempty"`
	CompletionTime string `json:"completionTime,omitempty"`
	ContainerImage string `json:"containerImage,omitempty"`
	DiskImage      string `json:"diskImage,omitempty"`
}

// JumpstarterTarget contains flash-specific config for a target (from CRD)
type JumpstarterTarget struct {
	Selector string `json:"selector"`
	FlashCmd string `json:"flashCmd,omitempty"`
}

// TargetDefaults contains build defaults for a target (from ConfigMap)
type TargetDefaults struct {
	Architecture string   `json:"architecture,omitempty"`
	ExtraArgs    []string `json:"extraArgs,omitempty"`
}

// OperatorConfigResponse returns relevant operator configuration for CLI validation
type OperatorConfigResponse struct {
	// JumpstarterTargets contains flash-specific config per target (from CRD)
	JumpstarterTargets map[string]JumpstarterTarget `json:"jumpstarterTargets,omitempty"`
	// TargetDefaults contains build defaults per target (from ConfigMap)
	TargetDefaults map[string]TargetDefaults `json:"targetDefaults,omitempty"`
}

type (
	// BuildRequestAlias is an alias for BuildRequest used for backward compatibility.
	BuildRequestAlias = BuildRequest
	// BuildListItemAlias is an alias for BuildListItem used for backward compatibility.
	BuildListItemAlias = BuildListItem
)

// BuildTemplateResponse includes the original inputs plus a hint of source files referenced by the manifest
type BuildTemplateResponse struct {
	BuildRequest `json:",inline"`
	SourceFiles  []string `json:"sourceFiles,omitempty"`
}

// ContainerBuildRequest is the payload to create a container build via the REST API
type ContainerBuildRequest struct {
	// Name is the build identifier (auto-generated if omitted)
	Name string `json:"name"`
	// Output is the target image reference to push to (required)
	Output string `json:"output"`
	// Containerfile is the path within the context (default: "Containerfile")
	Containerfile string `json:"containerfile,omitempty"`
	// Strategy is the Shipwright build strategy name (default: "buildah")
	Strategy string `json:"strategy,omitempty"`
	// BuildArgs are --build-arg KEY=VALUE pairs
	BuildArgs map[string]string `json:"buildArgs,omitempty"`
	// Architecture is the target CPU architecture
	Architecture string `json:"architecture,omitempty"`
	// Timeout is the maximum build duration in minutes (default: 30)
	Timeout int32 `json:"timeout,omitempty"`
	// RegistryCredentials contains push authentication details
	RegistryCredentials *RegistryCredentials `json:"registryCredentials,omitempty"`
	// UseInternalRegistry indicates the build should push to the OpenShift internal registry
	UseInternalRegistry bool `json:"useInternalRegistry,omitempty"`
}

// ContainerBuildResponse is returned by container build operations
type ContainerBuildResponse struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
	RequestedBy    string `json:"requestedBy,omitempty"`
	StartTime      string `json:"startTime,omitempty"`
	CompletionTime string `json:"completionTime,omitempty"`
	OutputImage    string `json:"outputImage,omitempty"`
	ImageDigest    string `json:"imageDigest,omitempty"`
	RegistryToken  string `json:"registryToken,omitempty"`
}

// ContainerBuildListItem represents a container build in the list API
type ContainerBuildListItem struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
	RequestedBy    string `json:"requestedBy,omitempty"`
	CreatedAt      string `json:"createdAt"`
	CompletionTime string `json:"completionTime,omitempty"`
	OutputImage    string `json:"outputImage,omitempty"`
}

// SealedOperation is the AIB sealed workflow operation to run
type SealedOperation string

// Sealed operation constants for each step in the AIB sealed workflow.
const (
	SealedPrepareReseal     SealedOperation = "prepare-reseal"
	SealedReseal            SealedOperation = "reseal"
	SealedExtractForSigning SealedOperation = "extract-for-signing"
	SealedInjectSigned      SealedOperation = "inject-signed"
)

// SealedOperationAPIPath returns the v1 API path prefix for the given sealed operation.
func SealedOperationAPIPath(op SealedOperation) string {
	switch op {
	case SealedPrepareReseal:
		return "/v1/prepare-reseals"
	case SealedReseal:
		return "/v1/reseals"
	case SealedExtractForSigning:
		return "/v1/extract-for-signings"
	case SealedInjectSigned:
		return "/v1/inject-signeds"
	default:
		return "/v1/reseals"
	}
}

// SealedRequest is the payload to create a sealed operation via the REST API
type SealedRequest struct {
	Name      string          `json:"name"`
	Operation SealedOperation `json:"operation,omitempty"`
	// Stages is an ordered list of operations (e.g. prepare-reseal, extract-for-signing, inject-signed, reseal). If set, Operation is ignored.
	Stages []string `json:"stages,omitempty"`
	// InputRef is the OCI reference to the input disk image (required)
	InputRef string `json:"inputRef"`
	// OutputRef is the OCI reference where to push the result (optional for extract-for-signing)
	OutputRef string `json:"outputRef,omitempty"`
	// SignedRef is the OCI reference to signed artifacts; required when operation is inject-signed
	SignedRef    string `json:"signedRef,omitempty"`
	AIBImage     string `json:"aibImage,omitempty"`
	BuilderImage string `json:"builderImage,omitempty"`
	// Architecture overrides the target architecture for the builder image (e.g., "amd64", "arm64").
	Architecture        string               `json:"architecture,omitempty"`
	StorageClass        string               `json:"storageClass,omitempty"`
	AIBExtraArgs        []string             `json:"aibExtraArgs,omitempty"`
	RegistryCredentials *RegistryCredentials `json:"registryCredentials,omitempty"`
	// KeySecretRef is the name of an existing secret containing the sealing key (data key "private-key").
	KeySecretRef string `json:"keySecretRef,omitempty"`
	// KeyPasswordSecretRef is the name of an existing secret containing the key password (data key "password").
	KeyPasswordSecretRef string `json:"keyPasswordSecretRef,omitempty"`
	// KeyContent is the PEM-encoded private key content (alternative to KeySecretRef; server creates a transient secret).
	KeyContent string `json:"keyContent,omitempty"`
	// KeyPassword is the password for an encrypted key (used with KeyContent).
	KeyPassword string `json:"keyPassword,omitempty"`
}

// SealedResponse is returned by POST and GET sealed operations
type SealedResponse struct {
	Name            string `json:"name"`
	Phase           string `json:"phase"`
	Message         string `json:"message"`
	RequestedBy     string `json:"requestedBy,omitempty"`
	StartTime       string `json:"startTime,omitempty"`
	CompletionTime  string `json:"completionTime,omitempty"`
	TaskRunName     string `json:"taskRunName,omitempty"`
	PipelineRunName string `json:"pipelineRunName,omitempty"`
	OutputRef       string `json:"outputRef,omitempty"`
}

// SealedListItem represents a sealed job in the list API
type SealedListItem struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
	RequestedBy    string `json:"requestedBy,omitempty"`
	CreatedAt      string `json:"createdAt"`
	CompletionTime string `json:"completionTime,omitempty"`
}
