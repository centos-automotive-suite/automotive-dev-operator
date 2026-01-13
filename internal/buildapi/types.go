package buildapi

import (
	"fmt"
	"strings"
)

type Distro string

type Target string

type Architecture string

type ExportFormat string

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

func (d Distro) IsValid() bool       { return IsValid(string(d)) }
func (t Target) IsValid() bool       { return IsValid(string(t)) }
func (a Architecture) IsValid() bool { return IsValid(string(a)) }
func (e ExportFormat) IsValid() bool { return IsValid(string(e)) }
func (m Mode) IsValid() bool         { return IsValid(string(m)) }

// IsBootc returns true if this is bootc mode
func (m Mode) IsBootc() bool {
	return m == ModeBootc
}

// IsTraditional returns true if this is a traditional (non-bootc) mode
func (m Mode) IsTraditional() bool {
	return m == ModeImage || m == ModePackage
}

func ParseDistro(s string) (Distro, error) {
	d := Distro(s)
	if !d.IsValid() {
		return "", fmt.Errorf("distro cannot be empty")
	}
	return d, nil
}

func ParseTarget(s string) (Target, error) {
	t := Target(s)
	if !t.IsValid() {
		return "", fmt.Errorf("target cannot be empty")
	}
	return t, nil
}

func ParseArchitecture(s string) (Architecture, error) {
	a := Architecture(s)
	if !a.IsValid() {
		return "", fmt.Errorf("architecture cannot be empty")
	}
	return a, nil
}

func ParseExportFormat(s string) (ExportFormat, error) {
	e := ExportFormat(s)
	if !e.IsValid() {
		return "", fmt.Errorf("exportFormat cannot be empty")
	}
	return e, nil
}

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
	Name                   string               `json:"name"`
	Manifest               string               `json:"manifest,omitempty"`
	ManifestFileName       string               `json:"manifestFileName,omitempty"`
	ContainerRef           string               `json:"containerRef,omitempty"` // For disk mode: existing container to convert
	Distro                 Distro               `json:"distro"`
	Target                 Target               `json:"target"`
	Architecture           Architecture         `json:"architecture"`
	ExportFormat           ExportFormat         `json:"exportFormat"`
	Mode                   Mode                 `json:"mode"`
	AutomotiveImageBuilder string               `json:"automotiveImageBuilder"`
	StorageClass           string               `json:"storageClass"`
	CustomDefs             []string             `json:"customDefs"`
	AIBExtraArgs           []string             `json:"aibExtraArgs"`
	ServeArtifact          bool                 `json:"serveArtifact"`
	Compression            string               `json:"compression,omitempty"`
	RegistryCredentials    *RegistryCredentials `json:"registryCredentials,omitempty"`
	PushRepository         string               `json:"pushRepository,omitempty"`

	ContainerPush  string `json:"containerPush,omitempty"`  // Registry URL to push bootc container
	BuildDiskImage bool   `json:"buildDiskImage,omitempty"` // Build disk image from bootc container
	ExportOCI      string `json:"exportOci,omitempty"`      // Registry URL to push disk as OCI artifact
	BuilderImage   string `json:"builderImage,omitempty"`   // Custom builder image
}

type RegistryCredentials struct {
	Enabled      bool   `json:"enabled"`
	AuthType     string `json:"authType"`
	RegistryURL  string `json:"registryUrl"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Token        string `json:"token"`
	DockerConfig string `json:"dockerConfig"`
}

// BuildResponse is returned by POST and GET build operations
type BuildResponse struct {
	Name             string `json:"name"`
	Phase            string `json:"phase"`
	Message          string `json:"message"`
	RequestedBy      string `json:"requestedBy,omitempty"`
	ArtifactURL      string `json:"artifactURL,omitempty"`
	ArtifactFileName string `json:"artifactFileName,omitempty"`
	StartTime        string `json:"startTime,omitempty"`
	CompletionTime   string `json:"completionTime,omitempty"`
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
}

type (
	BuildRequestAlias  = BuildRequest
	BuildListItemAlias = BuildListItem
)

// BuildTemplateResponse includes the original inputs plus a hint of source files referenced by the manifest
type BuildTemplateResponse struct {
	BuildRequest `json:",inline"`
	SourceFiles  []string `json:"sourceFiles,omitempty"`
}
