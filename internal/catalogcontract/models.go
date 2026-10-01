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

package catalogcontract

import "time"

// CatalogImageResponse represents a catalog image in API responses
//
//nolint:revive // Name intentionally includes package name for clarity in external API
type CatalogImageResponse struct {
	Name             string                `json:"name"`
	RegistryURL      string                `json:"registryUrl"`
	Digest           string                `json:"digest,omitempty"`
	Tags             []string              `json:"tags,omitempty"`
	Phase            string                `json:"phase"`
	Architecture     string                `json:"architecture,omitempty"`
	Distro           string                `json:"distro,omitempty"`
	DistroVersion    string                `json:"distroVersion,omitempty"`
	Targets          []HardwareTargetInfo  `json:"targets,omitempty"`
	Bootc            bool                  `json:"bootc"`
	SizeBytes        int64                 `json:"sizeBytes,omitempty"`
	LayerCount       int                   `json:"layerCount,omitempty"`
	LastVerified     *time.Time            `json:"lastVerified,omitempty"`
	PublishedAt      *time.Time            `json:"publishedAt,omitempty"`
	CreatedAt        time.Time             `json:"createdAt"`
	SourceImageBuild string                `json:"sourceImageBuild,omitempty"`
	SourceType       string                `json:"sourceType,omitempty"`
	ScheduleName     string                `json:"scheduleName,omitempty"`
	BuildMode        string                `json:"buildMode,omitempty"`
	ExportFormat     string                `json:"exportFormat,omitempty"`
	Labels           map[string]string     `json:"labels,omitempty"`
	ArtifactRefs     []ArtifactRefInfo     `json:"artifactRefs,omitempty"`
	DownloadURL      string                `json:"downloadUrl,omitempty"`
	IsMultiArch      bool                  `json:"isMultiArch,omitempty"`
	PlatformVariants []PlatformVariantInfo `json:"platformVariants,omitempty"`
	AccessCount      int64                 `json:"accessCount,omitempty"`
	StatusReason     string                `json:"statusReason,omitempty"`
	StatusMessage    string                `json:"statusMessage,omitempty"`
}

// ArtifactRefInfo represents artifact reference information in responses
type ArtifactRefInfo struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Digest    string `json:"digest,omitempty"`
	SizeBytes int64  `json:"sizeBytes,omitempty"`
	Format    string `json:"format,omitempty"`
}

// PlatformVariantInfo represents a platform-specific variant in API responses
type PlatformVariantInfo struct {
	Architecture string `json:"architecture,omitempty"`
	OS           string `json:"os,omitempty"`
	Variant      string `json:"variant,omitempty"`
	Digest       string `json:"digest,omitempty"`
	SizeBytes    int64  `json:"sizeBytes,omitempty"`
}

// HardwareTargetInfo represents hardware target information in responses
type HardwareTargetInfo struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
	Notes    string `json:"notes,omitempty"`
}

// CatalogImageListResponse represents a list of catalog images
//
//nolint:revive // Name intentionally includes package name for clarity in external API
type CatalogImageListResponse struct {
	Items    []CatalogImageResponse `json:"items"`
	Total    int                    `json:"total"`
	Continue string                 `json:"continue,omitempty"`
}

// CreateCatalogImageRequest represents a request to create a catalog image
type CreateCatalogImageRequest struct {
	Name           string               `json:"name" binding:"required"`
	RegistryURL    string               `json:"registryUrl" binding:"required"`
	Digest         string               `json:"digest,omitempty"`
	Tags           []string             `json:"tags,omitempty"`
	AuthSecretName string               `json:"authSecretName,omitempty"`
	Architecture   string               `json:"architecture,omitempty"`
	Distro         string               `json:"distro,omitempty"`
	DistroVersion  string               `json:"distroVersion,omitempty"`
	Targets        []HardwareTargetInfo `json:"targets,omitempty"`
	Bootc          bool                 `json:"bootc"`
}

// PublishImageBuildRequest represents a request to publish an ImageBuild to the catalog
type PublishImageBuildRequest struct {
	ImageBuildName   string   `json:"imageBuildName" binding:"required"`
	CatalogImageName string   `json:"catalogImageName,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// VerifyImageResponse represents the response from verifying an image
type VerifyImageResponse struct {
	Message   string `json:"message"`
	Triggered bool   `json:"triggered"`
}
