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

package catalog

import (
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CatalogImageResponse represents a catalog image in API responses
//
//nolint:revive // Name intentionally includes package name for clarity in external API
type CatalogImageResponse struct {
	Name             string                `json:"name"`
	Namespace        string                `json:"namespace"`
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
	ImageBuildName      string   `json:"imageBuildName" binding:"required"`
	ImageBuildNamespace string   `json:"imageBuildNamespace" binding:"required"`
	CatalogImageName    string   `json:"catalogImageName,omitempty"`
	Tags                []string `json:"tags,omitempty"`
}

// VerifyImageResponse represents the response from verifying an image
type VerifyImageResponse struct {
	Message   string `json:"message"`
	Triggered bool   `json:"triggered"`
}

// ListQueryParams represents query parameters for listing catalog images
type ListQueryParams struct {
	Namespace    string `form:"namespace"`
	Architecture string `form:"architecture"`
	Distro       string `form:"distro"`
	Target       string `form:"target"`
	Phase        string `form:"phase"`
	Tags         string `form:"tags"`
	Limit        int    `form:"limit,default=20"`
	Continue     string `form:"continue"`
}

// ToCatalogImageResponse converts a CatalogImage CR to an API response
func ToCatalogImageResponse(catalogImage *automotivev1alpha1.CatalogImage) CatalogImageResponse {
	response := CatalogImageResponse{
		Name:        catalogImage.Name,
		Namespace:   catalogImage.Namespace,
		RegistryURL: catalogImage.Spec.RegistryURL,
		Digest:      catalogImage.Spec.Digest,
		Tags:        catalogImage.Spec.Tags,
		Phase:       string(catalogImage.Status.Phase),
		Labels:      catalogImage.Labels,
		CreatedAt:   catalogImage.CreationTimestamp.Time,
	}

	// Extract metadata
	if catalogImage.Spec.Metadata != nil {
		response.Architecture = catalogImage.Spec.Metadata.Architecture
		response.Distro = catalogImage.Spec.Metadata.Distro
		response.DistroVersion = catalogImage.Spec.Metadata.DistroVersion
		response.Bootc = catalogImage.Spec.Metadata.Bootc
		response.BuildMode = catalogImage.Spec.Metadata.BuildMode
		response.ExportFormat = catalogImage.Spec.Metadata.ExportFormat

		for _, target := range catalogImage.Spec.Metadata.Targets {
			response.Targets = append(response.Targets, HardwareTargetInfo{
				Name:     target.Name,
				Verified: target.Verified,
				Notes:    target.Notes,
			})
		}
	}

	// Extract source type from label
	if sourceType, ok := catalogImage.Labels[automotivev1alpha1.LabelSourceType]; ok {
		response.SourceType = sourceType
	}

	// Extract registry metadata
	if catalogImage.Status.RegistryMetadata != nil {
		response.SizeBytes = catalogImage.Status.RegistryMetadata.SizeBytes
		response.LayerCount = catalogImage.Status.RegistryMetadata.LayerCount
		response.IsMultiArch = catalogImage.Status.RegistryMetadata.IsMultiArch

		// Extract platform variants for multi-arch images
		for _, variant := range catalogImage.Status.RegistryMetadata.PlatformVariants {
			response.PlatformVariants = append(response.PlatformVariants, PlatformVariantInfo{
				Architecture: variant.Architecture,
				OS:           variant.OS,
				Variant:      variant.Variant,
				Digest:       variant.Digest,
				SizeBytes:    variant.SizeBytes,
			})
		}
	}

	// Extract timestamps
	if catalogImage.Status.LastVerificationTime != nil {
		t := catalogImage.Status.LastVerificationTime.Time
		response.LastVerified = &t
	}
	if catalogImage.Status.PublishedAt != nil {
		t := catalogImage.Status.PublishedAt.Time
		response.PublishedAt = &t
	}

	response.SourceImageBuild = catalogImage.Status.SourceImageBuild
	response.AccessCount = catalogImage.Status.AccessCount

	if catalogImage.Status.Phase == automotivev1alpha1.CatalogImagePhaseUnavailable ||
		catalogImage.Status.Phase == automotivev1alpha1.CatalogImagePhaseFailed {
		for _, c := range catalogImage.Status.Conditions {
			if c.Type == automotivev1alpha1.CatalogImageConditionAvailable && c.Status == metav1.ConditionFalse {
				response.StatusReason = c.Reason
				response.StatusMessage = c.Message
				break
			}
		}
	}

	// Extract artifact references
	for _, ref := range catalogImage.Status.ArtifactRefs {
		response.ArtifactRefs = append(response.ArtifactRefs, ArtifactRefInfo{
			Type:      ref.Type,
			URL:       ref.URL,
			Digest:    ref.Digest,
			SizeBytes: ref.SizeBytes,
			Format:    ref.Format,
		})
	}

	// Resolve download URL - prefer first artifact, fallback to registry URL for bootc images
	response.DownloadURL = resolveDownloadURL(catalogImage)

	return response
}

// resolveDownloadURL determines the best download URL for a catalog image
func resolveDownloadURL(catalogImage *automotivev1alpha1.CatalogImage) string {
	// If we have artifact references, use the first one
	if len(catalogImage.Status.ArtifactRefs) > 0 {
		return catalogImage.Status.ArtifactRefs[0].URL
	}

	// For bootc images, the registry URL is the download reference
	if catalogImage.Spec.Metadata != nil && catalogImage.Spec.Metadata.Bootc {
		return catalogImage.Spec.RegistryURL
	}

	// For container images, use the registry URL as the download reference
	if catalogImage.Spec.Metadata != nil && catalogImage.Spec.Metadata.BuildMode == "bootc" {
		return catalogImage.Spec.RegistryURL
	}

	// Default to registry URL
	return catalogImage.Spec.RegistryURL
}

// ToCatalogImageListResponse converts a list of CatalogImage CRs to an API response
func ToCatalogImageListResponse(
	list *automotivev1alpha1.CatalogImageList, continueToken string,
) CatalogImageListResponse {
	response := CatalogImageListResponse{
		Items:    make([]CatalogImageResponse, 0, len(list.Items)),
		Total:    len(list.Items),
		Continue: continueToken,
	}

	for i := range list.Items {
		response.Items = append(response.Items, ToCatalogImageResponse(&list.Items[i]))
	}

	return response
}
