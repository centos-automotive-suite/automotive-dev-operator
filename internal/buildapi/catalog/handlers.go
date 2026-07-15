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

// Package catalog provides HTTP handlers for CatalogImage resource management via REST API.
package catalog

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

// Handler handles catalog API requests
type Handler struct {
	client           client.Client
	log              logr.Logger
	defaultNamespace string
}

// NewHandler creates a new catalog API handler
func NewHandler(client client.Client, log logr.Logger, defaultNamespace string) *Handler {
	if defaultNamespace == "" {
		defaultNamespace = "default"
	}
	return &Handler{
		client:           client,
		log:              log.WithName("catalog-handler"),
		defaultNamespace: defaultNamespace,
	}
}

// HandleListCatalogImages lists catalog images with filtering
func (h *Handler) HandleListCatalogImages(c *gin.Context) {
	ctx := context.Background()

	// Parse query parameters
	var params ListQueryParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters", "details": err.Error()})
		return
	}

	// Build list options
	listOpts := []client.ListOption{}

	// Namespace filtering — always scope to a namespace
	ns := params.Namespace
	if ns == "" {
		ns = h.defaultNamespace
	}
	listOpts = append(listOpts, client.InNamespace(ns))

	// Build label selector for filtering
	labelRequirements := []string{}

	if params.Architecture != "" {
		labelRequirements = append(labelRequirements, automotivev1alpha1.LabelArchitecture+"="+params.Architecture)
	}
	if params.Distro != "" {
		labelRequirements = append(labelRequirements, automotivev1alpha1.LabelDistro+"="+params.Distro)
	}
	if params.Target != "" {
		labelRequirements = append(labelRequirements, automotivev1alpha1.LabelTarget+"="+params.Target)
	}

	if len(labelRequirements) > 0 {
		selectorStr := strings.Join(labelRequirements, ",")
		selector, err := labels.Parse(selectorStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filter parameters", "details": err.Error()})
			return
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
	}

	// Apply limit
	if params.Limit > 0 && params.Limit <= 100 {
		listOpts = append(listOpts, client.Limit(int64(params.Limit)))
	} else {
		listOpts = append(listOpts, client.Limit(20))
	}

	// Apply continue token
	if params.Continue != "" {
		listOpts = append(listOpts, client.Continue(params.Continue))
	}

	// List catalog images
	catalogImages := &automotivev1alpha1.CatalogImageList{}
	if err := h.client.List(ctx, catalogImages, listOpts...); err != nil {
		h.log.Error(err, "failed to list catalog images")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list catalog images"})
		return
	}

	// Filter by phase if specified (post-filter since phase is in status)
	if params.Phase != "" {
		filtered := []automotivev1alpha1.CatalogImage{}
		for _, img := range catalogImages.Items {
			if string(img.Status.Phase) == params.Phase {
				filtered = append(filtered, img)
			}
		}
		catalogImages.Items = filtered
	}

	// Filter by tags if specified
	if params.Tags != "" {
		requestedTags := strings.Split(params.Tags, ",")
		filtered := []automotivev1alpha1.CatalogImage{}
		for _, img := range catalogImages.Items {
			if hasAllTags(img.Spec.Tags, requestedTags) {
				filtered = append(filtered, img)
			}
		}
		catalogImages.Items = filtered
	}

	// Convert to response
	response := ToCatalogImageListResponse(catalogImages, catalogImages.Continue)
	c.JSON(http.StatusOK, response)
}

// HandleGetCatalogImage gets a specific catalog image
func (h *Handler) HandleGetCatalogImage(c *gin.Context) {
	ctx := context.Background()
	name := c.Param("name")
	namespace := c.Query("namespace")

	if namespace == "" {
		namespace = h.defaultNamespace
	}

	catalogImage := &automotivev1alpha1.CatalogImage{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, catalogImage); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "catalog image not found"})
			return
		}
		h.log.Error(err, "failed to get catalog image", "name", name, "namespace", namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get catalog image"})
		return
	}

	response := ToCatalogImageResponse(catalogImage)
	c.JSON(http.StatusOK, response)
}

// HandleCreateCatalogImage creates a new catalog image
func (h *Handler) HandleCreateCatalogImage(c *gin.Context) {
	ctx := context.Background()
	namespace := c.Query("namespace")
	if namespace == "" {
		namespace = h.defaultNamespace
	}

	var req CreateCatalogImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	// Check for duplicates
	existing := &automotivev1alpha1.CatalogImageList{}
	if err := h.client.List(ctx, existing,
		client.InNamespace(namespace),
		client.MatchingFields{"spec.registryUrl": req.RegistryURL}); err == nil && len(existing.Items) > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "image with this registry URL already exists in catalog"})
		return
	}

	// Create CatalogImage CR
	catalogImage := &automotivev1alpha1.CatalogImage{}
	catalogImage.Name = req.Name
	catalogImage.Namespace = namespace
	catalogImage.Spec = automotivev1alpha1.CatalogImageSpec{
		RegistryURL: req.RegistryURL,
		Digest:      req.Digest,
		Tags:        req.Tags,
	}

	// Set metadata if provided
	if req.Architecture != "" || req.Distro != "" || len(req.Targets) > 0 {
		catalogImage.Spec.Metadata = &automotivev1alpha1.CatalogImageMetadata{
			Architecture:  req.Architecture,
			Distro:        req.Distro,
			DistroVersion: req.DistroVersion,
			Bootc:         req.Bootc,
		}

		for _, t := range req.Targets {
			catalogImage.Spec.Metadata.Targets = append(catalogImage.Spec.Metadata.Targets,
				automotivev1alpha1.HardwareTarget{
					Name:     t.Name,
					Verified: t.Verified,
					Notes:    t.Notes,
				})
		}
	}

	// Set auth secret if provided
	if req.AuthSecretName != "" {
		catalogImage.Spec.AuthSecretRef = &automotivev1alpha1.AuthSecretReference{
			Name: req.AuthSecretName,
		}
	}

	if err := h.client.Create(ctx, catalogImage); err != nil {
		h.log.Error(err, "failed to create catalog image", "name", req.Name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create catalog image"})
		return
	}

	h.log.Info("created catalog image", "name", req.Name, "namespace", namespace)
	response := ToCatalogImageResponse(catalogImage)
	c.JSON(http.StatusCreated, response)
}

// HandleDeleteCatalogImage deletes a catalog image
func (h *Handler) HandleDeleteCatalogImage(c *gin.Context) {
	ctx := context.Background()
	name := c.Param("name")
	namespace := c.Query("namespace")

	if namespace == "" {
		namespace = h.defaultNamespace
	}

	catalogImage := &automotivev1alpha1.CatalogImage{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, catalogImage); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "catalog image not found"})
			return
		}
		h.log.Error(err, "failed to get catalog image", "name", name, "namespace", namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get catalog image"})
		return
	}

	if err := h.client.Delete(ctx, catalogImage); err != nil {
		h.log.Error(err, "failed to delete catalog image", "name", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete catalog image"})
		return
	}

	h.log.Info("deleted catalog image", "name", name, "namespace", namespace)
	c.Status(http.StatusNoContent)
}

// HandleVerifyCatalogImage triggers verification of a catalog image
func (h *Handler) HandleVerifyCatalogImage(c *gin.Context) {
	ctx := context.Background()
	name := c.Param("name")
	namespace := c.Query("namespace")

	if namespace == "" {
		namespace = h.defaultNamespace
	}

	catalogImage := &automotivev1alpha1.CatalogImage{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, catalogImage); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "catalog image not found"})
			return
		}
		h.log.Error(err, "failed to get catalog image", "name", name, "namespace", namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get catalog image"})
		return
	}

	// Trigger verification by transitioning to Verifying phase
	catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseVerifying
	if err := h.client.Status().Update(ctx, catalogImage); err != nil {
		h.log.Error(err, "failed to trigger verification", "name", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to trigger verification"})
		return
	}

	h.log.Info("triggered verification for catalog image", "name", name, "namespace", namespace)
	c.JSON(http.StatusOK, VerifyImageResponse{
		Message:   "Verification triggered successfully",
		Triggered: true,
	})
}

// HandlePublishImageBuild publishes an ImageBuild to the catalog
func (h *Handler) HandlePublishImageBuild(c *gin.Context) {
	ctx := context.Background()

	var req PublishImageBuildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	// Get the ImageBuild
	imageBuild := &automotivev1alpha1.ImageBuild{}
	if err := h.client.Get(
		ctx, client.ObjectKey{Name: req.ImageBuildName, Namespace: req.ImageBuildNamespace}, imageBuild,
	); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "ImageBuild not found"})
			return
		}
		h.log.Error(err, "failed to get ImageBuild", "name", req.ImageBuildName)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get ImageBuild"})
		return
	}

	// Check if ImageBuild is completed
	if imageBuild.Status.Phase != "Completed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ImageBuild is not completed", "phase": imageBuild.Status.Phase})
		return
	}

	// Determine registry URL from ImageBuild (container push or disk OCI export)
	registryURL := imageBuild.Spec.GetContainerPush()
	if registryURL == "" {
		registryURL = imageBuild.Spec.GetExportOCI()
	}

	if registryURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ImageBuild does not have a registry URL"})
		return
	}

	// Determine catalog image name
	catalogImageName := req.CatalogImageName
	if catalogImageName == "" {
		catalogImageName = req.ImageBuildName
	}

	// Create CatalogImage
	catalogImage := &automotivev1alpha1.CatalogImage{}
	catalogImage.Name = catalogImageName
	catalogImage.Namespace = req.ImageBuildNamespace
	catalogImage.Spec = automotivev1alpha1.CatalogImageSpec{
		RegistryURL: registryURL,
		Tags:        req.Tags,
		Metadata: &automotivev1alpha1.CatalogImageMetadata{
			Architecture: imageBuild.Spec.Architecture,
			Distro:       imageBuild.Spec.GetDistro(),
			BuildMode:    imageBuild.Spec.GetMode(),
		},
	}

	// Add hardware target if available
	if imageBuild.Spec.GetTarget() != "" {
		catalogImage.Spec.Metadata.Targets = []automotivev1alpha1.HardwareTarget{
			{Name: imageBuild.Spec.GetTarget(), Verified: true},
		}
	}

	// Set source ImageBuild reference in status (will be set by controller, but preempt for response)
	catalogImage.Status.SourceImageBuild = req.ImageBuildName

	if err := h.client.Create(ctx, catalogImage); err != nil {
		h.log.Error(err, "failed to create catalog image from ImageBuild", "imageBuild", req.ImageBuildName)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to publish ImageBuild to catalog"})
		return
	}

	h.log.Info("published ImageBuild to catalog", "imageBuild", req.ImageBuildName, "catalogImage", catalogImageName)
	response := ToCatalogImageResponse(catalogImage)
	c.JSON(http.StatusCreated, response)
}

// hasAllTags checks if the image has all the requested tags
func hasAllTags(imageTags, requestedTags []string) bool {
	tagSet := make(map[string]bool)
	for _, t := range imageTags {
		tagSet[t] = true
	}
	for _, t := range requestedTags {
		if !tagSet[strings.TrimSpace(t)] {
			return false
		}
	}
	return true
}
