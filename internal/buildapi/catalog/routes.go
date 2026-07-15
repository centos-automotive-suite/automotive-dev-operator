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
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RegisterRoutes registers catalog API routes on the given router group
func RegisterRoutes(group *gin.RouterGroup, k8sClient client.Client, log logr.Logger, defaultNamespace string) {
	handler := NewHandler(k8sClient, log, defaultNamespace)

	// Catalog image routes
	catalogGroup := group.Group("/catalog")
	{
		// List catalog images
		catalogGroup.GET("/images", handler.HandleListCatalogImages)

		// Create catalog image (add external image)
		catalogGroup.POST("/images", handler.HandleCreateCatalogImage)

		// Get catalog image details
		catalogGroup.GET("/images/:name", handler.HandleGetCatalogImage)

		// Delete catalog image
		catalogGroup.DELETE("/images/:name", handler.HandleDeleteCatalogImage)

		// Verify catalog image
		catalogGroup.POST("/images/:name/verify", handler.HandleVerifyCatalogImage)

		// Publish ImageBuild to catalog
		catalogGroup.POST("/publish", handler.HandlePublishImageBuild)
	}
}
