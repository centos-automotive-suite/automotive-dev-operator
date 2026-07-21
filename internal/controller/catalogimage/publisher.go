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

package catalogimage

import (
	"context"
	"fmt"

	"github.com/containers/image/v5/types"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

// PublishSource indicates where the catalog image was published from
type PublishSource string

const (
	// PublishSourceImageBuild indicates the image was published from an ImageBuild
	PublishSourceImageBuild PublishSource = "ImageBuild"
	// PublishSourceExternal indicates the image was added as an external reference
	PublishSourceExternal PublishSource = "External"
	// PublishSourceManual indicates the image was manually added via API
	PublishSourceManual PublishSource = "Manual"
	// PublishSourceScheduled indicates the image was published from a scheduled build
	PublishSourceScheduled PublishSource = "Scheduled"
)

// PublishOptions contains options for publishing an image to the catalog
type PublishOptions struct {
	// Name is the name for the CatalogImage resource
	Name string
	// Namespace is the namespace for the CatalogImage
	Namespace string
	// RegistryURL is the full URL to the image in the registry
	RegistryURL string
	// Digest is the optional content-addressable digest
	Digest string
	// Tags are category tags to apply
	Tags []string
	// Metadata contains automotive-specific metadata
	Metadata *automotivev1alpha1.CatalogImageMetadata
	// AuthSecretRef references credentials for private registries
	AuthSecretRef *automotivev1alpha1.AuthSecretReference
	// Source indicates where this image came from
	Source PublishSource
	// SourceImageBuildName is the name of the source ImageBuild (if applicable)
	SourceImageBuildName string
	// VerifyAccessibility determines if registry accessibility should be verified
	VerifyAccessibility bool
}

// Publisher handles publishing images to the catalog with audit event recording
type Publisher struct {
	client         client.Client
	registryClient RegistryClient
	auditRecorder  *AuditRecorder
	log            logr.Logger
}

// NewPublisher creates a new Publisher
func NewPublisher(
	client client.Client,
	registryClient RegistryClient,
	auditRecorder *AuditRecorder,
	log logr.Logger,
) *Publisher {
	return &Publisher{
		client:         client,
		registryClient: registryClient,
		auditRecorder:  auditRecorder,
		log:            log.WithName("publisher"),
	}
}

// PublishResult contains the result of a publish operation
type PublishResult struct {
	// CatalogImage is the created CatalogImage resource
	CatalogImage *automotivev1alpha1.CatalogImage
	// Verified indicates if the image was verified accessible
	Verified bool
	// Metadata is the registry metadata extracted during verification
	Metadata *automotivev1alpha1.RegistryMetadata
}

// Publish creates a new CatalogImage and optionally verifies registry accessibility
func (p *Publisher) Publish(ctx context.Context, opts PublishOptions) (*PublishResult, error) {
	log := p.log.WithValues("name", opts.Name, "namespace", opts.Namespace, "registryURL", opts.RegistryURL)
	log.Info("Publishing image to catalog")

	// Check for duplicate registry URLs
	if err := p.checkDuplicates(ctx, opts.Namespace, opts.RegistryURL); err != nil {
		return nil, err
	}

	// Create the CatalogImage resource
	catalogImage := p.buildCatalogImage(opts)

	// Verify accessibility if requested
	var registryMetadata *automotivev1alpha1.RegistryMetadata
	var verified bool
	if opts.VerifyAccessibility {
		var err error
		verified, registryMetadata, err = p.verifyAndExtractMetadata(ctx, opts)
		if err != nil {
			log.Error(err, "Failed to verify registry accessibility")
			// Continue with creation, controller will handle verification
		}
	}

	// Create the CatalogImage
	if err := p.client.Create(ctx, catalogImage); err != nil {
		return nil, fmt.Errorf("failed to create CatalogImage: %w", err)
	}

	log.Info("Successfully created CatalogImage", "verified", verified)

	// Record audit event
	if p.auditRecorder != nil {
		p.auditRecorder.RecordPublished(ctx, catalogImage, string(opts.Source))
	}

	// If we verified and have metadata, update the status
	if verified && registryMetadata != nil {
		catalogImage.Status.RegistryMetadata = registryMetadata
		catalogImage.Status.LastVerificationTime = GetCurrentTime()
		catalogImage.Status.Phase = automotivev1alpha1.CatalogImagePhaseAvailable

		if err := p.client.Status().Update(ctx, catalogImage); err != nil {
			log.Error(err, "Failed to update status with verification results")
			// Non-fatal: controller will pick up verification on next reconcile
		}
	}

	return &PublishResult{
		CatalogImage: catalogImage,
		Verified:     verified,
		Metadata:     registryMetadata,
	}, nil
}

// PublishFromImageBuild creates a CatalogImage from a completed ImageBuild.
func (p *Publisher) PublishFromImageBuild(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
	catalogName string,
	tags []string,
	authSecretRef *automotivev1alpha1.AuthSecretReference,
	source PublishSource,
) (*PublishResult, error) {
	log := p.log.WithValues("imageBuild", imageBuild.Name, "namespace", imageBuild.Namespace)

	// Validate ImageBuild is completed
	if imageBuild.Status.Phase != "Completed" {
		return nil, fmt.Errorf("ImageBuild is not completed: current phase is %s", imageBuild.Status.Phase)
	}

	// Determine registry URL
	registryURL := p.extractRegistryURL(imageBuild)
	if registryURL == "" {
		return nil, fmt.Errorf("ImageBuild does not have a registry URL configured")
	}

	// Determine catalog image name
	if catalogName == "" {
		catalogName = imageBuild.Name
	}

	// Build metadata from ImageBuild
	exportFormat := resolvedExportFormat(imageBuild)
	if imageBuild.Spec.GetContainerPush() != "" {
		exportFormat = "oci"
	}

	metadata := &automotivev1alpha1.CatalogImageMetadata{
		Architecture: NormalizeArchitecture(imageBuild.Spec.Architecture),
		Distro:       imageBuild.Spec.GetDistro(),
		BuildMode:    imageBuild.Spec.GetMode(),
		ExportFormat: exportFormat,
		Bootc:        imageBuild.Spec.GetMode() == "bootc",
	}

	// Add hardware target if specified
	if imageBuild.Spec.GetTarget() != "" {
		metadata.Targets = []automotivev1alpha1.HardwareTarget{
			{Name: imageBuild.Spec.GetTarget(), Verified: true},
		}
	}

	publishSource := source
	if publishSource == "" {
		publishSource = PublishSourceImageBuild
	}

	log.Info("Publishing ImageBuild to catalog", "catalogName", catalogName, "registryURL", registryURL, "source", publishSource)

	return p.Publish(ctx, PublishOptions{
		Name:                 catalogName,
		Namespace:            imageBuild.Namespace,
		RegistryURL:          registryURL,
		Tags:                 tags,
		Metadata:             metadata,
		AuthSecretRef:        authSecretRef,
		Source:               publishSource,
		SourceImageBuildName: imageBuild.Name,
		VerifyAccessibility:  true,
	})
}

// checkDuplicates checks if a CatalogImage with the same registry URL already exists
func (p *Publisher) checkDuplicates(ctx context.Context, namespace, registryURL string) error {
	lister := NewCatalogImageLister(p.client)
	exists, err := lister.ExistsByRegistryURL(ctx, namespace, registryURL)
	if err != nil {
		return fmt.Errorf("failed to check for duplicates: %w", err)
	}
	if exists {
		return fmt.Errorf("catalog image with registry URL %q already exists in namespace %s", registryURL, namespace)
	}
	return nil
}

// buildCatalogImage creates a CatalogImage resource from PublishOptions
func (p *Publisher) buildCatalogImage(opts PublishOptions) *automotivev1alpha1.CatalogImage {
	catalogImage := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
			Labels:    make(map[string]string),
		},
		Spec: automotivev1alpha1.CatalogImageSpec{
			RegistryURL:   opts.RegistryURL,
			Digest:        opts.Digest,
			Tags:          opts.Tags,
			AuthSecretRef: opts.AuthSecretRef,
			Metadata:      opts.Metadata,
		},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase:       automotivev1alpha1.CatalogImagePhasePending,
			PublishedAt: GetCurrentTime(),
		},
	}

	// Set source ImageBuild if applicable
	if opts.SourceImageBuildName != "" {
		catalogImage.Status.SourceImageBuild = opts.SourceImageBuildName
	}

	// Set labels for indexing
	if opts.Metadata != nil {
		if opts.Metadata.Architecture != "" {
			catalogImage.Labels[automotivev1alpha1.LabelArchitecture] = NormalizeArchitecture(opts.Metadata.Architecture)
		}
		if opts.Metadata.Distro != "" {
			catalogImage.Labels[automotivev1alpha1.LabelDistro] = opts.Metadata.Distro
		}
		if len(opts.Metadata.Targets) > 0 {
			catalogImage.Labels[automotivev1alpha1.LabelTarget] = opts.Metadata.Targets[0].Name
		}
		if opts.Metadata.Bootc {
			catalogImage.Labels[automotivev1alpha1.LabelBootc] = "true"
		}
	}

	// Set source type label
	catalogImage.Labels[automotivev1alpha1.LabelSourceType] = string(opts.Source)

	return catalogImage
}

// verifyAndExtractMetadata verifies registry accessibility and extracts metadata
func (p *Publisher) verifyAndExtractMetadata(
	ctx context.Context,
	opts PublishOptions,
) (bool, *automotivev1alpha1.RegistryMetadata, error) {
	// Get authentication config
	var auth *types.DockerAuthConfig
	var err error
	if opts.AuthSecretRef != nil {
		auth, err = GetAuthFromSecret(ctx, p.client, opts.AuthSecretRef, opts.Namespace)
		if err != nil {
			return false, nil, fmt.Errorf("failed to get authentication: %w", err)
		}
	}

	// Verify accessibility
	accessible, err := p.registryClient.VerifyImageAccessible(ctx, opts.RegistryURL, auth)
	if err != nil {
		return false, nil, fmt.Errorf("failed to verify registry accessibility: %w", err)
	}
	if !accessible {
		return false, nil, fmt.Errorf("image not accessible at %s", opts.RegistryURL)
	}

	// Extract metadata
	metadata, err := p.registryClient.GetImageMetadata(ctx, opts.RegistryURL, auth)
	if err != nil {
		// Accessibility was confirmed, metadata extraction is optional
		p.log.Info("Image accessible but metadata extraction failed", "error", err)
		return true, nil, nil
	}

	return true, metadata, nil
}

// extractRegistryURL extracts the registry URL from an ImageBuild
func (p *Publisher) extractRegistryURL(imageBuild *automotivev1alpha1.ImageBuild) string {
	// Check container export first (bootc container destination)
	if url := imageBuild.Spec.GetContainerPush(); url != "" {
		return url
	}

	// Check disk OCI export
	if url := imageBuild.Spec.GetExportOCI(); url != "" {
		return url
	}

	return ""
}

// Unpublish removes a CatalogImage from the catalog with audit recording
func (p *Publisher) Unpublish(ctx context.Context, name, namespace string) error {
	log := p.log.WithValues("name", name, "namespace", namespace)
	log.Info("Removing image from catalog")

	catalogImage := &automotivev1alpha1.CatalogImage{}
	if err := p.client.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, catalogImage); err != nil {
		return fmt.Errorf("failed to get CatalogImage: %w", err)
	}

	// Record audit event before deletion
	if p.auditRecorder != nil {
		p.auditRecorder.RecordRemoved(ctx, catalogImage)
	}

	if err := p.client.Delete(ctx, catalogImage); err != nil {
		return fmt.Errorf("failed to delete CatalogImage: %w", err)
	}

	log.Info("Successfully removed CatalogImage from catalog")
	return nil
}

func resolvedExportFormat(imageBuild *automotivev1alpha1.ImageBuild) string {
	if imageBuild.Status.ResolvedExportFormat != "" {
		return imageBuild.Status.ResolvedExportFormat
	}
	return imageBuild.Spec.GetExportFormat()
}
