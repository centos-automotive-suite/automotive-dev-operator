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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
)

// RegistryClient provides methods to interact with container registries
type RegistryClient interface {
	// VerifyImageAccessible checks if the image is accessible in the registry
	VerifyImageAccessible(ctx context.Context, registryURL string, auth *types.DockerAuthConfig) (bool, error)

	// GetImageMetadata retrieves metadata from the registry manifest
	GetImageMetadata(
		ctx context.Context,
		registryURL string,
		auth *types.DockerAuthConfig,
	) (*automotivev1alpha1.RegistryMetadata, error)

	// VerifyDigest verifies that the image digest matches the expected digest
	VerifyDigest(
		ctx context.Context,
		registryURL string,
		expectedDigest string,
		auth *types.DockerAuthConfig,
	) (bool, string, error)
}

// DefaultRegistryClient implements RegistryClient using containers/image library
type DefaultRegistryClient struct{}

// NewRegistryClient creates a new DefaultRegistryClient
func NewRegistryClient() *DefaultRegistryClient {
	return &DefaultRegistryClient{}
}

// VerifyImageAccessible checks if the image is accessible in the registry
func (c *DefaultRegistryClient) VerifyImageAccessible(
	ctx context.Context,
	registryURL string,
	auth *types.DockerAuthConfig,
) (bool, error) {
	ref, err := docker.ParseReference("//" + registryURL)
	if err != nil {
		return false, fmt.Errorf("failed to parse registry URL: %w", err)
	}

	sysCtx := &types.SystemContext{}
	if auth != nil {
		sysCtx.DockerAuthConfig = auth
	}

	// Get the image source to verify accessibility
	src, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return false, fmt.Errorf("failed to access image: %w", err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close image source: %v\n", err)
		}
	}()

	// Successfully accessed the image
	return true, nil
}

// GetImageMetadata retrieves metadata from the registry manifest
func (c *DefaultRegistryClient) GetImageMetadata(
	ctx context.Context,
	registryURL string,
	auth *types.DockerAuthConfig,
) (*automotivev1alpha1.RegistryMetadata, error) {
	ref, err := docker.ParseReference("//" + registryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registry URL: %w", err)
	}

	sysCtx := &types.SystemContext{}
	if auth != nil {
		sysCtx.DockerAuthConfig = auth
	}

	src, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to access image: %w", err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close image source: %v\n", err)
		}
	}()

	return readImageMetadata(ctx, src, sysCtx)
}

func readImageMetadata(ctx context.Context, src types.ImageSource, sysCtx *types.SystemContext) (*automotivev1alpha1.RegistryMetadata, error) {
	manifestBytes, manifestType, err := src.GetManifest(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	// Parse manifest to extract metadata
	metadata := &automotivev1alpha1.RegistryMetadata{
		MediaType: manifestType,
	}

	// Handle different manifest types
	switch manifestType {
	case manifest.DockerV2Schema2MediaType:
		var m manifest.Schema2
		if err := json.Unmarshal(manifestBytes, &m); err != nil {
			return nil, fmt.Errorf("failed to parse manifest: %w", err)
		}
		metadata.LayerCount = len(m.LayersDescriptors)
		for _, layer := range m.LayersDescriptors {
			metadata.SizeBytes += layer.Size
		}

	case manifest.DockerV2ListMediaType:
		// Multi-arch manifest list
		var m manifest.Schema2List
		if err := json.Unmarshal(manifestBytes, &m); err != nil {
			return nil, fmt.Errorf("failed to parse manifest list: %w", err)
		}
		metadata.LayerCount = len(m.Manifests)
		metadata.IsMultiArch = true

		// Extract platform variants
		for _, desc := range m.Manifests {
			variant := automotivev1alpha1.PlatformVariant{
				Digest:       string(desc.Digest),
				SizeBytes:    desc.Size,
				Architecture: desc.Platform.Architecture,
				OS:           desc.Platform.OS,
				Variant:      desc.Platform.Variant,
			}
			metadata.PlatformVariants = append(metadata.PlatformVariants, variant)
		}

	default:
		// Handle OCI manifest types
		if manifestType == "application/vnd.oci.image.index.v1+json" {
			// OCI multi-arch index
			var idx manifest.OCI1Index
			if err := json.Unmarshal(manifestBytes, &idx); err != nil {
				return nil, fmt.Errorf("failed to parse OCI index: %w", err)
			}
			metadata.LayerCount = len(idx.Manifests)
			metadata.IsMultiArch = true

			// Extract platform variants from OCI index
			for _, desc := range idx.Manifests {
				variant := automotivev1alpha1.PlatformVariant{
					Digest:    string(desc.Digest),
					SizeBytes: desc.Size,
				}
				if desc.Platform != nil {
					variant.Architecture = desc.Platform.Architecture
					variant.OS = desc.Platform.OS
					variant.Variant = desc.Platform.Variant
				}
				metadata.PlatformVariants = append(metadata.PlatformVariants, variant)
			}
		} else if strings.HasPrefix(manifestType, "application/vnd.oci.image") {
			// Standard OCI image manifest
			var m manifest.OCI1
			if err := json.Unmarshal(manifestBytes, &m); err != nil {
				return nil, fmt.Errorf("failed to parse OCI manifest: %w", err)
			}
			metadata.LayerCount = len(m.Layers)
			for _, layer := range m.Layers {
				metadata.SizeBytes += layer.Size
			}
		}
	}

	// Pin this lookup to the manifest already read: a moving catalog tag must
	// not associate one revision's helper with another revision's digest.
	resolvedDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("digest image manifest: %w", err)
	}
	metadata.ResolvedDigest = resolvedDigest.String()

	// Keep every platform's helper, not just the manager's architecture.
	metadata.BuilderImages, err = readBuilderImages(ctx, src, sysCtx, &resolvedDigest, 0)
	if err != nil {
		log.FromContext(ctx).Error(err, "Could not resolve builder metadata", "digest", resolvedDigest)
	}
	metadata.BuilderImageResolved = err == nil

	return metadata, nil
}

// GetAuthFromSecret retrieves Docker auth config from a Kubernetes secret
func GetAuthFromSecret(
	ctx context.Context,
	k8sClient client.Client,
	secretRef *automotivev1alpha1.AuthSecretReference,
	defaultNamespace string,
) (*types.DockerAuthConfig, error) {
	if secretRef == nil {
		return nil, nil
	}

	namespace := secretRef.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, k8stypes.NamespacedName{Name: secretRef.Name, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get auth secret: %w", err)
	}

	// Handle docker-registry type secrets
	if secret.Type == corev1.SecretTypeDockerConfigJson {
		dockerConfig, ok := secret.Data[corev1.DockerConfigJsonKey]
		if !ok {
			return nil, fmt.Errorf("secret missing .dockerconfigjson key")
		}

		// Parse docker config
		var config DockerConfigJSON
		if err := json.Unmarshal(dockerConfig, &config); err != nil {
			return nil, fmt.Errorf("failed to parse docker config: %w", err)
		}

		// Return first auth entry (typically only one for registry secrets)
		for _, auth := range config.Auths {
			return parseDockerAuth(auth)
		}
	}

	// Handle generic secrets with username/password
	username := string(secret.Data["username"])
	password := string(secret.Data["password"])
	if username != "" && password != "" {
		return &types.DockerAuthConfig{
			Username: username,
			Password: password,
		}, nil
	}

	// Handle secrets with auth token
	if token, ok := secret.Data["token"]; ok {
		return &types.DockerAuthConfig{
			IdentityToken: string(token),
		}, nil
	}

	return nil, fmt.Errorf("secret does not contain valid credentials")
}

// DockerConfigJSON represents the structure of .dockerconfigjson
type DockerConfigJSON struct {
	Auths map[string]DockerAuth `json:"auths"`
}

// DockerAuth represents authentication credentials for a registry
type DockerAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Auth     string `json:"auth,omitempty"`
}

// parseDockerAuth extracts credentials from a DockerAuth structure
func parseDockerAuth(auth DockerAuth) (*types.DockerAuthConfig, error) {
	if auth.Username != "" && auth.Password != "" {
		return &types.DockerAuthConfig{
			Username: auth.Username,
			Password: auth.Password,
		}, nil
	}

	if auth.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to decode auth: %w", err)
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid auth format")
		}
		return &types.DockerAuthConfig{
			Username: parts[0],
			Password: parts[1],
		}, nil
	}

	return nil, fmt.Errorf("no valid credentials found")
}

// VerifyDigest verifies that the image digest matches the expected digest
func (c *DefaultRegistryClient) VerifyDigest(
	ctx context.Context,
	registryURL string,
	expectedDigest string,
	auth *types.DockerAuthConfig,
) (bool, string, error) {
	ref, err := docker.ParseReference("//" + registryURL)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse registry URL: %w", err)
	}

	sysCtx := &types.SystemContext{}
	if auth != nil {
		sysCtx.DockerAuthConfig = auth
	}

	src, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return false, "", fmt.Errorf("failed to access image: %w", err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close image source: %v\n", err)
		}
	}()

	// Get the manifest to compute digest
	manifestBytes, _, err := src.GetManifest(ctx, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to get manifest: %w", err)
	}

	// Compute the digest from the manifest
	actualDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return false, "", fmt.Errorf("failed to compute digest: %w", err)
	}

	actualDigestStr := actualDigest.String()

	// If no expected digest provided, just return the actual digest
	if expectedDigest == "" {
		return true, actualDigestStr, nil
	}

	// Compare digests
	match := actualDigestStr == expectedDigest
	return match, actualDigestStr, nil
}

// NormalizeArchitecture normalizes architecture names to OCI standard
func NormalizeArchitecture(arch string) string {
	return controllerutils.NormalizeArchToK8s(arch)
}

// GetCurrentTime returns the current time as a metav1.Time
func GetCurrentTime() *metav1.Time {
	now := metav1.Now()
	return &now
}

// readBuilderImages reads manifests and configs, never filesystem layers.
func readBuilderImages(ctx context.Context, src types.ImageSource, sys *types.SystemContext, instance *digest.Digest, depth int) ([]string, error) {
	if depth > 8 {
		return nil, fmt.Errorf("image index nesting exceeds 8 levels")
	}
	raw, mediaType, err := src.GetManifest(ctx, instance)
	if err != nil {
		return nil, err
	}
	var manifestData struct {
		Annotations map[string]string `json:"annotations"`
		Config      struct {
			MediaType string `json:"mediaType"`
		} `json:"config"`
		Manifests []struct {
			Digest digest.Digest `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &manifestData); err != nil {
		return nil, err
	}
	key := oci.Get().AnnotationKey("builder-image")
	refs := []string{}
	if ref := manifestData.Annotations[key]; ref != "" {
		refs = append(refs, ref)
	}
	if mediaType == manifest.DockerV2ListMediaType || mediaType == "application/vnd.oci.image.index.v1+json" {
		for _, child := range manifestData.Manifests {
			if err := child.Digest.Validate(); err != nil {
				return nil, err
			}
			children, err := readBuilderImages(ctx, src, sys, &child.Digest, depth+1)
			refs = append(refs, children...)
			if err != nil {
				return refs, err
			}
		}
	} else if _, annotated := manifestData.Annotations[key]; !annotated && manifestData.Config.MediaType != "application/vnd.oci.empty.v1+json" {
		// Disk artifacts use the OCI empty config and carry provenance only in
		// manifest annotations. Inspecting them as container images is invalid.
		parsed, err := image.FromUnparsedImage(ctx, sys, image.UnparsedInstance(src, instance))
		var info *types.ImageInspectInfo
		if err == nil {
			info, err = parsed.Inspect(ctx)
		}
		if err != nil {
			var artifact manifest.NonImageArtifactError
			if errors.As(err, &artifact) {
				return refs, nil
			}
			return nil, err
		}
		if ref := info.Labels[key]; ref != "" {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}
