package caibcommon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
)

// ReadManifestAnnotations fetches the OCI manifest for the given image reference
// and returns its annotations map along with the manifest digest.
func ReadManifestAnnotations(ociRef string, sysCtx *types.SystemContext) (map[string]string, string, error) {
	ref, err := docker.ParseReference("//" + ociRef)
	if err != nil {
		return nil, "", fmt.Errorf("parse reference: %w", err)
	}

	ctx := context.Background()
	src, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, "", fmt.Errorf("open image source: %w", err)
	}
	defer func() { _ = src.Close() }()

	rawManifest, _, err := src.GetManifest(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("get manifest: %w", err)
	}

	digest, err := manifest.Digest(rawManifest)
	if err != nil {
		return nil, "", fmt.Errorf("compute digest: %w", err)
	}

	var parsed struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(rawManifest, &parsed); err != nil {
		return nil, "", fmt.Errorf("parse manifest JSON: %w", err)
	}

	return parsed.Annotations, string(digest), nil
}

// NewRegistrySystemContext creates a containers/image SystemContext configured
// with TLS settings, auth file path, and registry credentials extracted from
// environment variables.
func NewRegistrySystemContext(ociRef string, insecureSkipTLS bool, authFile string) *types.SystemContext {
	sysCtx := &types.SystemContext{}
	if insecureSkipTLS {
		sysCtx.DockerInsecureSkipTLSVerify = types.OptionalBoolTrue
	}

	_, username, password := registryauth.ExtractRegistryCredentials(ociRef, "")
	if authFile != "" {
		sysCtx.AuthFilePath = authFile
	}
	if username != "" && password != "" {
		sysCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: username,
			Password: password,
		}
	}

	return sysCtx
}
