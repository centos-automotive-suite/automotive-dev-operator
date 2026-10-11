package registryauth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/registryutil"
	"github.com/docker/cli/cli/config"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// PinImage resolves a tag with the user's registry credentials, preserving the requested tag.
// On failure it returns the original reference so callers can submit it unchanged.
func PinImage(ctx context.Context, ref, authFile string) (string, error) {
	image, err := name.ParseReference(strings.TrimSpace(ref))
	if err != nil {
		return ref, err
	}
	if _, pinned := image.(name.Digest); pinned {
		return ref, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	auth, err := imageRegistryAuth(image.Context().RegistryStr(), authFile)
	if err != nil {
		return ref, err
	}
	opts := []remote.Option{remote.WithContext(ctx), auth}
	descriptor, err := remote.Head(image, opts...)
	if err != nil && ctx.Err() == nil {
		manifest, getErr := remote.Get(image, opts...)
		err = getErr
		if err == nil {
			descriptor = &manifest.Descriptor
		}
	}
	if err != nil {
		return ref, fmt.Errorf("resolving OCI repository image: %w", err)
	}
	return registryutil.PinDigest(strings.TrimSpace(ref), descriptor.Digest.String()), nil
}

func imageRegistryAuth(registry, authFile string) (remote.Option, error) {
	creds, err := ResolveRegistryCredentials(registry, os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD"), authFile)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return remote.WithAuthFromKeychain(authn.DefaultKeychain), nil
	}
	auth := authn.AuthConfig{Username: creds.Username, Password: creds.Password}
	if creds.DockerConfig != "" {
		cf, err := config.LoadFromReader(strings.NewReader(creds.DockerConfig))
		if err != nil {
			return nil, err
		}
		key := registry
		if key == name.DefaultRegistry {
			key = "https://" + name.DefaultRegistry + "/v1/"
		}
		entry, err := cf.GetAuthConfig(key)
		if err != nil {
			return nil, err
		}
		auth = authn.AuthConfig{Username: entry.Username, Password: entry.Password, Auth: entry.Auth, IdentityToken: entry.IdentityToken, RegistryToken: entry.RegistryToken}
	}
	return remote.WithAuth(authn.FromConfig(auth)), nil
}
