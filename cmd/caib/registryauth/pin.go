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

// PinImage resolves a qualified tag, preserving the requested tag. Environment
// credentials are used only for envRegistry, the registry bound to the push target.
// On failure it returns the original reference so callers can submit it unchanged.
func PinImage(ctx context.Context, ref, authFile, envRegistry string) (string, error) {
	image, err := name.ParseReference(strings.TrimSpace(ref))
	if err != nil {
		return ref, err
	}
	if _, pinned := image.(name.Digest); pinned {
		return ref, nil
	}
	host, _, qualified := strings.Cut(strings.TrimSpace(ref), "/")
	if !qualified || (!strings.ContainsAny(host, ".:") && host != "localhost") {
		return ref, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	auth, err := imageRegistryAuth(image.Context().RegistryStr(), authFile, envRegistry)
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

func imageRegistryAuth(registry, authFile, envRegistry string) (remote.Option, error) {
	authFile = strings.TrimSpace(authFile)
	if authFile != "" {
		content, err := os.ReadFile(authFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read --registry-auth-file %q: %w", authFile, err)
		}
		matched, err := authFileHasRegistryAuth(content, registry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse --registry-auth-file %q: %w", authFile, err)
		}
		if !matched {
			authFile = ""
		}
	}
	username, password := "", ""
	envRegistry = registryutil.NormalizeRegistryHost(envRegistry)
	if envRegistry == "docker.io" {
		envRegistry = name.DefaultRegistry
	}
	if registryutil.RegistryHostMatches(registry, envRegistry) {
		username, password = os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD")
	}
	creds, err := ResolveRegistryCredentials(registry, username, password, authFile)
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
