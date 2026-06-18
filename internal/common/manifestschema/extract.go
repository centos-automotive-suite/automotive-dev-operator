package manifestschema

import (
	"archive/tar"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// FetchImageFn is the function used to pull a container image.
// Replaceable for testing.
var FetchImageFn = func(ref name.Reference) (v1.Image, error) {
	return remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

// ResolveDigestFn resolves an image reference to its digest string.
// Replaceable for testing.
var ResolveDigestFn = func(ref name.Reference) (string, error) {
	desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

// ExtractSchemaFromImage extracts manifest_schema.yml from an AIB container
// image by pulling its layers from the registry.
func ExtractSchemaFromImage(imageRef string) ([]byte, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", imageRef, err)
	}

	img, err := FetchImageFn(ref)
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", imageRef, err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image layers: %w", err)
	}

	for i := len(layers) - 1; i >= 0; i-- {
		data, err := findFileInLayer(layers[i], SchemaPathInContainer)
		if err != nil {
			continue
		}
		if data != nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("manifest_schema.yml not found in image %s", imageRef)
}

func findFileInLayer(layer v1.Layer, targetPath string) ([]byte, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		cleanName := strings.TrimPrefix(hdr.Name, "./")
		cleanName = strings.TrimPrefix(cleanName, "/")
		if cleanName == targetPath {
			const maxSchemaSize = 10 << 20 // 10 MB
			data, err := io.ReadAll(io.LimitReader(tr, maxSchemaSize))
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", targetPath, err)
			}
			return data, nil
		}
	}
}
