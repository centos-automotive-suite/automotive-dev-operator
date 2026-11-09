package manifestschema

import (
	"archive/tar"
	"fmt"
	"io"
	"slices"
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
// image by pulling its layers from the registry. It takes a digest so the
// pulled content is verified against it.
func ExtractSchemaFromImage(ref name.Digest) ([]byte, error) {
	img, err := FetchImageFn(ref)
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", ref, err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image layers: %w", err)
	}

	for _, layer := range slices.Backward(layers) {
		data, err := findFileInLayer(layer, SchemaPathInContainer)
		if err != nil {
			return nil, fmt.Errorf("reading layer of %s: %w", ref, err)
		}
		if data != nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("manifest_schema.yml not found in image %s", ref)
}

func findFileInLayer(layer v1.Layer, targetPath string) ([]byte, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	data, err := findFileInTar(rc, targetPath)
	if err != nil {
		return nil, err
	}
	// A pulled layer's digest is only checked when its stream reaches EOF, and
	// the tar can end before that. Read the rest before trusting either the
	// file or its absence.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return nil, fmt.Errorf("verifying layer: %w", err)
	}
	return data, nil
}

// findFileInTar returns the contents of targetPath, or nil if the archive has
// no such file.
func findFileInTar(r io.Reader, targetPath string) ([]byte, error) {
	tr := tar.NewReader(r)
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
