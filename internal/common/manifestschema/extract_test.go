package manifestschema

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type testLayer struct {
	buf []byte
}

func newTestLayer(files map[string][]byte) *testLayer {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(content)), Mode: 0644})
		_, _ = tw.Write(content)
	}
	_ = tw.Close()
	_ = gz.Close()
	return &testLayer{buf: buf.Bytes()}
}

func (l *testLayer) Digest() (v1.Hash, error)            { return v1.Hash{}, nil }
func (l *testLayer) DiffID() (v1.Hash, error)            { return v1.Hash{}, nil }
func (l *testLayer) Size() (int64, error)                { return int64(len(l.buf)), nil }
func (l *testLayer) MediaType() (types.MediaType, error) { return types.OCILayer, nil }
func (l *testLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.buf)), nil
}
func (l *testLayer) Uncompressed() (io.ReadCloser, error) {
	gz, err := gzip.NewReader(bytes.NewReader(l.buf))
	if err != nil {
		return nil, err
	}
	return gz, nil
}

type testImage struct{ layers []v1.Layer }

func (i *testImage) Layers() ([]v1.Layer, error)             { return i.layers, nil }
func (i *testImage) MediaType() (types.MediaType, error)     { return types.DockerManifestSchema2, nil }
func (i *testImage) Size() (int64, error)                    { return 0, nil }
func (i *testImage) ConfigName() (v1.Hash, error)            { return v1.Hash{}, nil }
func (i *testImage) ConfigFile() (*v1.ConfigFile, error)     { return &v1.ConfigFile{}, nil }
func (i *testImage) RawConfigFile() ([]byte, error)          { return []byte("{}"), nil }
func (i *testImage) Digest() (v1.Hash, error)                { return v1.Hash{}, nil }
func (i *testImage) Manifest() (*v1.Manifest, error)         { return &v1.Manifest{}, nil }
func (i *testImage) RawManifest() ([]byte, error)            { return []byte("{}"), nil }
func (i *testImage) LayerByDigest(v1.Hash) (v1.Layer, error) { return nil, fmt.Errorf("unimplemented") }
func (i *testImage) LayerByDiffID(v1.Hash) (v1.Layer, error) { return nil, fmt.Errorf("unimplemented") }

func TestExtractSchemaFromImage(t *testing.T) {
	orig := FetchImageFn
	defer func() { FetchImageFn = orig }()

	t.Run("extracts from layer", func(t *testing.T) {
		FetchImageFn = func(_ name.Reference) (v1.Image, error) {
			return &testImage{layers: []v1.Layer{
				newTestLayer(map[string][]byte{SchemaPathInContainer: minimalSchema}),
			}}, nil
		}
		data, err := ExtractSchemaFromImage("fake:latest")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Contains(data, []byte("$schema")) {
			t.Error("expected schema content")
		}
	})

	t.Run("not found", func(t *testing.T) {
		FetchImageFn = func(_ name.Reference) (v1.Image, error) {
			return &testImage{layers: []v1.Layer{
				newTestLayer(map[string][]byte{"other/file": []byte("x")}),
			}}, nil
		}
		_, err := ExtractSchemaFromImage("empty:latest")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("top layer wins", func(t *testing.T) {
		old := []byte("type: object\n")
		FetchImageFn = func(_ name.Reference) (v1.Image, error) {
			return &testImage{layers: []v1.Layer{
				newTestLayer(map[string][]byte{SchemaPathInContainer: old}),
				newTestLayer(map[string][]byte{SchemaPathInContainer: minimalSchema}),
			}}, nil
		}
		data, err := ExtractSchemaFromImage("layered:latest")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Contains(data, []byte("additionalProperties")) {
			t.Error("expected top layer schema")
		}
	})

	t.Run("invalid ref", func(t *testing.T) {
		_, err := ExtractSchemaFromImage("!!!invalid!!!")
		if err == nil {
			t.Fatal("expected error for invalid ref")
		}
	})

	t.Run("handles ./ prefix in tar", func(t *testing.T) {
		FetchImageFn = func(_ name.Reference) (v1.Image, error) {
			return &testImage{layers: []v1.Layer{
				newTestLayer(map[string][]byte{"./" + SchemaPathInContainer: []byte("found")}),
			}}, nil
		}
		data, err := ExtractSchemaFromImage("prefixed:latest")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "found" {
			t.Errorf("got %q, want %q", data, "found")
		}
	})
}
