package manifestschema

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// rejectAllSchema fails every manifest, so a poisoned cache entry shows up as a
// validation failure for a manifest the genuine schema accepts.
var rejectAllSchema = []byte(`
$schema: https://json-schema.org/draft-07/schema
type: object
required:
  - poisoned
`)

var genuineManifest = []byte("name: demo\n")

// An attacker's registry claims its tag resolves to the genuine image's digest
// but serves its own image for the tag. The genuine image must still validate
// against its own schema afterwards.
func TestValidateFromImageIgnoresSpoofedHeadDigest(t *testing.T) {
	isolateSchemaCaches(t)

	genuineImg := schemaImage(t, minimalSchema, nil)

	reg := newTestRegistry(t)
	reg.add(t, "aib", "good", genuineImg)
	reg.add(t, "evil", "latest", schemaImage(t, rejectAllSchema, nil))
	host := reg.start(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodHead || r.URL.Path != "/v2/evil/manifests/latest" {
			return false
		}
		writeManifestHeaders(t, w, genuineImg)
		w.WriteHeader(http.StatusOK)
		return true
	})

	_, _ = ValidateFromImage(host+"/evil:latest", genuineManifest)

	assertGenuineSchemaUsed(t, host+"/aib:good")
}

// An attacker's registry mirrors the genuine manifest but serves a different
// blob for its schema layer. The tampered layer must not reach the cache.
func TestValidateFromImageRejectsTamperedLayer(t *testing.T) {
	isolateSchemaCaches(t)

	padding := incompressible(t, 1<<20)
	genuineImg := schemaImage(t, minimalSchema, padding)
	genuine := imageDigest(t, genuineImg)
	layers, err := genuineImg.Layers()
	if err != nil {
		t.Fatal(err)
	}
	genuineLayer, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Schema first, so a reader that stops at the file never reaches the
	// end of the blob where its digest is checked.
	tampered := gzipTar(t, tarFile{SchemaPathInContainer, rejectAllSchema}, tarFile{"padding", padding})

	reg := newTestRegistry(t)
	reg.add(t, "aib", "good", genuineImg)
	reg.add(t, "evil", "mirror", genuineImg)
	host := reg.start(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/evil/blobs/"+genuineLayer.String() {
			return false
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tampered)
		return true
	})

	_, _ = ValidateFromImage(host+"/evil@"+genuine.String(), genuineManifest)

	assertGenuineSchemaUsed(t, host+"/aib:good")
}

// An attacker's registry mirrors the genuine manifest but replaces the layer
// holding its schema with a tar that ends at once. A layer without the schema
// must still have its digest checked, or the search falls through to an older
// schema further down the image.
func TestValidateFromImageRejectsTruncatedSchemaLayer(t *testing.T) {
	isolateSchemaCaches(t)

	// The lower layer's older schema is shadowed by the top layer's. The top
	// layer is padded because a pull stops at the layer's size: a layer
	// shorter than the end marker would be read to its end anyway.
	padding := incompressible(t, 1<<20)
	genuineImg := imageFromLayers(t,
		gzipTar(t, tarFile{SchemaPathInContainer, rejectAllSchema}),
		gzipTar(t, tarFile{SchemaPathInContainer, minimalSchema}, tarFile{"padding", padding}))
	genuine := imageDigest(t, genuineImg)
	layers, err := genuineImg.Layers()
	if err != nil {
		t.Fatal(err)
	}
	topLayer, err := layers[1].Digest()
	if err != nil {
		t.Fatal(err)
	}
	// An uncompressed tar's end marker, then padding: the tar ends while the
	// blob, and the digest check at its end, are still to come.
	truncated := append(make([]byte, 2*512), padding...)

	reg := newTestRegistry(t)
	reg.add(t, "aib", "good", genuineImg)
	reg.add(t, "evil", "mirror", genuineImg)
	host := reg.start(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/evil/blobs/"+topLayer.String() {
			return false
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(truncated)
		return true
	})

	_, _ = ValidateFromImage(host+"/evil@"+genuine.String(), genuineManifest)

	assertGenuineSchemaUsed(t, host+"/aib:good")
}

func assertGenuineSchemaUsed(t *testing.T, ref string) {
	t.Helper()
	res, err := ValidateFromImage(ref, genuineManifest)
	if err != nil {
		t.Fatalf("validating against %s: %v", ref, err)
	}
	if !res.Valid {
		t.Fatalf("%s was validated against the attacker's schema: %v", ref, res.Errors)
	}
}

func isolateSchemaCaches(t *testing.T) {
	t.Helper()
	t.Setenv("CAIB_SKIP_MANIFEST_VALIDATION", "")
	withTempCacheDir(t)
	compiledCache.Clear()
	t.Cleanup(compiledCache.Clear)
}

// testRegistry serves images for pulls: manifests by tag or digest, and blobs.
type testRegistry struct {
	images map[string]v1.Image // "repo:tag" and "repo@digest"
	blobs  map[string][]byte   // digest → content, shared by all repos
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	return &testRegistry{images: map[string]v1.Image{}, blobs: map[string][]byte{}}
}

func (reg *testRegistry) add(t *testing.T, repo, tag string, img v1.Image) {
	t.Helper()
	reg.images[repo+":"+tag] = img
	reg.images[repo+"@"+imageDigest(t, img).String()] = img

	cfgName, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	reg.blobs[cfgName.String()] = cfg

	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		reg.blobs[d.String()] = b
	}
}

// start serves the registry. intercept handles a request itself by
// returning true, which is how a test plays a malicious registry.
func (reg *testRegistry) start(t *testing.T, intercept func(http.ResponseWriter, *http.Request) bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept(w, r) {
			return
		}
		reg.serve(t, w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func (reg *testRegistry) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	if path == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if repo, ref, ok := strings.Cut(path, "/manifests/"); ok {
		sep := ":"
		if strings.HasPrefix(ref, "sha256:") {
			sep = "@"
		}
		img, found := reg.images[repo+sep+ref]
		if !found {
			http.NotFound(w, r)
			return
		}
		writeManifestHeaders(t, w, img)
		if r.Method == http.MethodHead {
			return
		}
		raw, err := img.RawManifest()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(raw)
		return
	}
	if _, digest, ok := strings.Cut(path, "/blobs/"); ok {
		b, found := reg.blobs[digest]
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
		return
	}
	http.NotFound(w, r)
}

func writeManifestHeaders(t *testing.T, w http.ResponseWriter, img v1.Image) {
	t.Helper()
	raw, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	mt, err := img.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	w.Header().Set("Content-Type", string(mt))
	w.Header().Set("Docker-Content-Digest", imageDigest(t, img).String())
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
}

// schemaImage builds a single-layer image holding schema, followed by an
// optional padding file.
func schemaImage(t *testing.T, schema, padding []byte) v1.Image {
	t.Helper()
	files := []tarFile{{SchemaPathInContainer, schema}}
	if padding != nil {
		files = append(files, tarFile{"padding", padding})
	}
	return imageFromLayers(t, gzipTar(t, files...))
}

// imageFromLayers builds an image from layer blobs, bottom first.
func imageFromLayers(t *testing.T, blobs ...[]byte) v1.Image {
	t.Helper()
	layers := make([]v1.Layer, 0, len(blobs))
	for _, blob := range blobs {
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(blob)), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		layers = append(layers, layer)
	}
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

type tarFile struct {
	name    string
	content []byte
}

// gzipTar writes files into a gzipped tar, in order.
func gzipTar(t *testing.T, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Size: int64(len(f.content)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func incompressible(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func imageDigest(t *testing.T, img v1.Image) v1.Hash {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
