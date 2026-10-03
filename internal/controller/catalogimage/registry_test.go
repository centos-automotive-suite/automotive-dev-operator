package catalogimage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
)

type helperSource struct {
	types.ImageSource
	manifests map[digest.Digest][]byte
	blobs     map[digest.Digest][]byte
	reads     map[digest.Digest]int
}

func (s *helperSource) Reference() types.ImageReference {
	ref, _ := docker.ParseReference("//registry.example/image:test")
	return ref
}
func (s *helperSource) GetManifest(_ context.Context, instance *digest.Digest) ([]byte, string, error) {
	key := digest.Digest("")
	if instance != nil {
		key = *instance
	}
	if s.reads != nil {
		s.reads[key]++
	}
	b, ok := s.manifests[key]
	if !ok {
		return nil, "", fmt.Errorf("missing manifest %s", key)
	}
	return b, manifest.GuessMIMEType(b), nil
}
func (s *helperSource) GetBlob(_ context.Context, info types.BlobInfo, _ types.BlobInfoCache) (io.ReadCloser, int64, error) {
	b, ok := s.blobs[info.Digest]
	if !ok {
		return nil, 0, fmt.Errorf("missing blob %s", info.Digest)
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}
func TestReadBuilderImages(t *testing.T) {
	key := oci.Get().AnnotationKey("builder-image")
	encode := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	config := encode(map[string]any{"architecture": "arm64", "os": "linux", "config": map[string]any{"Labels": map[string]string{key: "registry/helper:legacy"}}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{}}})
	cfgDigest := digest.FromBytes(config)
	schema2 := encode(map[string]any{"schemaVersion": 2, "mediaType": manifest.DockerV2Schema2MediaType, "config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(config), "digest": cfgDigest}, "layers": []any{}})
	annotated := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "annotations": map[string]string{key: "registry/helper:pinned"}})
	noHelper := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "annotations": map[string]string{key: ""}})
	diskManifest := map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"artifactType": "application/vnd.automotive.disk.simg",
		"config":       map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "size": 2, "digest": digest.FromString("{}"), "data": "e30="},
	}
	diskWithoutHelper := encode(diskManifest)
	diskManifest["config"] = map[string]any{"mediaType": "application/vnd.example.artifact.config.v1+json", "size": 2, "digest": digest.FromString("{}")}
	customArtifact := encode(diskManifest)
	diskManifest["annotations"] = map[string]string{key: "registry/helper:disk"}
	diskWithHelper := encode(diskManifest)
	schemaDigest, annotatedDigest := digest.FromBytes(schema2), digest.FromBytes(annotated)
	index := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{map[string]any{"digest": schemaDigest}, map[string]any{"digest": annotatedDigest}}})
	for _, tc := range []struct {
		name    string
		raw     []byte
		want    []string
		missing bool
	}{
		{name: "config label", raw: schema2, want: []string{"registry/helper:legacy"}},
		{name: "manifest annotation", raw: annotated, want: []string{"registry/helper:pinned"}},
		{name: "explicit empty annotation", raw: noHelper},
		{name: "legacy disk artifact without helper", raw: diskWithoutHelper},
		{name: "custom artifact config without helper", raw: customArtifact},
		{name: "disk artifact with helper", raw: diskWithHelper, want: []string{"registry/helper:disk"}},
		{name: "every platform", raw: index, want: []string{"registry/helper:legacy", "registry/helper:pinned"}},
		{name: "inaccessible config is unresolved", raw: schema2, missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &helperSource{manifests: map[digest.Digest][]byte{"": tc.raw, schemaDigest: schema2, annotatedDigest: annotated}, blobs: map[digest.Digest][]byte{cfgDigest: config}, reads: map[digest.Digest]int{}}
			if tc.missing {
				src.blobs = nil
			}
			rootDigest := digest.FromBytes(tc.raw)
			src.manifests[rootDigest] = tc.raw
			metadata, err := readImageMetadata(context.Background(), src, &types.SystemContext{})
			if err != nil || metadata == nil {
				t.Fatalf("lost manifest metadata: %v", err)
			}
			if metadata.ResolvedDigest != rootDigest.String() || metadata.BuilderImageResolved == tc.missing {
				t.Fatalf("incorrect metadata: %+v", metadata)
			}
			if src.reads[""] != 1 || src.reads[rootDigest] != 0 {
				t.Fatalf("top-level manifest was fetched again: %v", src.reads)
			}
			for key, reads := range src.reads {
				if reads != 1 {
					t.Fatalf("manifest %s fetched %d times", key, reads)
				}
			}
			got, err := readBuilderImages(context.Background(), src, &types.SystemContext{}, &rootDigest, 0)
			if tc.missing {
				if err == nil {
					t.Fatal("silently accepted inaccessible config")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReadBuilderImagesContinuesAfterChildFailure(t *testing.T) {
	key := oci.Get().AnnotationKey("builder-image")
	before := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","annotations":{%q:"registry/helper:before"}}`, key)
	after := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","annotations":{%q:"registry/helper:after"}}`, key)
	beforeDigest, afterDigest := digest.FromBytes(before), digest.FromBytes(after)
	want := []string{"registry/helper:before", "registry/helper:after"}
	for _, tc := range []struct {
		name     string
		failures []digest.Digest
	}{
		{name: "missing manifest", failures: []digest.Digest{digest.FromString("missing")}},
		{name: "invalid digest", failures: []digest.Digest{"sha256:invalid"}},
		{name: "multiple failures", failures: []digest.Digest{digest.FromString("missing one"), digest.FromString("missing two")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			children := []string{fmt.Sprintf(`{"digest":%q}`, beforeDigest)}
			for _, failure := range tc.failures {
				children = append(children, fmt.Sprintf(`{"digest":%q}`, failure))
			}
			children = append(children, fmt.Sprintf(`{"digest":%q}`, afterDigest))
			raw := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}`, strings.Join(children, ","))
			src := &helperSource{manifests: map[digest.Digest][]byte{"": raw, beforeDigest: before, afterDigest: after}}
			refs, err := readBuilderImages(context.Background(), src, &types.SystemContext{}, nil, 0)
			if !slices.Equal(refs, want) {
				t.Fatalf("got %v, want references from both sides of the failure: %v", refs, want)
			}
			if err == nil {
				t.Fatal("silently accepted incomplete helper resolution")
			}
			for _, failure := range tc.failures {
				if !strings.Contains(err.Error(), failure.String()) {
					t.Errorf("error does not identify failed child %s: %v", failure, err)
				}
			}
			metadata, err := readImageMetadata(context.Background(), src, &types.SystemContext{})
			if err != nil || metadata == nil {
				t.Fatalf("lost metadata: %v", err)
			}
			if metadata.BuilderImageResolved || !slices.Equal(metadata.BuilderImages, want) {
				t.Fatalf("incorrect partial helper metadata: %+v", metadata)
			}
			if metadata.ResolvedDigest != digest.FromBytes(raw).String() || !metadata.IsMultiArch || len(metadata.PlatformVariants) != len(children) {
				t.Fatalf("lost index metadata: %+v", metadata)
			}
		})
	}
}

func TestMetadataSurvivesHelperExtractionFailure(t *testing.T) {
	for _, multiArch := range []bool{false, true} {
		t.Run(fmt.Sprint("multiArch=", multiArch), func(t *testing.T) {
			var raw []byte
			if multiArch {
				raw = fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":%q,"size":123,"platform":{"architecture":"arm64","os":"linux"}}]}`, digest.FromString("missing manifest"))
			} else {
				raw = fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":42},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":%q,"size":123}]}`, digest.FromString("missing config"), digest.FromString("layer"))
			}
			d := digest.FromBytes(raw)
			src := &helperSource{manifests: map[digest.Digest][]byte{"": raw, d: raw}}
			metadata, err := readImageMetadata(context.Background(), src, &types.SystemContext{})
			if err != nil || metadata == nil {
				t.Fatalf("lost metadata: %v", err)
			}
			if metadata.BuilderImageResolved || metadata.ResolvedDigest != d.String() || metadata.LayerCount != 1 || metadata.IsMultiArch != multiArch {
				t.Fatalf("incorrect metadata: %+v", metadata)
			}
			if multiArch {
				if len(metadata.PlatformVariants) != 1 || metadata.PlatformVariants[0].Architecture != "arm64" || metadata.PlatformVariants[0].SizeBytes != 123 {
					t.Fatalf("lost platforms: %+v", metadata.PlatformVariants)
				}
			} else if metadata.SizeBytes != 123 {
				t.Fatalf("lost image size: %d", metadata.SizeBytes)
			}
		})
	}
}
