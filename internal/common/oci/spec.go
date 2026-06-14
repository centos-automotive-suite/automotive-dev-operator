// Package oci defines the shared OCI artifact contract (media types, annotations, referrer types).
package oci

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed spec.json
var specJSON []byte

var spec Spec

func init() {
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		panic(fmt.Sprintf("oci: failed to parse spec.json: %v", err))
	}
}

// Spec is the top-level OCI artifact specification.
type Spec struct {
	AnnotationPrefix string         `json:"annotationPrefix"`
	Annotations      AnnotationSpec `json:"annotations"`
	MediaTypes       MediaTypeSpec  `json:"mediaTypes"`
	ReferrerTypes    []ReferrerType `json:"referrerTypes"`
}

// AnnotationSpec groups manifest-level and layer-level annotation keys.
type AnnotationSpec struct {
	Manifest ManifestAnnotations `json:"manifest"`
	Layer    LayerAnnotations    `json:"layer"`
}

// ManifestAnnotations separates required from optional annotation keys.
type ManifestAnnotations struct {
	Required []AnnotationKey `json:"required"`
	Optional []AnnotationKey `json:"optional"`
}

// LayerAnnotations separates custom (prefixed) from standard OCI keys.
type LayerAnnotations struct {
	Custom   []AnnotationKey `json:"custom"`
	Standard []AnnotationKey `json:"standard"`
}

// AnnotationKey pairs an annotation key with its shell variable name.
type AnnotationKey struct {
	Key string `json:"key"`
	Var string `json:"var"`
}

// MediaTypeSpec contains all media type families.
type MediaTypeSpec struct {
	DiskFormats         map[string]string `json:"diskFormats"`
	CompressionSuffixes map[string]string `json:"compressionSuffixes"`
	ContainerLayers     map[string]string `json:"containerLayers"`
	Generic             map[string]string `json:"generic"`
}

// ReferrerType defines an OCI referrer artifact type with display label and default filename.
type ReferrerType struct {
	ArtifactType string `json:"artifactType"`
	Label        string `json:"label"`
	Var          string `json:"var"`
	Filename     string `json:"filename"`
}

// Get returns the parsed OCI artifact specification.
func Get() *Spec { return &spec }

// AnnotationKey returns a fully-qualified annotation key (prefix + short name).
func (s *Spec) AnnotationKey(short string) string {
	return s.AnnotationPrefix + short
}

// ReferrerFileMap returns a map from artifact type to default filename.
func (s *Spec) ReferrerFileMap() map[string]string {
	m := make(map[string]string, len(s.ReferrerTypes))
	for _, r := range s.ReferrerTypes {
		m[r.ArtifactType] = r.Filename
	}
	return m
}

// AllManifestAnnotationKeys returns all annotation keys (required + optional).
func (s *Spec) AllManifestAnnotationKeys() []AnnotationKey {
	result := make([]AnnotationKey, 0, len(s.Annotations.Manifest.Required)+len(s.Annotations.Manifest.Optional))
	result = append(result, s.Annotations.Manifest.Required...)
	result = append(result, s.Annotations.Manifest.Optional...)
	return result
}

// ReferrerArtifactTypeByLabel returns the artifact type string for a given display label.
// Panics on unknown labels since callers use compile-time-known string literals.
func (s *Spec) ReferrerArtifactTypeByLabel(label string) string {
	for _, r := range s.ReferrerTypes {
		if r.Label == label {
			return r.ArtifactType
		}
	}
	panic(fmt.Sprintf("oci: unknown referrer label %q", label))
}

// ShellVars generates deterministic shell variable assignments for all OCI constants.
func (s *Spec) ShellVars() string {
	var b strings.Builder
	b.WriteString("# --- OCI Artifact Constants (generated from spec.json) ---\n")

	fmt.Fprintf(&b, "export OCI_ANNOTATION_PREFIX=%q\n", s.AnnotationPrefix)

	for _, ak := range s.Annotations.Manifest.Required {
		fmt.Fprintf(&b, "export OCI_ANN_%s=%q\n", ak.Var, s.AnnotationPrefix+ak.Key)
	}
	for _, ak := range s.Annotations.Manifest.Optional {
		fmt.Fprintf(&b, "export OCI_ANN_%s=%q\n", ak.Var, s.AnnotationPrefix+ak.Key)
	}

	for _, ak := range s.Annotations.Layer.Custom {
		fmt.Fprintf(&b, "export OCI_LAYER_ANN_%s=%q\n", ak.Var, s.AnnotationPrefix+ak.Key)
	}
	for _, ak := range s.Annotations.Layer.Standard {
		fmt.Fprintf(&b, "export OCI_LAYER_ANN_%s=%q\n", ak.Var, ak.Key)
	}

	writeMapSorted(&b, "OCI_MEDIA_DISK_", s.MediaTypes.DiskFormats)
	writeMapSorted(&b, "OCI_COMPRESS_SUFFIX_", s.MediaTypes.CompressionSuffixes)
	writeMapSorted(&b, "OCI_MEDIA_LAYER_", s.MediaTypes.ContainerLayers)
	writeMapSorted(&b, "OCI_MEDIA_", s.MediaTypes.Generic)

	for _, r := range s.ReferrerTypes {
		fmt.Fprintf(&b, "export OCI_REFERRER_TYPE_%s=%q\n", r.Var, r.ArtifactType)
		fmt.Fprintf(&b, "export OCI_REFERRER_FILE_%s=%q\n", r.Var, r.Filename)
	}

	b.WriteString("# --- End OCI Artifact Constants ---\n")
	return b.String()
}

func writeMapSorted(b *strings.Builder, prefix string, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "export %s%s=%q\n", prefix, strings.ToUpper(k), m[k])
	}
}
