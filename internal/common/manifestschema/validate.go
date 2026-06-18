// Package manifestschema provides AIB manifest validation against the JSON Schema
// extracted from the automotive-image-builder container image.
// This package has no gin, k8s, or server dependencies and can be used by both
// the build API server and the caib CLI.
package manifestschema

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v3"
)

var (
	printer       = message.NewPrinter(language.English)
	compiledCache sync.Map // digest → *jsonschema.Schema
)

// SchemaPathInContainer is where the AIB RPM installs the manifest schema.
const SchemaPathInContainer = "usr/lib/automotive-image-builder/files/manifest_schema.yml"

// ValidationResult holds the outcome of a manifest validation.
type ValidationResult struct {
	Valid  bool
	Errors []string
}

func (r ValidationResult) Error() string {
	return fmt.Sprintf("manifest validation errors:\n  - %s", strings.Join(r.Errors, "\n  - "))
}

// ValidateFromImage extracts a schema from the given AIB container image and
// validates the manifest against it. Resolves the image tag to a digest first,
// then checks a content-addressed cache before pulling layers.
func ValidateFromImage(imageRef string, manifest []byte) (ValidationResult, error) {
	if os.Getenv("CAIB_SKIP_MANIFEST_VALIDATION") != "" {
		return ValidationResult{Valid: true}, nil
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return ValidationResult{}, fmt.Errorf("parsing image reference %q: %w", imageRef, err)
	}

	var digest string
	if cached := loadCachedDigest(imageRef); cached != "" {
		digest = cached
	} else {
		digest, err = ResolveDigestFn(ref)
		if err != nil {
			return ValidationResult{}, fmt.Errorf("resolving digest for %q: %w", imageRef, err)
		}
		saveCachedDigest(imageRef, digest)
	}

	schemaYAML := loadCachedSchema(digest)
	if schemaYAML == nil {
		schemaYAML, err = ExtractSchemaFromImage(imageRef)
		if err != nil {
			return ValidationResult{}, err
		}
		_ = saveCachedSchema(digest, schemaYAML)
	}

	var schema *jsonschema.Schema
	if cached, ok := compiledCache.Load(digest); ok {
		schema = cached.(*jsonschema.Schema)
	} else {
		compiled, err := CompileSchema(schemaYAML)
		if err != nil {
			return ValidationResult{}, err
		}
		compiledCache.Store(digest, compiled)
		schema = compiled
	}

	return ValidateManifest(schema, manifest), nil
}

// ValidateManifest validates a YAML manifest against a pre-compiled schema.
func ValidateManifest(schema *jsonschema.Schema, manifest []byte) ValidationResult {
	var data any
	if err := yaml.Unmarshal(manifest, &data); err != nil {
		return ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("invalid YAML: %v", err)},
		}
	}

	data = ConvertYAMLToJSONCompatible(data)

	err := schema.Validate(data)
	if err == nil {
		return ValidationResult{Valid: true}
	}

	var errors []string
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		collectLeafErrors(ve, &errors)
		if len(errors) == 0 {
			errors = []string{ve.Error()}
		}
	} else {
		errors = []string{err.Error()}
	}

	return ValidationResult{Valid: false, Errors: errors}
}

func collectLeafErrors(ve *jsonschema.ValidationError, out *[]string) {
	if len(ve.Causes) == 0 {
		loc := "/" + strings.Join(ve.InstanceLocation, "/")
		*out = append(*out, fmt.Sprintf("%s: %s", loc, ve.ErrorKind.LocalizedString(printer)))
		return
	}
	for _, cause := range ve.Causes {
		collectLeafErrors(cause, out)
	}
}

// CompileSchema parses a YAML schema and compiles it for validation.
// Uses an ECMA-262 compatible regexp engine to support patterns with
// negative lookaheads used in the AIB schema.
func CompileSchema(schemaYAML []byte) (*jsonschema.Schema, error) {
	var schemaObj any
	if err := yaml.Unmarshal(schemaYAML, &schemaObj); err != nil {
		return nil, fmt.Errorf("parsing schema YAML: %w", err)
	}
	schemaObj = ConvertYAMLToJSONCompatible(schemaObj)

	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(ecmaRegexpEngine)
	if err := compiler.AddResource("manifest_schema.json", schemaObj); err != nil {
		return nil, fmt.Errorf("adding schema resource: %w", err)
	}

	return compiler.Compile("manifest_schema.json")
}

// ecmaRegexp adapts regexp2 to the jsonschema.Regexp interface.
type ecmaRegexp struct {
	re  *regexp2.Regexp
	src string
}

func (r *ecmaRegexp) MatchString(s string) bool {
	m, err := r.re.MatchString(s)
	if err != nil {
		slog.Warn("regexp2 match failed, skipping pattern check", "pattern", r.src, "error", err)
		return true
	}
	return m
}

func (r *ecmaRegexp) String() string { return r.src }

func ecmaRegexpEngine(s string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(s, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return &ecmaRegexp{re: re, src: s}, nil
}

// ConvertYAMLToJSONCompatible converts YAML-decoded data to JSON-compatible types.
// YAML can decode maps as map[any]any; JSON Schema validation expects map[string]any.
func ConvertYAMLToJSONCompatible(v any) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, v := range val {
			result[k] = ConvertYAMLToJSONCompatible(v)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(val))
		for k, v := range val {
			result[fmt.Sprintf("%v", k)] = ConvertYAMLToJSONCompatible(v)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, v := range val {
			result[i] = ConvertYAMLToJSONCompatible(v)
		}
		return result
	default:
		return v
	}
}
