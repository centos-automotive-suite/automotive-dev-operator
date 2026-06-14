package manifestschema

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var minimalSchema = []byte(`
$schema: https://json-schema.org/draft-07/schema
type: object
additionalProperties: false
required:
  - name
properties:
  name:
    type: string
  content:
    type: object
    additionalProperties: false
    properties:
      rpms:
        type: array
        items:
          type: string
`)

func TestCompileSchema(t *testing.T) {
	t.Run("valid schema", func(t *testing.T) {
		schema, err := CompileSchema(minimalSchema)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if schema == nil {
			t.Fatal("expected non-nil schema")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		_, err := CompileSchema([]byte("{{not yaml"))
		if err == nil {
			t.Fatal("expected error for invalid YAML")
		}
	})

	t.Run("invalid JSON Schema", func(t *testing.T) {
		_, err := CompileSchema([]byte(`type: not-a-real-type`))
		if err == nil {
			t.Fatal("expected error for invalid JSON Schema type")
		}
	})
}

func TestConvertYAMLToJSONCompatible(t *testing.T) {
	t.Run("map[any]any to map[string]any", func(t *testing.T) {
		input := map[any]any{"key": "value", 42: "number-key"}
		result := ConvertYAMLToJSONCompatible(input)
		m, ok := result.(map[string]any)
		if !ok {
			t.Fatalf("expected map[string]any, got %T", result)
		}
		if m["key"] != "value" || m["42"] != "number-key" {
			t.Errorf("unexpected result: %v", m)
		}
	})

	t.Run("nested maps", func(t *testing.T) {
		input := map[string]any{"outer": map[any]any{"inner": "value"}}
		result := ConvertYAMLToJSONCompatible(input)
		inner := result.(map[string]any)["outer"].(map[string]any)
		if inner["inner"] != "value" {
			t.Errorf("unexpected nested value: %v", inner)
		}
	})

	t.Run("scalars unchanged", func(t *testing.T) {
		if ConvertYAMLToJSONCompatible("hello") != "hello" {
			t.Error("string changed")
		}
		if ConvertYAMLToJSONCompatible(42) != 42 {
			t.Error("int changed")
		}
		if ConvertYAMLToJSONCompatible(nil) != nil {
			t.Error("nil changed")
		}
	})
}

func TestValidateManifest(t *testing.T) {
	schema, err := CompileSchema(minimalSchema)
	if err != nil {
		t.Fatalf("failed to compile schema: %v", err)
	}

	t.Run("valid manifest", func(t *testing.T) {
		r := ValidateManifest(schema, []byte("name: my-build\n"))
		if !r.Valid {
			t.Errorf("expected valid, got errors: %v", r.Errors)
		}
	})

	t.Run("valid with content", func(t *testing.T) {
		r := ValidateManifest(schema, []byte("name: my-build\ncontent:\n  rpms:\n    - vim\n"))
		if !r.Valid {
			t.Errorf("expected valid, got errors: %v", r.Errors)
		}
	})

	t.Run("missing required name", func(t *testing.T) {
		r := ValidateManifest(schema, []byte("content:\n  rpms: [vim]\n"))
		if r.Valid {
			t.Error("expected invalid for missing name")
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		r := ValidateManifest(schema, []byte("name: test\nunknown_field: nope\n"))
		if r.Valid {
			t.Error("expected invalid for unknown field")
		}
		found := false
		for _, e := range r.Errors {
			if strings.Contains(e, "unknown_field") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected error to mention 'unknown_field', got: %v", r.Errors)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		r := ValidateManifest(schema, []byte("{{broken"))
		if r.Valid {
			t.Error("expected invalid for broken YAML")
		}
		if len(r.Errors) == 0 || r.Errors[0] == "" {
			t.Error("expected error message")
		}
	})
}

func TestValidateWithRealSchema(t *testing.T) {
	schemaPath := os.Getenv("AIB_SCHEMA_PATH")
	if schemaPath == "" {
		candidates := []string{
			"../../../../automotive-image-builder/files/manifest_schema.yml",
			os.ExpandEnv("$HOME/dev/automotive/automotive-image-builder/files/manifest_schema.yml"),
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				schemaPath = p
				break
			}
		}
	}
	if schemaPath == "" {
		t.Skip("AIB schema not available locally (set AIB_SCHEMA_PATH)")
	}

	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Skipf("cannot read schema: %v", err)
	}

	schema, err := CompileSchema(data)
	if err != nil {
		t.Fatalf("CompileSchema failed: %v", err)
	}

	tests := []struct {
		name     string
		manifest string
		valid    bool
	}{
		{"valid minimal", "name: test\n", true},
		{"valid with rpms", "name: test\ncontent:\n  rpms:\n    - vim\n    - curl\n", true},
		{"valid image_size", "name: test\nimage:\n  image_size: \"8 GiB\"\n", true},
		{"valid network static", "name: test\nnetwork:\n  static:\n    ip: \"192.168.1.1\"\n    ip_prefixlen: 24\n    gateway: \"192.168.1.1\"\n    dns: \"8.8.8.8\"\n", true},
		{"valid auth users", "name: test\nauth:\n  users:\n    testuser:\n      uid: 1001\n      groups: [wheel]\n", true},
		{"valid qm", "name: test\nqm:\n  content:\n    rpms: [podman]\n  memory_limit:\n    max: \"512M\"\n", true},
		{"valid kernel", "name: test\nkernel:\n  cmdline: [quiet]\n  loglevel: 3\n", true},
		{"invalid missing name", "content:\n  rpms: [vim]\n", false},
		{"invalid unknown field", "name: test\nbogus: nope\n", false},
		{"invalid image_size format", "name: test\nimage:\n  image_size: \"lots\"\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var manifestData any
			if err := yaml.Unmarshal([]byte(tt.manifest), &manifestData); err != nil {
				t.Fatalf("bad test YAML: %v", err)
			}
			manifestData = ConvertYAMLToJSONCompatible(manifestData)
			err := schema.Validate(manifestData)
			if tt.valid && err != nil {
				t.Errorf("expected valid, got: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected invalid, got valid")
			}
		})
	}
}
