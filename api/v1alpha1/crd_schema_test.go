package v1alpha1

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// CRDSchema represents the structure of a CRD YAML file
type CRDSchema struct {
	Spec struct {
		Names struct {
			Kind string `yaml:"kind"`
		} `yaml:"names"`
		Versions []struct {
			Name   string `yaml:"name"`
			Schema struct {
				OpenAPIV3Schema struct {
					Properties struct {
						Status struct {
							Properties map[string]any `yaml:"properties"`
						} `yaml:"status"`
						Spec struct {
							Properties map[string]any `yaml:"properties"`
						} `yaml:"spec"`
					} `yaml:"properties"`
				} `yaml:"openAPIV3Schema"`
			} `yaml:"schema"`
		} `yaml:"versions"`
	} `yaml:"spec"`
}

const aibAggregateSizeRule = "(has(self.manifest) ? bytes(self.manifest).size() : 0) + (has(self.lockfile) ? bytes(self.lockfile).size() : 0) <= 921600"

// getJSONFieldNames extracts JSON field names from a struct type using reflection
func getJSONFieldNames(t reflect.Type) []string {
	var fields []string
	for field := range t.Fields() {
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		// Extract the field name from the tag (before any comma)
		jsonName, _, _ := strings.Cut(jsonTag, ",")
		if jsonName != "" {
			fields = append(fields, jsonName)
		}
	}
	sort.Strings(fields)
	return fields
}

// getCRDPath returns the path to the CRD bases directory
func getCRDPath() string {
	_, filename, _, _ := runtime.Caller(0)
	// api/v1alpha1/crd_schema_test.go -> config/crd/bases/
	return filepath.Join(filepath.Dir(filename), "..", "..", "config", "crd", "bases")
}

// TestCRDSchemaMatchesGoTypes validates that CRD schemas match Go type definitions.
// This catches issues where Go types are updated but CRD manifests are not regenerated
// or deployed, which can cause silent failures in Kubernetes controllers.
func TestCRDSchemaMatchesGoTypes(t *testing.T) {
	crdPath := getCRDPath()

	tests := []struct {
		name       string
		crdFile    string
		statusType reflect.Type
		specType   reflect.Type
	}{
		{
			name:       "ImageBuild",
			crdFile:    "automotive.sdv.cloud.redhat.com_imagebuilds.yaml",
			statusType: reflect.TypeFor[ImageBuildStatus](),
			specType:   reflect.TypeFor[ImageBuildSpec](),
		},
		{
			name:       "Image",
			crdFile:    "automotive.sdv.cloud.redhat.com_images.yaml",
			statusType: reflect.TypeFor[ImageStatus](),
			specType:   reflect.TypeFor[ImageSpec](),
		},
		{
			name:       "OperatorConfig",
			crdFile:    "automotive.sdv.cloud.redhat.com_operatorconfigs.yaml",
			statusType: reflect.TypeFor[OperatorConfigStatus](),
			specType:   reflect.TypeFor[OperatorConfigSpec](),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crdFilePath := filepath.Join(crdPath, tt.crdFile)

			// Read and parse CRD file
			data, err := os.ReadFile(crdFilePath)
			if err != nil {
				t.Fatalf("Failed to read CRD file %s: %v", tt.crdFile, err)
			}

			var crd CRDSchema
			if err := yaml.Unmarshal(data, &crd); err != nil {
				t.Fatalf("Failed to parse CRD file %s: %v", tt.crdFile, err)
			}

			if len(crd.Spec.Versions) == 0 {
				t.Fatalf("CRD %s has no versions defined", tt.crdFile)
			}

			// Get fields from CRD schema (first version)
			crdStatusFields := make([]string, 0)
			for field := range crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Status.Properties {
				crdStatusFields = append(crdStatusFields, field)
			}
			sort.Strings(crdStatusFields)

			// Get fields from Go types
			goStatusFields := getJSONFieldNames(tt.statusType)

			// Compare status fields
			t.Run("Status", func(t *testing.T) {
				compareFields(t, tt.name+"Status", goStatusFields, crdStatusFields)
			})

			// Get and compare spec fields
			crdSpecFields := make([]string, 0)
			for field := range crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Properties {
				crdSpecFields = append(crdSpecFields, field)
			}
			sort.Strings(crdSpecFields)

			goSpecFields := getJSONFieldNames(tt.specType)

			t.Run("Spec", func(t *testing.T) {
				compareFields(t, tt.name+"Spec", goSpecFields, crdSpecFields)
			})
		})
	}
}

func TestAIBAggregateSizeValidation(t *testing.T) {
	tests := []struct {
		name    string
		crdFile string
		path    []string
	}{
		{
			name:    "ImageBuild",
			crdFile: "automotive.sdv.cloud.redhat.com_imagebuilds.yaml",
			path:    []string{"spec", "aib"},
		},
		{
			name:    "ScheduledImageBuild",
			crdFile: "automotive.sdv.cloud.redhat.com_scheduledimagebuilds.yaml",
			path:    []string{"spec", "imageBuildTemplate", "spec", "aib"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(getCRDPath(), tt.crdFile))
			if err != nil {
				t.Fatal(err)
			}

			var crd map[string]any
			if err := yaml.Unmarshal(data, &crd); err != nil {
				t.Fatal(err)
			}

			schema := crd["spec"].(map[string]any)["versions"].([]any)[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
			for _, field := range tt.path {
				schema = schema["properties"].(map[string]any)[field].(map[string]any)
			}

			validations := schema["x-kubernetes-validations"].([]any)
			for _, validation := range validations {
				if validation.(map[string]any)["rule"] == aibAggregateSizeRule {
					return
				}
			}
			t.Fatalf("aggregate AIB size validation missing from %s", tt.crdFile)
		})
	}
}

func TestWorkspaceRunRetentionSchemaBounds(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(getCRDPath(), "automotive.sdv.cloud.redhat.com_operatorconfigs.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crd CRDSchema
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	workspaces := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Properties["workspaces"].(map[string]any)
	properties := workspaces["properties"].(map[string]any)
	for _, tc := range []struct {
		field        string
		defaultValue int
		maximum      int
	}{
		{"runRetentionDays", 7, 30},
		{"runMaxRecords", 1000, 1000},
	} {
		field, ok := properties[tc.field].(map[string]any)
		if !ok || field["default"] != tc.defaultValue || field["minimum"] != 1 || field["maximum"] != tc.maximum {
			t.Errorf("%s schema lacks bounded retention: %+v", tc.field, field)
		}
	}
}

func compareFields(t *testing.T, typeName string, goFields, crdFields []string) {
	t.Helper()

	// Find fields in Go types but not in CRD
	missingInCRD := difference(goFields, crdFields)
	if len(missingInCRD) > 0 {
		t.Errorf("%s: Fields in Go types but MISSING in CRD schema: %v\n"+
			"This usually means you need to run 'make manifests' to regenerate CRDs",
			typeName, missingInCRD)
	}

	// Find fields in CRD but not in Go types
	extraInCRD := difference(crdFields, goFields)
	if len(extraInCRD) > 0 {
		t.Errorf("%s: Fields in CRD schema but MISSING in Go types: %v\n"+
			"This might indicate stale CRD or removed Go fields",
			typeName, extraInCRD)
	}

	if len(missingInCRD) == 0 && len(extraInCRD) == 0 {
		t.Logf("%s: All %d fields match between Go types and CRD schema", typeName, len(goFields))
	}
}

// difference returns elements in a that are not in b
func difference(a, b []string) []string {
	bSet := make(map[string]bool)
	for _, item := range b {
		bSet[item] = true
	}

	var diff []string
	for _, item := range a {
		if !bSet[item] {
			diff = append(diff, item)
		}
	}
	return diff
}
