package buildapi

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"sigs.k8s.io/yaml"
)

func TestOpenAPIContract(t *testing.T) {
	documented, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(documented, embeddedOpenAPI) {
		t.Fatal("OpenAPI drift: run make generate-openapi")
	}
	var document map[string]any
	if err := yaml.Unmarshal(embeddedOpenAPI, &document); err != nil {
		t.Fatal(err)
	}
	schemas := document["components"].(map[string]any)["schemas"].(map[string]any)
	for name, typ := range map[string]reflect.Type{
		"BuildRequest": reflect.TypeFor[BuildRequest](), "BuildResponse": reflect.TypeFor[BuildResponse](), "BuildListItem": reflect.TypeFor[BuildListItem](),
		"FlashRequest": reflect.TypeFor[FlashRequest](), "FlashResponse": reflect.TypeFor[FlashResponse](), "FlashListItem": reflect.TypeFor[FlashListItem](),
		"BuildCallback": reflect.TypeFor[BuildCallback](), "ArtifactStatus": reflect.TypeFor[ArtifactStatus](),
		"FlashOutcomeStatus": reflect.TypeFor[FlashOutcomeStatus](), "NotificationStatus": reflect.TypeFor[NotificationStatus](),
		"TerminalEvent": reflect.TypeFor[notifications.TerminalEvent](), "BuildTerminalEvent": reflect.TypeFor[notifications.BuildEvent](), "FlashTerminalEvent": reflect.TypeFor[notifications.FlashEvent](),
	} {
		t.Run(name, func(t *testing.T) {
			props := schemas[name].(map[string]any)["properties"].(map[string]any)
			fields := contractJSONFields(typ)
			if len(props) != len(fields) {
				t.Errorf("OpenAPI has %d fields, Go has %d", len(props), len(fields))
			}
			for _, field := range fields {
				if _, ok := props[field]; !ok {
					t.Errorf("undocumented JSON field: %s", field)
				}
			}
		})
	}
	for _, name := range []string{"BuildCallback"} {
		if schemas[name].(map[string]any)["writeOnly"] != true {
			t.Errorf("%s must be write-only", name)
		}
	}
	// OpenAPI 3.0 nullable maps to the JSON Schema null type for fixture validation.
	var normalize func(any)
	normalize = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			if node["nullable"] == true {
				node["type"] = []any{node["type"], "null"}
				delete(node, "nullable")
			}
			for _, value := range node {
				normalize(value)
			}
		case []any:
			for _, value := range node {
				normalize(value)
			}
		}
	}
	normalize(document)
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("https://caib.example/openapi.json", document); err != nil {
		t.Fatal(err)
	}
	for name := range schemas {
		if _, err := compiler.Compile("https://caib.example/openapi.json#/components/schemas/" + name); err != nil {
			t.Fatalf("schema %s: %v", name, err)
		}
	}
}

func contractJSONFields(typ reflect.Type) []string {
	var fields []string
	for field := range typ.Fields() {
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if field.Anonymous {
			fields = append(fields, contractJSONFields(field.Type)...)
		} else if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	return fields
}
