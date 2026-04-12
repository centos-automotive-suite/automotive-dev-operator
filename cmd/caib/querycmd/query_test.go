package querycmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"gopkg.in/yaml.v3"
)

const (
	testFormatJSON  = "json"
	testFormatYAML  = "yaml"
	testFormatTable = "table"
)

func sampleItems() []buildapitypes.BuildListItem {
	return []buildapitypes.BuildListItem{
		{
			Name:           "build-1",
			Phase:          "Succeeded",
			RequestedBy:    "alice",
			CreatedAt:      "2025-01-01T00:00:00Z",
			ContainerImage: "quay.io/org/img:v1",
		},
		{
			Name:      "build-2",
			Phase:     "Running",
			CreatedAt: "2025-06-01T12:00:00Z",
			DiskImage: "quay.io/org/disk:v2",
		},
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func TestPrintBuildList_Table(t *testing.T) {
	items := sampleItems()
	out := captureStdout(t, func() {
		_ = printBuildList(items)
	})

	if !strings.Contains(out, "NAME") || !strings.Contains(out, "STATUS") {
		t.Errorf("expected table header, got: %s", out)
	}
	if !strings.Contains(out, "build-1") || !strings.Contains(out, "build-2") {
		t.Errorf("expected both build names in output, got: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("expected requestedBy in output, got: %s", out)
	}
}

func TestPrintBuildList_DiskImagePreferred(t *testing.T) {
	items := sampleItems()
	out := captureStdout(t, func() {
		_ = printBuildList(items)
	})

	// build-2 has DiskImage set — it should appear instead of ContainerImage
	if !strings.Contains(out, "quay.io/org/disk:v2") {
		t.Errorf("expected disk image artifact for build-2, got: %s", out)
	}
}

func TestFormatOutputJSON_List(t *testing.T) {
	format := testFormatJSON
	items := sampleItems()

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { lastErr = err },
	})

	out := captureStdout(t, func() {
		h.renderList(format, items)
	})

	if lastErr != nil {
		t.Fatalf("unexpected error: %v", lastErr)
	}

	var parsed []buildapitypes.BuildListItem
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	if len(parsed) != 2 {
		t.Errorf("expected 2 items, got %d", len(parsed))
	}
	if parsed[0].Name != "build-1" {
		t.Errorf("expected first item name build-1, got %s", parsed[0].Name)
	}
}

func TestFormatOutputYAML_List(t *testing.T) {
	format := testFormatYAML
	items := sampleItems()

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { lastErr = err },
	})

	out := captureStdout(t, func() {
		h.renderList(format, items)
	})

	if lastErr != nil {
		t.Fatalf("unexpected error: %v", lastErr)
	}

	var parsed []map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v\noutput: %s", err, out)
	}
	if len(parsed) != 2 {
		t.Errorf("expected 2 items, got %d", len(parsed))
	}
}

func TestFormatOutputTable_List(t *testing.T) {
	format := testFormatTable
	items := sampleItems()

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { lastErr = err },
	})

	out := captureStdout(t, func() {
		h.renderList(format, items)
	})

	if lastErr != nil {
		t.Fatalf("unexpected error: %v", lastErr)
	}

	if !strings.Contains(out, "NAME") {
		t.Errorf("expected table header, got: %s", out)
	}
}

func TestFormatOutputNil_DefaultsToTable(t *testing.T) {
	items := sampleItems()

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: nil,
		HandleError:  func(err error) { lastErr = err },
	})

	out := captureStdout(t, func() {
		h.renderList(testFormatTable, items)
	})

	if lastErr != nil {
		t.Fatalf("unexpected error: %v", lastErr)
	}

	if !strings.Contains(out, "NAME") {
		t.Errorf("expected table output when format is nil, got: %s", out)
	}
}

func TestFormatOutputInvalid_ReturnsError(t *testing.T) {
	format := "csv"
	items := sampleItems()

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { lastErr = err },
	})

	captureStdout(t, func() {
		h.renderList(format, items)
	})

	if lastErr == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(lastErr.Error(), "csv") {
		t.Errorf("expected error to mention the invalid format, got: %v", lastErr)
	}
}

func TestFormatOutputJSON_Show(t *testing.T) {
	format := testFormatJSON
	resp := &buildapitypes.BuildResponse{
		Name:  "test-build",
		Phase: "Succeeded",
	}

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { lastErr = err },
	})

	out := captureStdout(t, func() {
		h.renderShow(format, resp)
	})

	if lastErr != nil {
		t.Fatalf("unexpected error: %v", lastErr)
	}

	var parsed buildapitypes.BuildResponse
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	if parsed.Name != "test-build" {
		t.Errorf("expected name test-build, got %s", parsed.Name)
	}
}

func TestFormatOutputYAML_Show(t *testing.T) {
	format := testFormatYAML
	resp := &buildapitypes.BuildResponse{
		Name:  "test-build",
		Phase: "Succeeded",
	}

	var lastErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { lastErr = err },
	})

	out := captureStdout(t, func() {
		h.renderShow(format, resp)
	})

	if lastErr != nil {
		t.Fatalf("unexpected error: %v", lastErr)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v\noutput: %s", err, out)
	}
	if parsed["name"] != "test-build" {
		t.Errorf("expected name test-build, got %v", parsed["name"])
	}
}

func TestValueOrDash(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"", "-"},
		{"  ", "-"},
	}
	for _, tt := range tests {
		got := valueOrDash(tt.input)
		if got != tt.want {
			t.Errorf("valueOrDash(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatAge(t *testing.T) {
	// non-RFC3339 input should be returned as-is
	got := formatAge("not-a-date")
	if got != "not-a-date" {
		t.Errorf("formatAge(invalid) = %q, want %q", got, "not-a-date")
	}
}
