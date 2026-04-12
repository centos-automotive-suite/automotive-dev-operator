package catalog

import (
	"testing"

	"github.com/spf13/cobra"
)

const (
	testFormatTable = "table"
	testFormatJSON  = "json"
	testFormatYAML  = "yaml"
)

func TestGetOutputFormat_ReadsFromRoot(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("output-format", "table", "output format")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	// Default
	if got := getOutputFormat(child); got != testFormatTable {
		t.Errorf("expected default %q, got %q", testFormatTable, got)
	}

	// Set to json
	if err := root.PersistentFlags().Set("output-format", testFormatJSON); err != nil {
		t.Fatal(err)
	}
	if got := getOutputFormat(child); got != testFormatJSON {
		t.Errorf("expected %q, got %q", testFormatJSON, got)
	}

	// Set to yaml
	if err := root.PersistentFlags().Set("output-format", testFormatYAML); err != nil {
		t.Fatal(err)
	}
	if got := getOutputFormat(child); got != testFormatYAML {
		t.Errorf("expected %q, got %q", testFormatYAML, got)
	}
}

func TestGetOutputFormat_FallbackWithoutFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "standalone"}
	if got := getOutputFormat(cmd); got != testFormatTable {
		t.Errorf("expected fallback %q, got %q", testFormatTable, got)
	}
}
