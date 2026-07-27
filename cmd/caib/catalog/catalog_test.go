package catalog

import (
	"testing"
	"time"

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

func TestFormatAge(t *testing.T) {
	tests := []struct {
		name   string
		offset time.Duration
		want   string
	}{
		{"seconds ago", 30 * time.Second, "30s"},
		{"minutes ago", 5 * time.Minute, "5m"},
		{"hours ago", 3 * time.Hour, "3h"},
		{"days ago", 2 * 24 * time.Hour, "2d"},
		{"months ago", 60 * 24 * time.Hour, "2mo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := time.Now().Add(-tt.offset).Format(time.RFC3339)
			got := formatAge(ts)
			if got != tt.want {
				t.Errorf("formatAge(%q) = %q, want %q", ts, got, tt.want)
			}
		})
	}
}

func TestFormatAge_InvalidTimestamp(t *testing.T) {
	got := formatAge("not-a-timestamp")
	if got != "not-a-timestamp" {
		t.Errorf("expected raw string passthrough, got %q", got)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{1536 * 1024, "1.5 MiB"},
		{2 * 1024 * 1024 * 1024, "2.0 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
