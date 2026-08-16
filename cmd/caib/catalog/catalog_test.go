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

func resetListFlagVars() {
	listArchitecture = ""
	listDistro = ""
	listTarget = ""
	listPhase = ""
	listTags = ""
	listSort = listSortCreated
	listLatest = false
	listAll = false
	listLimit = 20
}

func TestListQueryParams_LatestFlag(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantLatest string
		wantPhase  string
	}{
		{name: "default omits latest so the API keeps its true default", args: nil, wantLatest: ""},
		{name: "explicit --latest sends true", args: []string{"--latest"}, wantLatest: "true"},
		{name: "explicit --latest=false is sent, not dropped", args: []string{"--latest=false"}, wantLatest: "false"},
		{name: "--all disables latest heads", args: []string{"--all"}, wantLatest: "false", wantPhase: "all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetListFlagVars()
			cmd := newListCmd()
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			params, err := listQueryParams(cmd)
			if err != nil {
				t.Fatal(err)
			}
			if got := params.Get("latest"); got != tt.wantLatest {
				t.Errorf("latest=%q, want %q (raw query %q)", got, tt.wantLatest, params.Encode())
			}
			if tt.wantLatest == "" && params.Has("latest") {
				t.Errorf("latest should be omitted, got query %q", params.Encode())
			}
			if tt.wantPhase != "" && params.Get("phase") != tt.wantPhase {
				t.Errorf("phase=%q, want %q", params.Get("phase"), tt.wantPhase)
			}
		})
	}
}

func TestCatalogAgeTimestamp(t *testing.T) {
	if got := catalogAgeTimestamp("created", "published"); got != "published" {
		t.Errorf("catalogAgeTimestamp() = %q, want published", got)
	}
	if got := catalogAgeTimestamp("created", ""); got != "created" {
		t.Errorf("catalogAgeTimestamp() = %q, want created", got)
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
