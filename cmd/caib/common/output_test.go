package caibcommon

import (
	"encoding/json"
	"testing"
)

func ptr(s string) *string { return &s }

func TestResolveOutputFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   *string
		want    string
		wantErr bool
	}{
		{"nil defaults to table", nil, OutputFormatTable, false},
		{"empty defaults to table", ptr(""), OutputFormatTable, false},
		{"table", ptr("table"), OutputFormatTable, false},
		{"json", ptr("json"), "json", false},
		{"JSON uppercase", ptr("JSON"), "json", false},
		{"yaml", ptr("yaml"), "yaml", false},
		{"yml", ptr("yml"), "yml", false},
		{"invalid format", ptr("csv"), "", true},
		{"whitespace trimmed", ptr("  json  "), "json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveOutputFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveOutputFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ResolveOutputFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsStructuredFormat(t *testing.T) {
	tests := []struct {
		name  string
		input *string
		want  bool
	}{
		{"nil is not structured", nil, false},
		{"table is not structured", ptr("table"), false},
		{"json is structured", ptr("json"), true},
		{"yaml is structured", ptr("yaml"), true},
		{"yml is structured", ptr("yml"), true},
		{"invalid falls back to false", ptr("csv"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStructuredFormat(tt.input); got != tt.want {
				t.Errorf("IsStructuredFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRenderFormattedJSON(t *testing.T) {
	type testData struct {
		Name  string `json:"name"`
		Value string `json:"value,omitempty"`
	}

	var gotErr error
	handleErr := func(err error) { gotErr = err }

	t.Run("json renders valid JSON", func(t *testing.T) {
		gotErr = nil
		data := testData{Name: "test", Value: "val"}

		// RenderFormatted writes to stdout; just verify no error
		RenderFormatted("json", data, nil, handleErr)
		if gotErr != nil {
			t.Fatalf("unexpected error: %v", gotErr)
		}
	})

	t.Run("json omitempty works", func(t *testing.T) {
		data := testData{Name: "test"}
		out, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip map[string]any
		if err := json.Unmarshal(out, &roundtrip); err != nil {
			t.Fatal(err)
		}
		if _, ok := roundtrip["value"]; ok {
			t.Error("expected omitempty to exclude empty value field")
		}
	})

	t.Run("invalid format calls handleError", func(t *testing.T) {
		gotErr = nil
		RenderFormatted("csv", nil, nil, handleErr)
		if gotErr == nil {
			t.Error("expected error for invalid format")
		}
	})
}
