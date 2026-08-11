package caibcommon

import (
	"encoding/json"
	"testing"
)

func TestResolveOutputFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   *string
		want    string
		wantErr bool
	}{
		{"nil defaults to table", nil, OutputFormatTable, false},
		{"empty defaults to table", new(""), OutputFormatTable, false},
		{"table", new("table"), OutputFormatTable, false},
		{"json", new("json"), "json", false},
		{"JSON uppercase", new("JSON"), "json", false},
		{"yaml", new("yaml"), "yaml", false},
		{"yml", new("yml"), "yml", false},
		{"invalid format", new("csv"), "", true},
		{"whitespace trimmed", new("  json  "), "json", false},
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
		{"table is not structured", new("table"), false},
		{"json is structured", new("json"), true},
		{"yaml is structured", new("yaml"), true},
		{"yml is structured", new("yml"), true},
		{"invalid falls back to false", new("csv"), false},
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
