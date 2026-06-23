package caibcommon

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// OutputFormatTable is the default table-formatted output mode.
	OutputFormatTable = "table"
	outputFormatJSON  = "json"
	outputFormatYAML  = "yaml"
	outputFormatYML   = "yml"
)

// ResolveOutputFormat normalises and validates a format flag value.
func ResolveOutputFormat(format *string) (string, error) {
	f := OutputFormatTable
	if format != nil && strings.TrimSpace(*format) != "" {
		f = strings.ToLower(strings.TrimSpace(*format))
	}
	switch f {
	case OutputFormatTable, outputFormatJSON, outputFormatYAML, outputFormatYML:
		return f, nil
	default:
		return "", fmt.Errorf("invalid output format %q (supported: table, json, yaml)", f)
	}
}

// IsStructuredFormat returns true for json/yaml output formats.
func IsStructuredFormat(format *string) bool {
	f, err := ResolveOutputFormat(format)
	if err != nil {
		return false
	}
	return f != OutputFormatTable
}

// RenderFormatted outputs data as JSON, YAML, or via the tablePrinter callback.
func RenderFormatted(format string, data any, tablePrinter func() error, handleError func(error)) {
	switch format {
	case outputFormatJSON:
		out, marshalErr := json.MarshalIndent(data, "", "  ")
		if marshalErr != nil {
			handleError(fmt.Errorf("error rendering JSON output: %w", marshalErr))
			return
		}
		fmt.Println(string(out))
	case outputFormatYAML, outputFormatYML:
		out, marshalErr := yaml.Marshal(data)
		if marshalErr != nil {
			handleError(fmt.Errorf("error rendering YAML output: %w", marshalErr))
			return
		}
		fmt.Print(string(out))
	case OutputFormatTable:
		if err := tablePrinter(); err != nil {
			handleError(fmt.Errorf("error writing table output: %w", err))
		}
	default:
		handleError(fmt.Errorf("invalid output format %q (supported: table, json, yaml)", format))
	}
}
