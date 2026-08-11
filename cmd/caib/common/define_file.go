package caibcommon

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// LoadDefineFiles reads one or more YAML dictionary files and returns
// KEY=VALUE strings with JSON-encoded values, matching AIB's --define-file
// behavior. Later files override earlier ones for the same key.
func LoadDefineFiles(paths []string) ([]string, error) {
	merged := make(map[string]any)

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading define file %q: %w", path, err)
		}

		var fileDefines map[string]any
		if err := yaml.Unmarshal(data, &fileDefines); err != nil {
			return nil, fmt.Errorf("parsing define file %q: %w", path, err)
		}
		if fileDefines == nil {
			continue
		}

		maps.Copy(merged, fileDefines)
	}

	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		encoded, err := json.Marshal(merged[k])
		if err != nil {
			return nil, fmt.Errorf("encoding value for key %q: %w", k, err)
		}
		result = append(result, fmt.Sprintf("%s=%s", k, string(encoded)))
	}

	return result, nil
}
