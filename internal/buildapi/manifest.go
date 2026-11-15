package buildapi

import (
	"log"

	"gopkg.in/yaml.v3"
)

// manifestAddFile represents a single add_files entry from an AIB manifest.
type manifestAddFile struct {
	SourcePath string `yaml:"source_path"`
}

// manifestContent represents the content section of an AIB manifest.
type manifestContent struct {
	AddFiles []manifestAddFile `yaml:"add_files"`
}

// manifestSchema is a minimal schema for parsing add_files from AIB manifests.
type manifestSchema struct {
	Content manifestContent `yaml:"content"`
	QM      struct {
		Content manifestContent `yaml:"content"`
	} `yaml:"qm"`
}

// manifestNeedsUpload parses the manifest YAML and returns true if any
// add_files entry references local files via source_path.
// Note: source_glob is intentionally excluded — only the client can determine
// whether a glob expands to actual files. This fallback exists for backward
// compatibility with older clients that don't send HasLocalFiles.
func manifestNeedsUpload(manifest string) bool {
	var m manifestSchema
	if err := yaml.Unmarshal([]byte(manifest), &m); err != nil {
		log.Printf("warning: failed to parse manifest for upload detection: %v", err)
		return false
	}
	for _, sections := range [][]manifestAddFile{m.Content.AddFiles, m.QM.Content.AddFiles} {
		for _, f := range sections {
			if f.SourcePath != "" {
				return true
			}
		}
	}
	return false
}
