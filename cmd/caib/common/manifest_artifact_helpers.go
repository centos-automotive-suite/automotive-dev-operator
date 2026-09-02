package caibcommon

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ManifestTarget extracts the top-level "target" field from a manifest YAML.
// Returns empty string if the field is absent, blank, or the YAML is invalid.
func ManifestTarget(manifest []byte) string {
	var m struct {
		Target string `yaml:"target"`
	}
	if err := yaml.Unmarshal(manifest, &m); err != nil {
		return ""
	}
	return strings.TrimSpace(m.Target)
}

// PrepareLocalFileUploads resolves local add_files sources relative to the
// manifest directory and returns upload references and a manifest with matching
// destinations. Cluster workspace sources are deferred when requested.
func PrepareLocalFileUploads(manifestContent, manifestDir string, excludeClusterWorkspace bool) (string, []map[string]string, error) {
	var manifestData map[string]any
	if err := yaml.Unmarshal([]byte(manifestContent), &manifestData); err != nil {
		return "", nil, fmt.Errorf("failed to parse manifest YAML: %w", err)
	}
	manifestDir, err := filepath.Abs(manifestDir)
	if err != nil {
		return "", nil, fmt.Errorf("resolve manifest directory: %w", err)
	}

	var localFiles []map[string]string
	sources := make(map[string]string)
	addFile := func(source string) error {
		dest := localUploadDestination(source)
		if dest == "" {
			return fmt.Errorf("invalid upload source path: %q", source)
		}
		if !filepath.IsAbs(source) {
			source = filepath.Join(manifestDir, source)
		}
		if previous, ok := sources[dest]; ok {
			if previous != source {
				return fmt.Errorf("local files %q and %q have the same upload destination %q", previous, source, dest)
			}
			return nil
		}
		sources[dest] = source
		localFiles = append(localFiles, map[string]string{"source_path": source, "dest": dest})
		return nil
	}

	content, _ := manifestData["content"].(map[string]any)
	qm, _ := manifestData["qm"].(map[string]any)
	qmContent, _ := qm["content"].(map[string]any)
	changed := false
	for _, section := range []map[string]any{content, qmContent} {
		files, _ := section["add_files"].([]any)
		rewritten, err := collectAddFileRefs(files, manifestDir, excludeClusterWorkspace, addFile)
		if err != nil {
			return "", nil, err
		}
		changed = changed || rewritten
	}
	if !changed {
		return manifestContent, localFiles, nil
	}
	out, err := yaml.Marshal(manifestData)
	if err != nil {
		return "", nil, fmt.Errorf("rewrite manifest for local uploads: %w", err)
	}
	return string(out), localFiles, nil
}

func collectAddFileRefs(addFiles []any, manifestDir string, excludeClusterWorkspace bool, addFile func(string) error) (bool, error) {
	changed := false
	for _, file := range addFiles {
		entry, ok := file.(map[string]any)
		if !ok || entry["text"] != nil || entry["url"] != nil {
			continue
		}
		key := "source_glob"
		source, ok := entry[key].(string)
		if !ok {
			if _, hasPath := entry["path"].(string); !hasPath {
				continue
			}
			key = "source_path"
			source, ok = entry[key].(string)
			if !ok {
				key = "source"
				source, ok = entry[key].(string)
			}
		}
		if !ok || (excludeClusterWorkspace && isClusterWorkspacePath(source)) {
			continue
		}

		matches := []string{source}
		if key == "source_glob" {
			var err error
			matches, err = expandSourceGlob(source, manifestDir)
			if err != nil {
				return false, err
			}
		}
		for _, match := range matches {
			if err := addFile(match); err != nil {
				return false, err
			}
		}
		if source != "" {
			if dest := localUploadDestination(source); dest != source {
				entry[key] = dest
				changed = true
			}
		}
	}
	return changed, nil
}

func localUploadDestination(source string) string {
	// Match the upload API's rooted path cleaning before find_manifest.sh adds
	// /manifest-work/. Cleaning after that prefix would escape the staged files.
	return strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(source)), "/")
}

func isClusterWorkspacePath(p string) bool {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		return false
	}
	cleaned := path.Clean(p)
	return cleaned == "/workspace" || strings.HasPrefix(cleaned, "/workspace/")
}

// expandSourceGlob expands a glob pattern relative to manifestDir and returns
// the matched file paths (relative to manifestDir if the pattern was relative).
// Supports ** for recursive directory matching (e.g. "dir/**/*.yaml").
func expandSourceGlob(pattern string, manifestDir string) ([]string, error) {
	isAbs := filepath.IsAbs(pattern)

	// Resolve the glob pattern relative to the manifest directory
	var fullPattern string
	if isAbs {
		fullPattern = pattern
	} else {
		fullPattern = filepath.Join(manifestDir, pattern)
	}

	// Use recursive walk for ** patterns since filepath.Glob doesn't support **
	var matches []string
	if strings.Contains(fullPattern, "**") {
		var err error
		matches, err = expandDoubleStarGlob(fullPattern)
		if err != nil {
			return nil, fmt.Errorf("error expanding glob %q: %w", pattern, err)
		}
	} else {
		var err error
		matches, err = filepath.Glob(fullPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
		}
		// filepath.Glob can return directories; filter to files only
		matches = filterFiles(matches)
	}

	// Convert matches to the appropriate path form
	var files []string
	for _, m := range matches {
		if isAbs {
			files = append(files, m)
		} else {
			rel, err := filepath.Rel(manifestDir, m)
			if err != nil {
				return nil, fmt.Errorf("error computing relative path for %s: %w", m, err)
			}
			files = append(files, rel)
		}
	}

	return files, nil
}

// filterFiles returns only regular files from a list of paths.
func filterFiles(paths []string) []string {
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, p)
	}
	return files
}

// expandDoubleStarGlob handles glob patterns containing ** by walking the
// directory tree. It splits the pattern at the first ** segment, walks the
// base directory recursively, and matches remaining segments against each path.
// If the prefix before ** contains wildcards, those are expanded first.
func expandDoubleStarGlob(pattern string) ([]string, error) {
	// e.g. "/tmp/dir/files/**/*.yaml" -> basePattern="/tmp/dir/files", tail="*.yaml"
	parts := strings.SplitN(pattern, "**", 2)
	basePattern := strings.TrimRight(parts[0], string(filepath.Separator))
	if basePattern == "" {
		basePattern = "."
	}
	tail := ""
	if len(parts) > 1 {
		tail = strings.TrimPrefix(parts[1], string(filepath.Separator))
	}

	// Expand the base if it contains wildcards (e.g. "images/*/**/*.rpm")
	var bases []string
	if strings.ContainsAny(basePattern, "*?[") {
		expanded, err := filepath.Glob(basePattern)
		if err != nil {
			return nil, fmt.Errorf("invalid base pattern %q: %w", basePattern, err)
		}
		for _, b := range expanded {
			info, statErr := os.Stat(b)
			if statErr == nil && info.IsDir() {
				bases = append(bases, b)
			}
		}
	} else {
		bases = []string{filepath.Clean(basePattern)}
	}

	var matches []string
	for _, base := range bases {
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			if tail == "" {
				matches = append(matches, path)
				return nil
			}

			rel, relErr := filepath.Rel(base, path)
			if relErr != nil {
				return nil
			}

			// Try matching tail against every suffix of the relative path so that
			// patterns like **/deep/nested/*.yaml match a/b/deep/nested/f.yaml.
			segments := strings.Split(rel, string(filepath.Separator))
			for i := range segments {
				suffix := filepath.Join(segments[i:]...)
				if matched, _ := filepath.Match(tail, suffix); matched {
					matches = append(matches, path)
					return nil
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return matches, nil
}

// compressionExtension returns the filename extension for a compression algorithm.
func compressionExtension(algo string) string {
	switch algo {
	case "tar.gz":
		return ".tar.gz"
	case "gzip":
		return ".gz"
	case "xz":
		return ".xz"
	default:
		return ""
	}
}

// hasCompressionExtension checks if filename already has a compression extension.
func hasCompressionExtension(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".gz") ||
		strings.HasSuffix(lower, ".xz")
}

// detectFileCompression examines magic bytes and returns the compression algorithm.
func detectFileCompression(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close file: %v\n", err)
		}
	}()

	header := make([]byte, 10)
	n, err := file.Read(header)
	if err != nil || n < 3 {
		return ""
	}

	if n >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		if isTarInsideGzip(filePath) {
			return "tar.gz"
		}
		return "gzip"
	}
	if n >= 6 && header[0] == 0xfd && header[1] == 0x37 && header[2] == 0x7a &&
		header[3] == 0x58 && header[4] == 0x5a && header[5] == 0x00 {
		return "xz"
	}

	return ""
}

// isTarInsideGzip checks whether a gzip file contains a tar archive.
func isTarInsideGzip(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return false
	}
	defer func() { _ = gzReader.Close() }()

	header := make([]byte, 512)
	n, err := io.ReadFull(gzReader, header)
	if err != nil && n < 262 {
		return false
	}

	return n >= 262 && string(header[257:262]) == "ustar"
}
