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

// FindLocalFileReferences extracts manifest add_files source_path and
// source_glob references. Glob patterns are expanded locally and each
// matched file is returned as a separate source_path entry.
// manifestDir is the directory containing the manifest, used to resolve
// relative glob patterns.
func FindLocalFileReferences(manifestContent string, manifestDir string) ([]map[string]string, error) {
	return findLocalFileReferences(manifestContent, manifestDir, false)
}

// FindLocalFileReferencesForWorkspaceBuild is like FindLocalFileReferences but
// skips source_path/source_glob under /workspace (those live on the cluster
// workspace PVC, not the local machine).
func FindLocalFileReferencesForWorkspaceBuild(manifestContent string, manifestDir string) ([]map[string]string, error) {
	return findLocalFileReferences(manifestContent, manifestDir, true)
}

func findLocalFileReferences(manifestContent string, manifestDir string, excludeClusterWorkspace bool) ([]map[string]string, error) {
	var manifestData map[string]any
	var localFiles []map[string]string

	if err := yaml.Unmarshal([]byte(manifestContent), &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse manifest YAML: %w", err)
	}

	isPathSafe := func(path string) error {
		if path == "" || path == "/" {
			return fmt.Errorf("empty or root path is not allowed")
		}

		if filepath.IsAbs(path) {
			safeDirectories := configuredSafeDirectories()
			if len(safeDirectories) > 0 {
				cleanedPath := filepath.Clean(path)
				isInSafeDir := false
				for _, dir := range safeDirectories {
					if dir == "" {
						continue
					}
					cleanedDir := filepath.Clean(dir)
					if cleanedPath == cleanedDir ||
						strings.HasPrefix(cleanedPath, cleanedDir+string(os.PathSeparator)) {
						isInSafeDir = true
						break
					}
				}
				if !isInSafeDir {
					return fmt.Errorf(
						"absolute path outside configured safe directories: %s (set CAIB_SAFE_DIRECTORIES)",
						path,
					)
				}
			}
		}
		return nil
	}

	if content, ok := manifestData["content"].(map[string]any); ok {
		if addFiles, ok := content["add_files"].([]any); ok {
			if err := collectAddFileRefs(addFiles, manifestDir, excludeClusterWorkspace, isPathSafe, &localFiles); err != nil {
				return nil, err
			}
		}
	}
	if qm, ok := manifestData["qm"].(map[string]any); ok {
		if qmContent, ok := qm["content"].(map[string]any); ok {
			if addFiles, ok := qmContent["add_files"].([]any); ok {
				if err := collectAddFileRefs(addFiles, manifestDir, excludeClusterWorkspace, isPathSafe, &localFiles); err != nil {
					return nil, err
				}
			}
		}
	}

	return localFiles, nil
}

func collectAddFileRefs(
	addFiles []any,
	manifestDir string,
	excludeClusterWorkspace bool,
	isPathSafe func(string) error,
	localFiles *[]map[string]string,
) error {
	for _, file := range addFiles {
		fileMap, ok := file.(map[string]any)
		if !ok {
			continue
		}

		if sourceGlob, hasGlob := fileMap["source_glob"].(string); hasGlob {
			if excludeClusterWorkspace && isClusterWorkspacePath(sourceGlob) {
				continue
			}
			matches, err := expandSourceGlob(sourceGlob, manifestDir)
			if err != nil {
				return err
			}
			for _, m := range matches {
				if err := isPathSafe(m); err != nil {
					return err
				}
				*localFiles = append(*localFiles, map[string]string{
					"source_path": m,
				})
			}
			continue
		}

		path, hasPath := fileMap["path"].(string)
		sourcePath, hasSourcePath := fileMap["source_path"].(string)
		if hasPath && hasSourcePath {
			if excludeClusterWorkspace && isClusterWorkspacePath(sourcePath) {
				continue
			}
			if err := isPathSafe(sourcePath); err != nil {
				return err
			}
			*localFiles = append(*localFiles, map[string]string{
				"path":        path,
				"source_path": sourcePath,
			})
		}
	}
	return nil
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

func configuredSafeDirectories() []string {
	raw := strings.TrimSpace(os.Getenv("CAIB_SAFE_DIRECTORIES"))
	if raw == "" {
		// Default policy: allow absolute paths when no safe directories are configured.
		return nil
	}

	parts := strings.Split(raw, string(os.PathListSeparator))
	dirs := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		dirs = append(dirs, filepath.Clean(part))
	}
	return dirs
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
