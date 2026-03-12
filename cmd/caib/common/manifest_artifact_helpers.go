package caibcommon

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FindLocalFileReferences extracts manifest add_files source_path references.
func FindLocalFileReferences(manifestContent string) ([]map[string]string, error) {
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

	processAddFiles := func(addFiles []any) error {
		for _, file := range addFiles {
			if fileMap, ok := file.(map[string]any); ok {
				path, hasPath := fileMap["path"].(string)
				sourcePath, hasSourcePath := fileMap["source_path"].(string)
				if hasPath && hasSourcePath {
					if err := isPathSafe(sourcePath); err != nil {
						return err
					}
					localFiles = append(localFiles, map[string]string{
						"path":        path,
						"source_path": sourcePath,
					})
				}
			}
		}
		return nil
	}

	if content, ok := manifestData["content"].(map[string]any); ok {
		if addFiles, ok := content["add_files"].([]any); ok {
			if err := processAddFiles(addFiles); err != nil {
				return nil, err
			}
		}
	}
	if qm, ok := manifestData["qm"].(map[string]any); ok {
		if qmContent, ok := qm["content"].(map[string]any); ok {
			if addFiles, ok := qmContent["add_files"].([]any); ok {
				if err := processAddFiles(addFiles); err != nil {
					return nil, err
				}
			}
		}
	}

	return localFiles, nil
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
	case "lz4":
		return ".lz4"
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
		strings.HasSuffix(lower, ".lz4") ||
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
	if n >= 4 && header[0] == 0x04 && header[1] == 0x22 && header[2] == 0x4d && header[3] == 0x18 {
		return "lz4"
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
