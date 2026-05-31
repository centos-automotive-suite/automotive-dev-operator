package caibcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
)

// PullOCIArtifact pulls and extracts an OCI artifact to local destination.
func PullOCIArtifact(ociRef, destPath, username, password string, insecureSkipTLS bool, authFilePaths ...string) error {
	fmt.Printf("Pulling OCI artifact %s to %s\n", ociRef, destPath)

	destDir := filepath.Dir(destPath)
	if destDir != "" && destDir != "." {
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}

	ctx := context.Background()
	systemCtx := &types.SystemContext{}
	if len(authFilePaths) > 0 && authFilePaths[0] != "" {
		systemCtx.AuthFilePath = authFilePaths[0]
	}
	if username != "" && password != "" {
		fmt.Printf("Using provided username/password credentials\n")
		systemCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: username,
			Password: password,
		}
	} else {
		fmt.Printf("No explicit credentials provided, will use local container auth files if available\n")
	}

	if insecureSkipTLS {
		systemCtx.OCIInsecureSkipTLSVerify = insecureSkipTLS
		systemCtx.DockerInsecureSkipTLSVerify = types.OptionalBoolTrue
	}

	verifySignatures, err := signatureVerificationEnabled()
	if err != nil {
		return err
	}
	var policy *signature.Policy
	if verifySignatures {
		policy, err = signature.DefaultPolicy(systemCtx)
		if err != nil {
			return fmt.Errorf("load default signature policy: %w", err)
		}
	} else {
		policy = &signature.Policy{
			Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()},
		}
	}

	policyCtx, err := signature.NewPolicyContext(policy)
	if err != nil {
		return fmt.Errorf("create policy context: %w", err)
	}

	srcRef, err := docker.ParseReference("//" + ociRef)
	if err != nil {
		return fmt.Errorf("parse source reference: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "oci-pull-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp directory: %v\n", err)
		}
	}()

	destRef, err := layout.ParseReference(tempDir + ":latest")
	if err != nil {
		return fmt.Errorf("parse destination reference: %w", err)
	}

	fmt.Printf("Downloading OCI artifact...")
	_, err = copy.Image(ctx, policyCtx, destRef, srcRef, &copy.Options{
		ReportWriter:   os.Stdout,
		SourceCtx:      systemCtx,
		DestinationCtx: systemCtx,
	})
	if err != nil {
		return fmt.Errorf("copy image: %w", err)
	}

	fmt.Printf("\nExtracting artifact to %s\n", destPath)
	if err := extractOCIArtifactBlob(tempDir, destPath); err != nil {
		return fmt.Errorf("extract artifact: %w", err)
	}

	info, err := os.Stat(destPath)
	if err != nil {
		return fmt.Errorf("stat destination: %w", err)
	}

	if info.IsDir() {
		fmt.Printf("Downloaded multi-layer artifact to %s/\n", destPath)
		return nil
	}

	finalPath := destPath
	compression := detectFileCompression(destPath)
	if compression != "" && !hasCompressionExtension(destPath) {
		ext := compressionExtension(compression)
		if ext != "" {
			newPath := destPath + ext
			fmt.Printf("Adding compression extension: %s -> %s\n", filepath.Base(destPath), filepath.Base(newPath))
			if err := os.Rename(destPath, newPath); err != nil {
				return fmt.Errorf("rename file with compression extension: %w", err)
			}
			finalPath = newPath
		}
	}
	fmt.Printf("Downloaded to %s\n", finalPath)
	return nil
}

func signatureVerificationEnabled() (bool, error) {
	raw := strings.TrimSpace(os.Getenv("SIGNATURE_VERIFY"))
	if raw == "" {
		return false, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid SIGNATURE_VERIFY value %q: %w", raw, err)
	}
	return enabled, nil
}

func extractOCIArtifactBlob(ociLayoutPath, destPath string) error {
	indexPath := filepath.Join(ociLayoutPath, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("read index.json: %w", err)
	}

	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexData, &index); err != nil {
		return fmt.Errorf("parse index.json: %w", err)
	}
	if len(index.Manifests) == 0 {
		return fmt.Errorf("no manifests found in index")
	}

	manifestDigest := strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")
	manifestPath := filepath.Join(ociLayoutPath, "blobs", "sha256", manifestDigest)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var manifest struct {
		Annotations map[string]string `json:"annotations"`
		Layers      []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	if len(manifest.Layers) == 0 {
		return fmt.Errorf("no layers found in manifest")
	}

	annotationMultiLayer := manifest.Annotations[oci.Get().AnnotationKey("multi-layer")] == "true"
	isMultiLayer := annotationMultiLayer || len(manifest.Layers) > 1
	if isMultiLayer {
		if !annotationMultiLayer && len(manifest.Layers) > 1 {
			fmt.Printf("Warning: manifest has %d layers without multi-layer annotation; extracting all layers\n", len(manifest.Layers))
		}
		fmt.Printf("Multi-layer artifact detected (%d layers)\n", len(manifest.Layers))
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("create destination directory: %w", err)
		}

		seenFilenames := make(map[string]struct {
			layerIndex int
			digest     string
			title      string
		})
		for i, layer := range manifest.Layers {
			layerDigest := strings.TrimPrefix(layer.Digest, "sha256:")
			layerPath := filepath.Join(ociLayoutPath, "blobs", "sha256", layerDigest)

			originalTitle := layer.Annotations["org.opencontainers.image.title"]
			filename := sanitizeFilename(originalTitle, i)

			if prev, exists := seenFilenames[filename]; exists {
				return fmt.Errorf(
					"duplicate sanitized filename '%s' for layer %d (digest: %s, title: %s) conflicts with layer %d (digest: %s, title: %s)",
					filename, i, layer.Digest, originalTitle, prev.layerIndex, prev.digest, prev.title)
			}
			seenFilenames[filename] = struct {
				layerIndex int
				digest     string
				title      string
			}{
				layerIndex: i,
				digest:     layer.Digest,
				title:      originalTitle,
			}

			destFile := filepath.Join(destPath, filename)
			fmt.Printf("  Extracting layer %d: %s\n", i+1, filename)
			if err := copyFile(layerPath, destFile); err != nil {
				return fmt.Errorf("extract layer %s: %w", filename, err)
			}
		}

		fmt.Printf("Extracted %d files to %s\n", len(manifest.Layers), destPath)
		return nil
	}

	layerDigest := strings.TrimPrefix(manifest.Layers[0].Digest, "sha256:")
	layerPath := filepath.Join(ociLayoutPath, "blobs", "sha256", layerDigest)
	return copyFile(layerPath, destPath)
}

func sanitizeFilename(filename string, layerIndex int) string {
	fallback := fmt.Sprintf("layer-%d.bin", layerIndex)
	if filename == "" {
		return fallback
	}
	if strings.ContainsRune(filename, 0) {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename contains null bytes, using fallback\n", layerIndex)
		return fallback
	}
	if filepath.IsAbs(filename) {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename is absolute path, using fallback\n", layerIndex)
		return fallback
	}
	if strings.Contains(filename, "..") {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename contains '..', using fallback\n", layerIndex)
		return fallback
	}

	base := filepath.Base(filename)
	if base != filename {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename contains path separators, using basename: %s\n", layerIndex, base)
		filename = base
	}
	if filename == "" || filename == "." || filename == ".." {
		return fallback
	}
	return filename
}

func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close source file: %v\n", err)
		}
	}()

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() {
		if err := dst.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close destination file: %v\n", err)
		}
	}()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	return nil
}
