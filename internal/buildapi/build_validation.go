package buildapi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

// digestPinnedRef matches an OCI reference with a sha256 digest: image@sha256:<64 hex chars>
var digestPinnedRef = regexp.MustCompile(`^.+@sha256:[a-fA-F0-9]{64}$`)

func validateBuildRequest(req *BuildRequest) error {
	if err := validateBuildName(req.Name); err != nil {
		return err
	}
	req.Name = sanitizeBuildNameForValidation(req.Name)

	if len(req.Manifest) > maxManifestSize {
		return fmt.Errorf("manifest too large: %d bytes exceeds %d byte limit (ConfigMap/etcd constraint)",
			len(req.Manifest), maxManifestSize)
	}

	if req.Mode == ModeDisk {
		if req.ContainerRef == "" {
			return fmt.Errorf("container-ref is required for disk mode")
		}
		if err := validateContainerRef(req.ContainerRef); err != nil {
			return err
		}
	} else if req.Manifest == "" {
		return fmt.Errorf("manifest is required")
	}

	for field, value := range map[string]string{"container-push": req.ContainerPush, "export-oci": req.ExportOCI} {
		if err := validateContainerRef(value); err != nil {
			return fmt.Errorf("invalid %s: %v", field, err)
		}
	}

	if req.Reproducible && !req.SecureBuild {
		return fmt.Errorf("reproducible builds require secureBuild to be true")
	}

	return nil
}

// resolveAndClampTTL validates the requested TTL and enforces MaxBuildTTL if configured.
func resolveAndClampTTL(ctx context.Context, k8sClient client.Client, namespace, requestedTTL string) (string, error) {
	if requestedTTL == "" {
		return requestedTTL, nil
	}
	if requestedTTL != "0" {
		dur, err := time.ParseDuration(requestedTTL)
		if err != nil {
			return "", fmt.Errorf("invalid TTL %q: %w", requestedTTL, err)
		}
		if dur < 0 {
			return "", fmt.Errorf("TTL must not be negative")
		}
	}
	operatorCfg, cfgErr := loadOperatorConfigFn(ctx, k8sClient, namespace)
	if cfgErr != nil && !k8serrors.IsNotFound(cfgErr) {
		return "", fmt.Errorf("failed to load OperatorConfig: %w", cfgErr)
	}
	if operatorCfg != nil && operatorCfg.Spec.OSBuilds != nil {
		if maxStr := operatorCfg.Spec.OSBuilds.GetMaxBuildTTL(); maxStr != "" && maxStr != "0" {
			maxDur, parseErr := time.ParseDuration(maxStr)
			if parseErr != nil {
				return "", fmt.Errorf("invalid MaxBuildTTL %q in OperatorConfig: %w", maxStr, parseErr)
			}
			if maxDur <= 0 {
				return "", fmt.Errorf("MaxBuildTTL must be positive, got %q", maxStr)
			}
			if requestedTTL == "0" {
				return "", fmt.Errorf("no-expiry (TTL \"0\") is not allowed when MaxBuildTTL is set (%s)", maxStr)
			}
			dur, _ := time.ParseDuration(requestedTTL)
			if dur > maxDur {
				return "", fmt.Errorf("requested TTL %q exceeds maximum %q", requestedTTL, maxStr)
			}
		}
	}
	return requestedTTL, nil
}

// applyBuildDefaults sets default values for build request fields
func applyBuildDefaults(req *BuildRequest) error {
	if req.Distro == "" {
		req.Distro = "autosd"
	}
	if req.Target == "" {
		req.Target = "qemu"
	}
	if req.Architecture == "" {
		req.Architecture = "arm64"
	}
	req.Architecture = req.Architecture.Normalize()
	if req.ExportFormat == "" {
		req.ExportFormat = formatImage
	}
	if req.Mode == "" {
		req.Mode = ModeBootc
	}
	if strings.TrimSpace(string(req.Compression)) == "" {
		req.Compression = CompressionGzip
	}
	if !req.Compression.IsValid() {
		return fmt.Errorf("invalid compression %q: must be lz4, gzip, or xz", req.Compression)
	}
	if !req.Distro.IsValid() {
		return fmt.Errorf("distro cannot be empty")
	}
	if !req.Target.IsValid() {
		return fmt.Errorf("target cannot be empty")
	}
	if !req.Architecture.IsValid() {
		return fmt.Errorf("invalid architecture %q: must be amd64, arm64, x86_64, or aarch64", req.Architecture)
	}
	// ExportFormat validation removed - allow AIB to handle format validation
	if !req.Mode.IsValid() {
		return fmt.Errorf("mode cannot be empty")
	}
	if req.AutomotiveImageBuilder == "" {
		req.AutomotiveImageBuilder = automotivev1alpha1.DefaultAutomotiveImageBuilderImage
	}
	if req.ManifestFileName == "" {
		req.ManifestFileName = "manifest.aib.yml"
	}
	return nil
}

func validateRestoreSourcesRef(req *BuildRequest) error {
	if req.RestoreSourcesRef == "" {
		return nil
	}
	ref := strings.TrimSpace(req.RestoreSourcesRef)
	if !digestPinnedRef.MatchString(ref) {
		return fmt.Errorf("restoreSourcesRef must be digest-pinned (image@sha256:<64 hex>), got %q", ref)
	}
	req.RestoreSourcesRef = ref
	return nil
}

// validateTargetDefaults checks that each target's default values are within its own accepted values.
func validateTargetDefaults(targets map[string]TargetDefaults) error {
	if len(targets) == 0 {
		return nil
	}

	var errs []string
	for name, td := range targets {
		checkInList(&errs, name, "architecture", td.Architecture, "acceptedArchitectures", td.AcceptedArchitectures)
		checkInList(&errs, name, "defaultFormat", td.DefaultFormat, "acceptedFormats", td.AcceptedFormats)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func checkInList(errs *[]string, target, field, value, listName string, accepted []string) {
	if value != "" && len(accepted) > 0 && !slices.Contains(accepted, value) {
		*errs = append(*errs, fmt.Sprintf("target %q: %s %q not in %s %v", target, field, value, listName, accepted))
	}
}
