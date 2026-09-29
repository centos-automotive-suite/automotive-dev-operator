package buildcmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	buildcontract "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

const defaultResolveTimeoutMinutes = 30

func resolveArchitecture(architecture string) (string, error) {
	switch architecture {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("invalid --arch %q (expected: amd64 or arm64)", architecture)
	}
}

func defaultLockfilePath(manifestPath string) string {
	return strings.TrimSuffix(manifestPath, filepath.Ext(manifestPath)) + ".lock"
}

func resolveTimeoutMinutes(cmd *cobra.Command, configured int) int {
	if cmd.Flags().Changed("timeout") {
		return configured
	}
	return defaultResolveTimeoutMinutes
}

func (h *Handler) resolveOperationBuildName(manifestPath string) error {
	explicitName := h.opts.Build.Name != ""
	if err := h.resolveManifestBuildName(manifestPath); err != nil {
		return err
	}
	if !explicitName {
		h.opts.Build.Name += "-resolve"
	}
	return common.ValidateBuildName(h.opts.Build.Name)
}

// RunResolve submits dependency resolution to the cluster and downloads its lockfile.
func (h *Handler) RunResolve(cmd *cobra.Command, args []string) {
	if err := h.resolveLockfile(cmd.Context(), cmd, args[0]); err != nil {
		h.handleError(err)
	}
}

func (h *Handler) resolveLockfile(ctx context.Context, cmd *cobra.Command, manifestPath string) error {
	if err := common.ValidateManifestSuffix(manifestPath); err != nil {
		return err
	}
	manifestPath, err := filepath.Abs(manifestPath)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	h.resolveTarget(cmd, common.ManifestTarget(manifest))
	if err := h.resolveOperationBuildName(manifestPath); err != nil {
		return err
	}
	architecture, err := resolveArchitecture(h.opts.Build.Architecture)
	if err != nil {
		return err
	}
	definitions, err := h.resolveCustomDefs()
	if err != nil {
		return err
	}
	timeoutMinutes := resolveTimeoutMinutes(cmd, h.opts.Output.Timeout)
	if timeoutMinutes <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMinutes)*time.Minute)
	defer cancel()
	api, err := common.CreateBuildAPIClient(h.opts.Connection.ServerURL, &h.opts.Connection.AuthToken, h.opts.Connection.InsecureSkipTLS)
	if err != nil {
		return err
	}
	req := buildcontract.BuildRequest{
		Name:                   h.opts.Build.Name,
		Manifest:               string(manifest),
		ManifestFileName:       filepath.Base(manifestPath),
		Mode:                   buildcontract.ModePackage,
		ResolveOnly:            true,
		Distro:                 buildcontract.Distro(h.opts.Build.Distro),
		Target:                 buildcontract.Target(h.opts.Build.Target),
		Architecture:           buildcontract.Architecture(architecture),
		AutomotiveImageBuilder: h.opts.Build.AutomotiveImageBuilder,
		CustomDefs:             definitions,
		AIBExtraArgs:           h.opts.Build.AIBExtraArgs,
		UseInternalRegistry:    true,
		TTL:                    h.opts.Build.TTL,
	}
	operatorConfig, err := h.fetchTargetDefaults(ctx, api, string(req.Target), false)
	if err != nil {
		return err
	}
	ApplyTargetDefaults(cmd, operatorConfig, &req)
	refs, cleanup, err := h.prepareManifestUploads(ctx, api, &req, manifestPath)
	if err != nil {
		return fmt.Errorf("prepare manifest uploads: %w", err)
	}
	defer cleanup()
	req.HasLocalFiles = len(refs) > 0
	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		return fmt.Errorf("submit cluster resolution: %w", err)
	}
	clilog.Infof("Resolution %s accepted on the cluster\n", resp.Name)
	h.displayBuildLogsCommand(resp.Name)
	if len(refs) > 0 {
		if err := h.handleFileUploads(ctx, api, resp.Name, refs); err != nil {
			return err
		}
	}
	for {
		reqCtx, reqCancel := context.WithTimeout(ctx, 15*time.Second)
		st, err := api.GetBuild(reqCtx, resp.Name)
		reqCancel()
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("waiting for resolution %s: %w", resp.Name, ctx.Err())
			}
			var statusErr buildapiclient.HTTPError
			if errors.As(err, &statusErr) && statusErr.HTTPStatusCode() < http.StatusInternalServerError && statusErr.HTTPStatusCode() != http.StatusRequestTimeout && statusErr.HTTPStatusCode() != http.StatusTooManyRequests {
				return fmt.Errorf("check resolution %s: %w", resp.Name, err)
			}
			clilog.Warnf("check resolution %s: %v (retrying)\n", resp.Name, err)
		} else {
			switch st.Phase {
			case "Completed":
				if st.LockfileArtifact == "" {
					return fmt.Errorf("resolution %s completed without a lockfile artifact", resp.Name)
				}
				if st.RegistryToken == "" {
					clilog.Warnf("Resolution %s completed; waiting for registry credentials\n", resp.Name)
					break
				}
				outputPath := strings.TrimSpace(h.opts.Output.Dir)
				if outputPath == "" {
					outputPath = defaultLockfilePath(manifestPath)
				}
				return downloadResolvedLockfile(ctx, st.LockfileArtifact, st.RegistryToken, outputPath, h.opts.Connection.InsecureSkipTLS, common.PullOCIArtifactWithContext)
			case "Failed", "Cancelled", "Expired":
				return fmt.Errorf("resolution %s %s: %s", resp.Name, st.Phase, st.Message)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for resolution %s: %w (inspect with caib image show %s)", resp.Name, ctx.Err(), resp.Name)
		case <-time.After(5 * time.Second):
		}
	}
}

func downloadResolvedLockfile(ctx context.Context, ref, token, outputPath string, insecure bool, pull func(context.Context, string, string, string, string, bool, ...string) error) error {
	outputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	// Keep the temporary file on the destination filesystem for atomic replacement.
	dir, err := os.MkdirTemp(filepath.Dir(outputPath), ".caib-resolve-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			clilog.Warnf("failed to remove resolver temporary directory: %v\n", err)
		}
	}()
	tmp := filepath.Join(dir, "aib.lock")
	if err := pull(ctx, ref, tmp, "serviceaccount", token, insecure); err != nil {
		return fmt.Errorf("download resolved lockfile: %w", err)
	}
	info, err := os.Stat(tmp)
	if err != nil {
		return err
	}
	if info.Size() == 0 || info.Size() > automotivev1alpha1.MaxAIBLockfileSize {
		return fmt.Errorf("generated lockfile is empty or exceeds %d bytes", automotivev1alpha1.MaxAIBLockfileSize)
	}
	lockfile, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	if err := automotivev1alpha1.ValidateAIBLockfile(string(lockfile)); err != nil {
		return fmt.Errorf("validate generated lockfile: %w", err)
	}
	if err := os.Rename(tmp, outputPath); err != nil {
		return err
	}
	clilog.Infof("Lockfile written to %s\n", outputPath)
	return nil
}
