// Package buildcmd provides handlers for image build workflows.
package buildcmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
	phaseFlashing  = "Flashing"
	phasePending   = "Pending"
	phaseRunning   = "Running"
	phaseUploading = "Uploading"

	errPrefixBuild = "build"
	errPrefixFlash = "flash"
	errPrefixPush  = "push"
)

// Options wires build handlers to caller-owned state and helper functions.
type Options struct {
	ServerURL              *string
	Manifest               *string
	BuildName              *string
	Distro                 *string
	Target                 *string
	Architecture           *string
	ExportFormat           *string
	Mode                   *string
	AutomotiveImageBuilder *string
	StorageClass           *string
	OutputDir              *string
	Timeout                *int
	WaitForBuild           *bool
	CustomDefs             *[]string
	AIBExtraArgs           *[]string
	FollowLogs             *bool
	CompressionAlgo        *string
	AuthToken              *string
	ContainerPush          *string
	BuildDiskImage         *bool
	DiskFormat             *string
	ExportOCI              *string
	BuilderImage           *string
	RegistryAuthFile       *string
	ContainerRef           *string
	RebuildBuilder         *bool
	FlashAfterBuild        *bool
	JumpstarterClient      *string
	LeaseDuration          *string

	UseInternalRegistry       *bool
	InternalRegistryImageName *string
	InternalRegistryTag       *string

	InsecureSkipTLS *bool

	HandleError func(error)
}

// Handler implements image build command run functions.
type Handler struct {
	opts Options
}

// NewHandler creates a build workflow handler.
func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts}
}

func (h *Handler) handleError(err error) {
	if h.opts.HandleError != nil {
		h.opts.HandleError(err)
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func (h *Handler) supportsColorOutput() bool {
	return common.SupportsColorOutput()
}

func (h *Handler) applyWaitFollowDefaults(cmd *cobra.Command, defaultWait, defaultFollow bool) {
	if cmd == nil {
		return
	}
	if !cmd.Flags().Changed("wait") {
		*h.opts.WaitForBuild = defaultWait
	}
	if !cmd.Flags().Changed("follow") {
		*h.opts.FollowLogs = defaultFollow
	}
}

// validateBootcBuildFlags validates flag combinations for the build command.
func (h *Handler) validateBootcBuildFlags() error {
	if strings.TrimSpace(*h.opts.ServerURL) == "" {
		return fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')")
	}

	if *h.opts.UseInternalRegistry && *h.opts.ExportOCI != "" {
		return fmt.Errorf("--internal-registry cannot be used with --push-disk")
	}

	if *h.opts.OutputDir != "" && !*h.opts.BuildDiskImage {
		*h.opts.BuildDiskImage = true
	}
	if *h.opts.ExportOCI != "" && !*h.opts.BuildDiskImage {
		*h.opts.BuildDiskImage = true
	}
	if *h.opts.FlashAfterBuild && !*h.opts.BuildDiskImage {
		*h.opts.BuildDiskImage = true
	}
	if !*h.opts.UseInternalRegistry {
		if err := common.ValidateOutputRequiresPush(*h.opts.OutputDir, *h.opts.ExportOCI, "--push-disk"); err != nil {
			return err
		}
	}

	if *h.opts.ContainerPush == "" && !*h.opts.BuildDiskImage && !*h.opts.UseInternalRegistry {
		return fmt.Errorf(
			"--push is required when not building a disk image " +
				"(use --disk or --output to create a disk image without pushing the container)",
		)
	}

	return nil
}

// applyRegistryCredentialsToRequest sets registry credentials on the build request.
// When --internal-registry is combined with --push, both are configured so the
// container is pushed externally while the disk image uses the internal registry.
func (h *Handler) applyRegistryCredentialsToRequest(req *buildapitypes.BuildRequest) error {
	if *h.opts.UseInternalRegistry {
		req.UseInternalRegistry = true
		req.InternalRegistryImageName = *h.opts.InternalRegistryImageName
		req.InternalRegistryTag = *h.opts.InternalRegistryTag
		if *h.opts.ContainerPush == "" {
			return nil
		}
		// Hybrid: fall through to also set external registry credentials
		// for the container push.
	}

	effectiveRegistryURL, registryUsername, registryPassword := registryauth.ExtractRegistryCredentials(*h.opts.ContainerPush, *h.opts.ExportOCI)
	registryCreds, err := registryauth.ResolveRegistryCredentials(
		effectiveRegistryURL,
		registryUsername,
		registryPassword,
		*h.opts.RegistryAuthFile,
	)
	if err != nil {
		return err
	}
	req.RegistryCredentials = registryCreds
	return nil
}

// fetchTargetDefaults fetches the operator config once and returns it.
// If flash is enabled, it also validates that the target has a Jumpstarter mapping.
func (h *Handler) fetchTargetDefaults(
	ctx context.Context,
	api *buildapiclient.Client,
	target string,
	validateFlash bool,
) (*buildapitypes.OperatorConfigResponse, error) {
	config, err := api.GetOperatorConfig(ctx)
	if err != nil {
		// Non-fatal for defaults: if we can't reach the config endpoint, just skip defaults.
		if !validateFlash {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch operator config for target defaults: %v\n", err)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get operator configuration for Jumpstarter validation: %w", err)
	}

	if validateFlash {
		if len(config.JumpstarterTargets) == 0 {
			return nil, fmt.Errorf("flash enabled but no Jumpstarter target mappings configured in operator")
		}

		if _, exists := config.JumpstarterTargets[target]; !exists {
			availableTargets := make([]string, 0, len(config.JumpstarterTargets))
			for t := range config.JumpstarterTargets {
				availableTargets = append(availableTargets, t)
			}
			return nil, fmt.Errorf(
				"flash enabled but no Jumpstarter target mapping found for target %q. Available targets: %v",
				target,
				availableTargets,
			)
		}
	}

	return config, nil
}

// ApplyTargetDefaults applies architecture and extra-args defaults from the operator
// target defaults. CLI flags override defaults when explicitly set.
func ApplyTargetDefaults(cmd *cobra.Command, config *buildapitypes.OperatorConfigResponse, req *buildapitypes.BuildRequest) {
	if config == nil || len(config.TargetDefaults) == 0 {
		return
	}

	defaults, exists := config.TargetDefaults[string(req.Target)]
	if !exists {
		return
	}

	if defaults.Architecture != "" && !cmd.Flags().Changed("arch") {
		req.Architecture = buildapitypes.Architecture(defaults.Architecture)
		fmt.Printf("Using architecture %q from target defaults for %q\n", defaults.Architecture, req.Target)
	}

	if len(defaults.ExtraArgs) > 0 {
		// Default args come first, user args appended.
		req.AIBExtraArgs = append(defaults.ExtraArgs, req.AIBExtraArgs...)
		fmt.Printf("Prepending extra args %v from target defaults for %q\n", defaults.ExtraArgs, req.Target)
	}
}

// displayBuildResults shows push locations after build completion.
func (h *Handler) displayBuildResults(ctx context.Context, api *buildapiclient.Client, buildName string) {
	labelColor := func(a ...any) string { return fmt.Sprint(a...) }
	valueColor := func(a ...any) string { return fmt.Sprint(a...) }
	if h.supportsColorOutput() {
		labelColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		valueColor = color.New(color.FgHiGreen).SprintFunc()
	}

	if *h.opts.UseInternalRegistry {
		st, err := api.GetBuild(ctx, buildName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to get build results for %s: %v\n", buildName, err)
			return
		}
		if st.ContainerImage != "" {
			fmt.Printf("%s %s\n", labelColor("Container image:"), valueColor(st.ContainerImage))
		}
		if st.DiskImage != "" {
			fmt.Printf("%s %s\n", labelColor("Disk image:"), valueColor(st.DiskImage))
		}
		if st.RegistryToken != "" {
			if *h.opts.OutputDir != "" && st.DiskImage != "" {
				if err := common.PullOCIArtifact(
					st.DiskImage,
					*h.opts.OutputDir,
					"serviceaccount",
					st.RegistryToken,
					*h.opts.InsecureSkipTLS,
				); err != nil {
					h.handleError(fmt.Errorf("failed to download OCI artifact: %w", err))
					return
				}
			} else {
				credsFile, credsErr := common.WriteRegistryCredentialsFile(st.RegistryToken)
				if credsErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to write registry credentials file: %v\n", credsErr)
					fmt.Printf("\n%s\n", labelColor("Registry credentials (valid ~4 hours):"))
					fmt.Printf("  %s %s\n", labelColor("Username:"), valueColor("serviceaccount"))
					fmt.Printf("  %s %s\n", labelColor("Token:"), valueColor(st.RegistryToken))
				} else {
					fmt.Printf("\n%s %s (valid ~4 hours)\n",
						labelColor("Registry credentials written to:"),
						valueColor(credsFile),
					)
				}
			}
		}
		return
	}

	if *h.opts.ContainerPush != "" {
		fmt.Printf("%s %s\n", labelColor("Container image pushed to:"), valueColor(*h.opts.ContainerPush))
	}
	if *h.opts.ExportOCI != "" {
		fmt.Printf("%s %s\n", labelColor("Disk image pushed to:"), valueColor(*h.opts.ExportOCI))
	}
	if *h.opts.OutputDir != "" {
		_, registryUsername, registryPassword := registryauth.ExtractRegistryCredentials(*h.opts.ContainerPush, *h.opts.ExportOCI)
		if err := common.PullOCIArtifact(
			*h.opts.ExportOCI,
			*h.opts.OutputDir,
			registryUsername,
			registryPassword,
			*h.opts.InsecureSkipTLS,
		); err != nil {
			h.handleError(fmt.Errorf("failed to download OCI artifact: %w", err))
			return
		}
	}
}

func (h *Handler) displayBuildLogsCommand(buildName string) {
	labelColor := func(a ...any) string { return fmt.Sprint(a...) }
	commandColor := func(a ...any) string { return fmt.Sprint(a...) }
	if h.supportsColorOutput() {
		labelColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		commandColor = color.New(color.FgHiYellow, color.Bold).SprintFunc()
	}

	fmt.Printf("\n%s\n  %s\n\n", labelColor("View build logs:"), commandColor("caib image logs "+buildName))
}

// RunBuild handles the main `caib image build` command.
func (h *Handler) RunBuild(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, true, false)

	ctx := context.Background()
	manifestPath := args[0]
	*h.opts.Manifest = manifestPath

	if err := common.ValidateManifestSuffix(manifestPath); err != nil {
		h.handleError(err)
		return
	}
	if err := h.validateBootcBuildFlags(); err != nil {
		h.handleError(err)
		return
	}

	if *h.opts.BuildName == "" {
		base := filepath.Base(manifestPath)
		base = strings.TrimSuffix(base, ".aib.yml")
		base = strings.TrimSuffix(base, ".mpp.yml")
		sanitized := common.SanitizeBuildName(base)
		*h.opts.BuildName = fmt.Sprintf("%s-%s", sanitized, time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", *h.opts.BuildName)
	} else if err := common.ValidateBuildName(*h.opts.BuildName); err != nil {
		h.handleError(err)
		return
	}

	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		h.handleError(fmt.Errorf("error reading manifest: %w", err))
		return
	}

	req := buildapitypes.BuildRequest{
		Name:                   *h.opts.BuildName,
		Manifest:               string(manifestBytes),
		ManifestFileName:       filepath.Base(manifestPath),
		Distro:                 buildapitypes.Distro(*h.opts.Distro),
		Target:                 buildapitypes.Target(*h.opts.Target),
		Architecture:           buildapitypes.Architecture(*h.opts.Architecture),
		ExportFormat:           buildapitypes.ExportFormat(*h.opts.DiskFormat),
		Mode:                   buildapitypes.ModeBootc,
		AutomotiveImageBuilder: *h.opts.AutomotiveImageBuilder,
		StorageClass:           *h.opts.StorageClass,
		CustomDefs:             *h.opts.CustomDefs,
		AIBExtraArgs:           *h.opts.AIBExtraArgs,
		Compression:            *h.opts.CompressionAlgo,
		ContainerPush:          *h.opts.ContainerPush,
		BuildDiskImage:         *h.opts.BuildDiskImage,
		ExportOCI:              *h.opts.ExportOCI,
		BuilderImage:           *h.opts.BuilderImage,
		RebuildBuilder:         *h.opts.RebuildBuilder,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, *h.opts.Target, *h.opts.FlashAfterBuild)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}
	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if *h.opts.FlashAfterBuild {
		if *h.opts.ExportOCI == "" && !*h.opts.UseInternalRegistry {
			h.handleError(fmt.Errorf("cannot enable --flash without exporting a disk image (--push-disk)"))
			return
		}
		if *h.opts.JumpstarterClient == "" {
			h.handleError(fmt.Errorf("--flash requires --client to specify Jumpstarter client config file"))
			return
		}
		clientConfigBytes, clientErr := os.ReadFile(*h.opts.JumpstarterClient)
		if clientErr != nil {
			h.handleError(fmt.Errorf("failed to read Jumpstarter client config: %w", clientErr))
			return
		}
		req.FlashEnabled = true
		req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientConfigBytes)
		req.FlashLeaseDuration = *h.opts.LeaseDuration
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	h.displayBuildLogsCommand(resp.Name)

	localRefs, refsErr := common.FindLocalFileReferences(string(manifestBytes))
	if refsErr != nil {
		h.handleError(fmt.Errorf("manifest file reference error: %w", refsErr))
		return
	}
	if len(localRefs) > 0 {
		if err := h.handleFileUploads(ctx, api, resp.Name, localRefs); err != nil {
			h.handleError(err)
			return
		}
	}

	if *h.opts.WaitForBuild || *h.opts.FollowLogs || *h.opts.OutputDir != "" || *h.opts.FlashAfterBuild {
		if err := h.waitForBuildCompletion(ctx, api, resp.Name); err != nil {
			return
		}
	}

	h.displayBuildResults(ctx, api, resp.Name)
}

// RunDisk handles `caib image disk`.
func (h *Handler) RunDisk(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, false, false)

	ctx := context.Background()
	containerRef := args[0]
	*h.opts.ContainerRef = containerRef

	if strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}

	// Default to internal registry when no push destination is specified
	if *h.opts.ExportOCI == "" && !*h.opts.UseInternalRegistry {
		*h.opts.UseInternalRegistry = true
	}

	if *h.opts.UseInternalRegistry && *h.opts.ExportOCI != "" {
		h.handleError(fmt.Errorf("--internal-registry cannot be used with --push"))
		return
	}

	if *h.opts.BuildName == "" {
		parts := strings.Split(containerRef, "/")
		imagePart := parts[len(parts)-1]
		imagePart = strings.Split(imagePart, ":")[0]
		sanitized := common.SanitizeBuildName(imagePart)
		*h.opts.BuildName = fmt.Sprintf("disk-%s-%s", sanitized, time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", *h.opts.BuildName)
	} else if err := common.ValidateBuildName(*h.opts.BuildName); err != nil {
		h.handleError(err)
		return
	}

	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	req := buildapitypes.BuildRequest{
		Name:                   *h.opts.BuildName,
		ContainerRef:           containerRef,
		Distro:                 buildapitypes.Distro(*h.opts.Distro),
		Target:                 buildapitypes.Target(*h.opts.Target),
		Architecture:           buildapitypes.Architecture(*h.opts.Architecture),
		ExportFormat:           buildapitypes.ExportFormat(*h.opts.DiskFormat),
		Mode:                   buildapitypes.ModeDisk,
		AutomotiveImageBuilder: *h.opts.AutomotiveImageBuilder,
		StorageClass:           *h.opts.StorageClass,
		AIBExtraArgs:           *h.opts.AIBExtraArgs,
		Compression:            *h.opts.CompressionAlgo,
		ExportOCI:              *h.opts.ExportOCI,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, *h.opts.Target, *h.opts.FlashAfterBuild)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}
	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if *h.opts.FlashAfterBuild {
		if *h.opts.ExportOCI == "" && !*h.opts.UseInternalRegistry {
			h.handleError(fmt.Errorf("cannot enable --flash without exporting a disk image (--push)"))
			return
		}
		if *h.opts.JumpstarterClient == "" {
			h.handleError(fmt.Errorf("--flash requires --client to specify Jumpstarter client config file"))
			return
		}
		clientConfigBytes, clientErr := os.ReadFile(*h.opts.JumpstarterClient)
		if clientErr != nil {
			h.handleError(fmt.Errorf("failed to read Jumpstarter client config: %w", clientErr))
			return
		}
		req.FlashEnabled = true
		req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientConfigBytes)
		req.FlashLeaseDuration = *h.opts.LeaseDuration
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	h.displayBuildLogsCommand(resp.Name)

	if *h.opts.WaitForBuild || *h.opts.FollowLogs || *h.opts.OutputDir != "" || *h.opts.FlashAfterBuild {
		if err := h.waitForBuildCompletion(ctx, api, resp.Name); err != nil {
			return
		}
	}

	h.displayBuildResults(ctx, api, resp.Name)
}

// RunBuildDev handles `caib image build-dev` (traditional ostree/package builds).
func (h *Handler) RunBuildDev(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, true, false)

	ctx := context.Background()
	manifestPath := args[0]
	*h.opts.Manifest = manifestPath

	if err := common.ValidateManifestSuffix(manifestPath); err != nil {
		h.handleError(err)
		return
	}

	if strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}

	if *h.opts.UseInternalRegistry {
		if *h.opts.ExportOCI != "" {
			h.handleError(fmt.Errorf("--internal-registry cannot be used with --push"))
			return
		}
	} else if err := common.ValidateOutputRequiresPush(*h.opts.OutputDir, *h.opts.ExportOCI, "--push"); err != nil {
		h.handleError(err)
		return
	}

	if *h.opts.BuildName == "" {
		base := filepath.Base(manifestPath)
		base = strings.TrimSuffix(base, ".aib.yml")
		base = strings.TrimSuffix(base, ".mpp.yml")
		sanitized := common.SanitizeBuildName(base)
		*h.opts.BuildName = fmt.Sprintf("%s-%s", sanitized, time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", *h.opts.BuildName)
	} else if err := common.ValidateBuildName(*h.opts.BuildName); err != nil {
		h.handleError(err)
		return
	}

	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		h.handleError(fmt.Errorf("error reading manifest: %w", err))
		return
	}

	var parsedMode buildapitypes.Mode
	switch *h.opts.Mode {
	case "image":
		parsedMode = buildapitypes.ModeImage
	case "package":
		parsedMode = buildapitypes.ModePackage
	default:
		h.handleError(fmt.Errorf(
			"invalid --mode %q (expected: %q or %q)",
			*h.opts.Mode,
			buildapitypes.ModeImage,
			buildapitypes.ModePackage,
		))
		return
	}

	req := buildapitypes.BuildRequest{
		Name:                   *h.opts.BuildName,
		Manifest:               string(manifestBytes),
		ManifestFileName:       filepath.Base(manifestPath),
		Distro:                 buildapitypes.Distro(*h.opts.Distro),
		Target:                 buildapitypes.Target(*h.opts.Target),
		Architecture:           buildapitypes.Architecture(*h.opts.Architecture),
		ExportFormat:           buildapitypes.ExportFormat(*h.opts.ExportFormat),
		Mode:                   parsedMode,
		AutomotiveImageBuilder: *h.opts.AutomotiveImageBuilder,
		StorageClass:           *h.opts.StorageClass,
		CustomDefs:             *h.opts.CustomDefs,
		AIBExtraArgs:           *h.opts.AIBExtraArgs,
		Compression:            *h.opts.CompressionAlgo,
		ExportOCI:              *h.opts.ExportOCI,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, *h.opts.Target, *h.opts.FlashAfterBuild)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}
	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if *h.opts.FlashAfterBuild {
		if *h.opts.ExportOCI == "" && !*h.opts.UseInternalRegistry {
			h.handleError(fmt.Errorf("cannot enable --flash without exporting a disk image (--push)"))
			return
		}
		if *h.opts.JumpstarterClient == "" {
			h.handleError(fmt.Errorf("--flash requires --client to specify Jumpstarter client config file"))
			return
		}

		clientConfigBytes, clientErr := os.ReadFile(*h.opts.JumpstarterClient)
		if clientErr != nil {
			h.handleError(fmt.Errorf("failed to read Jumpstarter client config: %w", clientErr))
			return
		}
		req.FlashEnabled = true
		req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientConfigBytes)
		req.FlashLeaseDuration = *h.opts.LeaseDuration
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	h.displayBuildLogsCommand(resp.Name)

	localRefs, refsErr := common.FindLocalFileReferences(string(manifestBytes))
	if refsErr != nil {
		h.handleError(fmt.Errorf("manifest file reference error: %w", refsErr))
		return
	}
	if len(localRefs) > 0 {
		if err := h.handleFileUploads(ctx, api, resp.Name, localRefs); err != nil {
			h.handleError(err)
			return
		}
	}

	if *h.opts.WaitForBuild || *h.opts.FollowLogs || *h.opts.OutputDir != "" || *h.opts.FlashAfterBuild {
		if err := h.waitForBuildCompletion(ctx, api, resp.Name); err != nil {
			return
		}
	}

	h.displayBuildResults(ctx, api, resp.Name)
}

func (h *Handler) handleFileUploads(
	ctx context.Context,
	api *buildapiclient.Client,
	buildName string,
	localRefs []map[string]string,
) error {
	for _, ref := range localRefs {
		if _, err := os.Stat(ref["source_path"]); err != nil {
			return fmt.Errorf("referenced file %s does not exist: %w", ref["source_path"], err)
		}
	}

	fmt.Println("Waiting for upload server to be ready...")
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		if err := readyCtx.Err(); err != nil {
			return fmt.Errorf("timed out waiting for upload server to be ready")
		}
		reqCtx, reqCancel := context.WithTimeout(readyCtx, 15*time.Second)
		st, err := api.GetBuild(reqCtx, buildName)
		reqCancel()
		if err == nil {
			if st.Phase == phaseUploading {
				break
			}
			if st.Phase == phaseFailed {
				return fmt.Errorf("build failed while waiting for upload server: %s", st.Message)
			}
		}
		time.Sleep(3 * time.Second)
	}

	uploads := make([]buildapiclient.Upload, 0, len(localRefs))
	for _, ref := range localRefs {
		uploads = append(uploads, buildapiclient.Upload{
			SourcePath: ref["source_path"],
			DestPath:   ref["path"],
		})
	}

	uploadDeadline := time.Now().Add(10 * time.Minute)
	const perAttemptTimeout = 30 * time.Second
	for {
		remaining := time.Until(uploadDeadline)
		if remaining <= 0 {
			return fmt.Errorf("upload files failed: timed out after 10m")
		}
		attemptTimeout := perAttemptTimeout
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}

		attemptCtx, attemptCancel := context.WithTimeout(ctx, attemptTimeout)
		err := api.UploadFiles(attemptCtx, buildName, uploads)
		attemptCancel()
		if err != nil {
			lower := strings.ToLower(err.Error())
			if time.Now().After(uploadDeadline) {
				return fmt.Errorf("upload files failed: %w", err)
			}
			isServiceUnavailable := strings.Contains(lower, "503") ||
				strings.Contains(lower, "service unavailable") ||
				strings.Contains(lower, "upload pod not ready")
			if isServiceUnavailable {
				fmt.Println("Upload server not ready yet. Retrying...")
				time.Sleep(5 * time.Second)
				continue
			}
			return fmt.Errorf("upload files failed: %w", err)
		}
		break
	}
	fmt.Println("Local files uploaded. Build will proceed.")
	return nil
}
