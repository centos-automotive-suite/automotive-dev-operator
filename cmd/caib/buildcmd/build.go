// Package buildcmd provides handlers for image build workflows.
package buildcmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/manifestschema"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	phaseCancelled = automotivev1alpha1.ImageBuildPhaseCancelled
	phaseCompleted = automotivev1alpha1.ImageBuildPhaseCompleted
	phaseFailed    = automotivev1alpha1.ImageBuildPhaseFailed
	phaseFlashing  = automotivev1alpha1.ImageBuildPhaseFlashing
	phasePending   = automotivev1alpha1.ImageBuildPhasePending
	phaseUploading = automotivev1alpha1.ImageBuildPhaseUploading
	phaseRunning   = "Running"

	errPrefixFlash = "flash"
)

var isTerminalPhase = automotivev1alpha1.IsTerminalBuildPhase

var validateFromImageFn = manifestschema.ValidateFromImage

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
	DefineFiles            *[]string
	AIBExtraArgs           *[]string
	ExtraRepos             *[]string
	Workspace              *string
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
	LeaseName              *string
	FlashCmd               *string
	ExporterSelector       *string
	LeaseTags              *[]string

	UseInternalRegistry       *bool
	InternalRegistryImageName *string
	InternalRegistryTag       *string

	SecureBuild       *bool
	Reproducible      *bool
	TaskBundleRef     *string
	RestoreSourcesRef *string
	TTL               *string

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
	fmt.Fprintln(os.Stderr, common.FormatError(err))
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
		return common.ServerURLRequiredError("caib image build --server <server-url>")
	}

	if *h.opts.UseInternalRegistry && *h.opts.ExportOCI != "" {
		return common.NewActionableError(
			fmt.Errorf("--internal-registry cannot be used with --push-disk"),
			fmt.Sprintf("caib image build -m %s --push-disk %s", *h.opts.Manifest, *h.opts.ExportOCI),
		)
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

	if err := h.validateReproducibleFlags(); err != nil {
		return err
	}

	if *h.opts.ContainerPush == "" && !*h.opts.BuildDiskImage && !*h.opts.UseInternalRegistry {
		return fmt.Errorf(
			"--push is required when not building a disk image " +
				"(use --disk or --output to create a disk image without pushing the container)",
		)
	}

	return nil
}

func (h *Handler) validateReproducibleFlags() error {
	if err := common.ValidateReproducibleRequiresSecure(*h.opts.Reproducible, *h.opts.SecureBuild); err != nil {
		return err
	}
	if *h.opts.Reproducible && *h.opts.UseInternalRegistry {
		return common.NewActionableError(
			fmt.Errorf("--reproducible cannot be used with --internal-registry (internal registry does not support OCI referrers)"),
			"caib image build -m <manifest> --reproducible --push-disk <registry>",
		)
	}
	return nil
}

// applyRegistryCredentialsToRequest sets registry credentials on the build request.
// When --internal-registry is combined with --push, both are configured so the
// container is pushed externally while the disk image uses the internal registry.
// Credentials are also resolved for --internal-registry without --push when the
// user provides them (env vars or --registry-auth-file), enabling authenticated
// pulls of private source images during the build.
func (h *Handler) applyRegistryCredentialsToRequest(req *buildapitypes.BuildRequest) error {
	if *h.opts.UseInternalRegistry {
		req.UseInternalRegistry = true
		req.InternalRegistryImageName = *h.opts.InternalRegistryImageName
		req.InternalRegistryTag = *h.opts.InternalRegistryTag
		if *h.opts.ContainerPush == "" && !h.hasRegistryCredentials() {
			return nil
		}
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

// hasRegistryCredentials returns true if the user has provided registry credentials
// via environment variables or --registry-auth-file.
func (h *Handler) hasRegistryCredentials() bool {
	if h.opts.RegistryAuthFile != nil && strings.TrimSpace(*h.opts.RegistryAuthFile) != "" {
		return true
	}
	if os.Getenv("REGISTRY_USERNAME") != "" || os.Getenv("REGISTRY_URL") != "" {
		return true
	}
	return false
}

// resolveTarget determines the build target: --target flag > manifest value > "qemu".
func (h *Handler) resolveTarget(cmd *cobra.Command, manifestTarget string) {
	if cmd.Flags().Changed("target") {
		return
	}

	if manifestTarget != "" {
		*h.opts.Target = manifestTarget
		clilog.Infof("Using target %q from manifest\n", manifestTarget)
		return
	}

	*h.opts.Target = "qemu"
}

func (h *Handler) validateManifestSchema(config *buildapitypes.OperatorConfigResponse, manifest []byte) bool {
	if os.Getenv("CAIB_SKIP_MANIFEST_VALIDATION") != "" {
		return true
	}

	imageRef := *h.opts.AutomotiveImageBuilder
	if imageRef == automotivev1alpha1.DefaultAutomotiveImageBuilderImage && config != nil && config.AutomotiveImageBuilder != "" {
		imageRef = config.AutomotiveImageBuilder
	}
	if imageRef == "" {
		return true
	}

	result, err := validateFromImageFn(imageRef, manifest)
	if err != nil {
		clilog.Warnf("Skipping local manifest validation: %v\n", err)
		return true
	}
	if !result.Valid {
		h.handleError(fmt.Errorf("%s", result.Error()))
		return false
	}
	return true
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
		clilog.Infof("Using architecture %q from target defaults for %q\n", defaults.Architecture, req.Target)
	}

	if len(defaults.ExtraArgs) > 0 {
		// Default args come first, user args appended.
		req.AIBExtraArgs = append(defaults.ExtraArgs, req.AIBExtraArgs...)
		clilog.Infof("Prepending extra args %v from target defaults for %q\n", defaults.ExtraArgs, req.Target)
	}

	if defaults.DefaultFormat != "" && !cmd.Flags().Changed("format") {
		req.ExportFormat = buildapitypes.ExportFormat(defaults.DefaultFormat)
		clilog.Infof("Using format %q from target defaults for %q\n", defaults.DefaultFormat, req.Target)
	}

	warnIfNotInList(defaults.AcceptedArchitectures, "architecture", string(req.Architecture))
	warnIfNotInList(defaults.AcceptedFormats, "format", string(req.ExportFormat))
}

func warnIfNotInList(accepted []string, field, value string) {
	if len(accepted) == 0 || value == "" {
		return
	}
	if !slices.Contains(accepted, value) {
		_, _ = color.New(color.FgRed, color.Bold).Fprintf(os.Stderr, "Warning: %s %q is not in accepted values %v\n", field, value, accepted)
	}
}

// displayBuildResults shows push locations after build completion.
// It queries the server for actual build status so that messages are only
// shown for steps that actually succeeded.
func (h *Handler) displayBuildResults(ctx context.Context, api *buildapiclient.Client, buildName string) {
	labelColor := func(a ...any) string { return fmt.Sprint(a...) }
	valueColor := func(a ...any) string { return fmt.Sprint(a...) }
	if h.supportsColorOutput() {
		labelColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		valueColor = color.New(color.FgHiGreen).SprintFunc()
	}

	st, err := api.GetBuild(ctx, buildName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to get build results for %s: %v\n", buildName, err)
		return
	}

	if *h.opts.UseInternalRegistry {
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
					clilog.Infof("\n%s\n", labelColor("Registry credentials (valid ~4 hours):"))
					clilog.Infof("  %s %s\n", labelColor("Username:"), valueColor("serviceaccount"))
					clilog.Infof("  %s %s\n", labelColor("Token:"), valueColor(st.RegistryToken))
				} else {
					clilog.Infof("\n%s %s (valid ~4 hours)\n",
						labelColor("Registry credentials written to:"),
						valueColor(credsFile),
					)
				}
			}
		}
		return
	}

	if st.ContainerImage != "" && *h.opts.ContainerPush != "" {
		fmt.Printf("%s %s\n", labelColor("Container image pushed to:"), valueColor(*h.opts.ContainerPush))
	}
	if st.DiskImage != "" && *h.opts.ExportOCI != "" {
		fmt.Printf("%s %s\n", labelColor("Disk image pushed to:"), valueColor(*h.opts.ExportOCI))
	}
	if *h.opts.OutputDir != "" && st.DiskImage != "" {
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

func (h *Handler) validateFlashLeaseFlags(cmd *cobra.Command) error {
	if *h.opts.FlashAfterBuild && *h.opts.LeaseName != "" && cmd.Flags().Changed("lease-duration") {
		return common.NewActionableError(
			fmt.Errorf("--lease and --lease-duration are mutually exclusive"),
			fmt.Sprintf("caib image build --flash --lease %s", *h.opts.LeaseName),
			"caib image build --flash --lease-duration <duration>",
		)
	}
	return nil
}

// applyFlashOptions validates flash flags and populates flash fields on req.
// The pushRequiredFlag is the flag name shown in the error message (e.g. "--push-disk" or "--push").
func (h *Handler) applyFlashOptions(req *buildapitypes.BuildRequest, pushRequiredFlag string) error {
	if !*h.opts.FlashAfterBuild {
		return nil
	}
	if *h.opts.ExportOCI == "" && !*h.opts.UseInternalRegistry {
		return common.NewActionableError(
			fmt.Errorf("cannot enable --flash without exporting a disk image (%s)", pushRequiredFlag),
			fmt.Sprintf("caib image build --flash %s <registry>", pushRequiredFlag),
		)
	}
	clientInfo, err := common.ResolveJumpstarterClient(strings.TrimSpace(*h.opts.JumpstarterClient))
	if err != nil {
		return fmt.Errorf("--flash: %w", err)
	}
	clilog.Infof("Using Jumpstarter client %q (endpoint: %s)\n", clientInfo.Name, clientInfo.Endpoint)
	req.FlashEnabled = true
	req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientInfo.Data)
	req.FlashLeaseName = *h.opts.LeaseName
	if req.FlashLeaseName == "" {
		req.FlashLeaseDuration = *h.opts.LeaseDuration
	}
	req.FlashCmd = *h.opts.FlashCmd
	req.FlashExporterSelector = *h.opts.ExporterSelector
	req.FlashLeaseTags, err = common.ValidateAndJoinLeaseTags(h.opts.LeaseTags)
	if err != nil {
		return err
	}
	return nil
}

func (h *Handler) displayBuildLogsCommand(buildName string) {
	if clilog.IsQuiet() {
		return
	}
	labelColor := func(a ...any) string { return fmt.Sprint(a...) }
	commandColor := func(a ...any) string { return fmt.Sprint(a...) }
	if h.supportsColorOutput() {
		labelColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		commandColor = color.New(color.FgHiYellow, color.Bold).SprintFunc()
	}

	fmt.Printf("\n%s\n  %s\n\n", labelColor("View build logs:"), commandColor("caib image logs "+buildName))
}

func (h *Handler) resolveCustomDefs() ([]string, error) {
	var defs []string
	if len(*h.opts.DefineFiles) > 0 {
		fileDefs, err := common.LoadDefineFiles(*h.opts.DefineFiles)
		if err != nil {
			return nil, err
		}
		defs = append(defs, fileDefs...)
	}
	if h.opts.CustomDefs != nil {
		defs = append(defs, *h.opts.CustomDefs...)
	}
	return defs, nil
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
	if err := h.validateFlashLeaseFlags(cmd); err != nil {
		h.handleError(err)
		return
	}

	if *h.opts.BuildName == "" {
		base := filepath.Base(manifestPath)
		base = strings.TrimSuffix(base, ".aib.yml")
		base = strings.TrimSuffix(base, ".mpp.yml")
		sanitized := common.SanitizeBuildName(base)
		*h.opts.BuildName = sanitized
		clilog.Infof("Auto-generated build name: %s\n", *h.opts.BuildName)
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

	h.resolveTarget(cmd, common.ManifestTarget(manifestBytes))

	validateFlash := *h.opts.FlashAfterBuild && *h.opts.ExporterSelector == ""
	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, *h.opts.Target, validateFlash)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}

	if !h.validateManifestSchema(operatorConfig, manifestBytes) {
		return
	}

	customDefs, err := h.resolveCustomDefs()
	if err != nil {
		h.handleError(err)
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
		CustomDefs:             customDefs,
		AIBExtraArgs:           *h.opts.AIBExtraArgs,
		ExtraRepos:             *h.opts.ExtraRepos,
		Workspace:              *h.opts.Workspace,
		Compression:            buildapitypes.Compression(*h.opts.CompressionAlgo),
		ContainerPush:          *h.opts.ContainerPush,
		BuildDiskImage:         *h.opts.BuildDiskImage,
		ExportOCI:              *h.opts.ExportOCI,
		BuilderImage:           *h.opts.BuilderImage,
		RebuildBuilder:         *h.opts.RebuildBuilder,
		SecureBuild:            *h.opts.SecureBuild,
		Reproducible:           *h.opts.Reproducible,
		TaskBundleRef:          *h.opts.TaskBundleRef,
		RestoreSourcesRef:      *h.opts.RestoreSourcesRef,
		TTL:                    *h.opts.TTL,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if err := h.applyFlashOptions(&req, "--push-disk"); err != nil {
		h.handleError(err)
		return
	}

	localRefs, refsErr := common.FindLocalFileReferences(string(manifestBytes), filepath.Dir(manifestPath))
	if refsErr != nil {
		h.handleError(fmt.Errorf("manifest file reference error: %w", refsErr))
		return
	}
	req.HasLocalFiles = len(localRefs) > 0

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	clilog.Infof("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	h.displayBuildLogsCommand(resp.Name)

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
		h.handleError(common.ServerURLRequiredError(fmt.Sprintf("caib image disk --server <server-url> %s", containerRef)))
		return
	}

	// Default to internal registry when no push destination is specified
	if *h.opts.ExportOCI == "" && !*h.opts.UseInternalRegistry {
		*h.opts.UseInternalRegistry = true
	}

	if *h.opts.UseInternalRegistry && *h.opts.ExportOCI != "" {
		h.handleError(common.NewActionableError(
			fmt.Errorf("--internal-registry cannot be used with --push"),
			fmt.Sprintf("caib image disk --push %s %s", *h.opts.ExportOCI, containerRef),
		))
		return
	}

	if *h.opts.BuildName == "" {
		parts := strings.Split(containerRef, "/")
		imagePart := parts[len(parts)-1]
		imagePart = strings.Split(imagePart, ":")[0]
		sanitized := common.SanitizeBuildName(imagePart)
		*h.opts.BuildName = fmt.Sprintf("disk-%s", sanitized)
		clilog.Infof("Auto-generated build name: %s\n", *h.opts.BuildName)
	} else if err := common.ValidateBuildName(*h.opts.BuildName); err != nil {
		h.handleError(err)
		return
	}
	if err := h.validateFlashLeaseFlags(cmd); err != nil {
		h.handleError(err)
		return
	}

	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	h.resolveTarget(cmd, "") // no manifest for disk command

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
		Compression:            buildapitypes.Compression(*h.opts.CompressionAlgo),
		ExportOCI:              *h.opts.ExportOCI,
		SecureBuild:            *h.opts.SecureBuild,
		TaskBundleRef:          *h.opts.TaskBundleRef,
		RestoreSourcesRef:      *h.opts.RestoreSourcesRef,
		TTL:                    *h.opts.TTL,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	validateFlash := *h.opts.FlashAfterBuild && *h.opts.ExporterSelector == ""
	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, *h.opts.Target, validateFlash)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}
	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if err := h.applyFlashOptions(&req, "--push"); err != nil {
		h.handleError(err)
		return
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	clilog.Infof("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
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
		h.handleError(common.ServerURLRequiredError(fmt.Sprintf("caib image build-dev --server <server-url> %s", manifestPath)))
		return
	}

	if err := h.validateReproducibleFlags(); err != nil {
		h.handleError(err)
		return
	}

	if *h.opts.UseInternalRegistry {
		if *h.opts.ExportOCI != "" {
			h.handleError(common.NewActionableError(
				fmt.Errorf("--internal-registry cannot be used with --push"),
				fmt.Sprintf("caib image build-dev --push %s %s", *h.opts.ExportOCI, manifestPath),
			))
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
		*h.opts.BuildName = sanitized
		clilog.Infof("Auto-generated build name: %s\n", *h.opts.BuildName)
	} else if err := common.ValidateBuildName(*h.opts.BuildName); err != nil {
		h.handleError(err)
		return
	}
	if err := h.validateFlashLeaseFlags(cmd); err != nil {
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

	h.resolveTarget(cmd, common.ManifestTarget(manifestBytes))

	validateFlash := *h.opts.FlashAfterBuild && *h.opts.ExporterSelector == ""
	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, *h.opts.Target, validateFlash)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}

	if !h.validateManifestSchema(operatorConfig, manifestBytes) {
		return
	}

	customDefs, err := h.resolveCustomDefs()
	if err != nil {
		h.handleError(err)
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
		CustomDefs:             customDefs,
		AIBExtraArgs:           *h.opts.AIBExtraArgs,
		ExtraRepos:             *h.opts.ExtraRepos,
		Workspace:              *h.opts.Workspace,
		Compression:            buildapitypes.Compression(*h.opts.CompressionAlgo),
		ExportOCI:              *h.opts.ExportOCI,
		SecureBuild:            *h.opts.SecureBuild,
		Reproducible:           *h.opts.Reproducible,
		TaskBundleRef:          *h.opts.TaskBundleRef,
		RestoreSourcesRef:      *h.opts.RestoreSourcesRef,
		TTL:                    *h.opts.TTL,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if err := h.applyFlashOptions(&req, "--push"); err != nil {
		h.handleError(err)
		return
	}

	localRefs, refsErr := common.FindLocalFileReferences(string(manifestBytes), filepath.Dir(manifestPath))
	if refsErr != nil {
		h.handleError(fmt.Errorf("manifest file reference error: %w", refsErr))
		return
	}
	req.HasLocalFiles = len(localRefs) > 0

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	clilog.Infof("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	h.displayBuildLogsCommand(resp.Name)

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

	clilog.Infoln("Waiting for upload server to be ready...")
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		if err := readyCtx.Err(); err != nil {
			return common.NewActionableError(
				fmt.Errorf("timed out waiting for upload server to be ready (10m)"),
				"caib image logs "+buildName,
			)
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
			DestPath:   ref["source_path"],
		})
	}

	uploadDeadline := time.Now().Add(10 * time.Minute)
	const perAttemptTimeout = 30 * time.Second
	for {
		remaining := time.Until(uploadDeadline)
		if remaining <= 0 {
			return common.NewActionableError(
				fmt.Errorf("upload files failed: timed out after 10m"),
				"caib image logs "+buildName,
			)
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
				clilog.Infoln("Upload server not ready yet. Retrying...")
				time.Sleep(5 * time.Second)
				continue
			}
			return fmt.Errorf("upload files failed: %w", err)
		}
		break
	}
	clilog.Infoln("Local files uploaded. Build will proceed.")
	return nil
}

// RunDelete handles `caib image delete`.
func (h *Handler) RunDelete(_ *cobra.Command, args []string) {
	h.runBuildAction(args[0], "deleted", func(ctx context.Context, api *buildapiclient.Client, name string) error {
		return api.DeleteBuild(ctx, name)
	})
}

// RunCancel handles `caib image cancel`.
func (h *Handler) RunCancel(_ *cobra.Command, args []string) {
	h.runBuildAction(args[0], "cancelled", func(ctx context.Context, api *buildapiclient.Client, name string) error {
		return api.CancelBuild(ctx, name)
	})
}

func (h *Handler) runBuildAction(buildName, verb string, action func(context.Context, *buildapiclient.Client, string) error) {
	if strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(common.ServerURLRequiredError(fmt.Sprintf("caib image %s --server <server-url> %s", verb, buildName)))
		return
	}

	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	if err := action(context.Background(), api, buildName); err != nil {
		h.handleError(err)
		return
	}

	clilog.Infof("Build %q %s\n", buildName, verb)
}
