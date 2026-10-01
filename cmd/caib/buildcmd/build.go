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
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	buildcontract "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
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
	Connection  *commandopts.Connection
	Output      *commandopts.Output
	Callback    *commandopts.Callback
	Registry    *commandopts.Registry
	S3          *commandopts.S3
	Flash       *commandopts.Flash
	Build       *commandopts.Build
	HandleError func(error)
}

// Handler implements image build command run functions.
type Handler struct {
	opts        Options
	lastLeaseID string
}

// NewHandler creates a build workflow handler.
func (o Options) withDefaults() Options {
	if o.Connection == nil {
		o.Connection = &commandopts.Connection{}
	}
	if o.Output == nil {
		o.Output = &commandopts.Output{}
	}
	if o.Callback == nil {
		o.Callback = &commandopts.Callback{}
	}
	if o.Registry == nil {
		o.Registry = &commandopts.Registry{}
	}
	if o.S3 == nil {
		o.S3 = &commandopts.S3{}
	}
	if o.Flash == nil {
		o.Flash = &commandopts.Flash{}
	}
	if o.Build == nil {
		o.Build = &commandopts.Build{}
	}
	return o
}

func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts.withDefaults()}
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

func (h *Handler) isStructuredOutput() bool {
	return common.IsStructuredFormat(&h.opts.Output.Format)
}

// BuildResult is the machine-readable output emitted when --output-format is json or yaml.
type BuildResult struct {
	ExternalID              string                            `json:"externalId,omitempty" yaml:"externalId,omitempty"`
	Notification            *buildcontract.NotificationStatus `json:"notification,omitempty" yaml:"notification,omitempty"`
	Name                    string                            `json:"name" yaml:"name"`
	Phase                   string                            `json:"phase" yaml:"phase"`
	Message                 string                            `json:"message,omitempty" yaml:"message,omitempty"`
	ContainerImage          string                            `json:"containerImage,omitempty" yaml:"containerImage,omitempty"`
	DiskImage               string                            `json:"diskImage,omitempty" yaml:"diskImage,omitempty"`
	LeaseID                 string                            `json:"leaseId,omitempty" yaml:"leaseId,omitempty"`
	RegistryCredentialsFile string                            `json:"registryCredentialsFile,omitempty" yaml:"registryCredentialsFile,omitempty"`
	RegistryUsername        string                            `json:"registryUsername,omitempty" yaml:"registryUsername,omitempty"`
	RegistryToken           string                            `json:"registryToken,omitempty" yaml:"registryToken,omitempty"`
}

func (h *Handler) applyWaitFollowDefaults(cmd *cobra.Command, defaultWait bool) {
	if cmd == nil {
		return
	}
	if h.isStructuredOutput() {
		clilog.SetQuiet(true)
	}
	if !cmd.Flags().Changed("wait") {
		h.opts.Output.Wait = defaultWait
	}
	if !cmd.Flags().Changed("follow") {
		h.opts.Output.FollowLogs = false
	}
}

// validateRegistryFlags auto-enables --internal-registry when --output is specified
// without a push destination, then validates mutual exclusion and output-requires-push.
func (h *Handler) validateRegistryFlags(pushFlagName, suggestion string) error {
	if h.opts.Output.Dir != "" && h.opts.Registry.ExportOCI == "" && !h.opts.Registry.UseInternalRegistry {
		h.opts.Registry.UseInternalRegistry = true
	}
	if h.opts.Registry.UseInternalRegistry && h.opts.Registry.ExportOCI != "" {
		return common.NewActionableError(
			fmt.Errorf("--internal-registry cannot be used with %s", pushFlagName),
			suggestion,
		)
	}
	if !h.opts.Registry.UseInternalRegistry {
		if err := common.ValidateOutputRequiresPush(h.opts.Output.Dir, h.opts.Registry.ExportOCI, pushFlagName); err != nil {
			return err
		}
	}
	return nil
}

// validateBootcBuildFlags validates flag combinations for the build command.
func (h *Handler) validateBootcBuildFlags() error {
	if strings.TrimSpace(h.opts.Connection.ServerURL) == "" {
		return common.ServerURLRequiredError("caib image build --server <server-url>")
	}

	if h.opts.Output.Dir != "" && !h.opts.Build.BuildDiskImage {
		h.opts.Build.BuildDiskImage = true
	}
	if h.opts.Registry.ExportOCI != "" && !h.opts.Build.BuildDiskImage {
		h.opts.Build.BuildDiskImage = true
	}
	if h.opts.Flash.AfterBuild && !h.opts.Build.BuildDiskImage {
		h.opts.Build.BuildDiskImage = true
	}
	if err := h.validateRegistryFlags("--push-disk",
		fmt.Sprintf("caib image build -m %s --push-disk %s", h.opts.Build.Manifest, h.opts.Registry.ExportOCI)); err != nil {
		return err
	}

	if err := h.validateSecurityFlags(); err != nil {
		return err
	}

	if h.opts.Registry.ContainerPush == "" && !h.opts.Build.BuildDiskImage && !h.opts.Registry.UseInternalRegistry {
		return fmt.Errorf(
			"--push is required when not building a disk image " +
				"(use --disk or --output to create a disk image without pushing the container)",
		)
	}

	return nil
}

func (h *Handler) validateSecurityFlags() error {
	if err := common.ValidateReproducibleRequiresSecure(h.opts.Build.Reproducible, h.opts.Build.SecureBuild); err != nil {
		return err
	}
	if h.opts.Build.SecureBuild && h.opts.Registry.UseInternalRegistry {
		return common.NewActionableError(
			fmt.Errorf("--secure cannot be used with --internal-registry (the internal registry does not support required OCI referrers)"),
			"push to a registry that supports OCI referrers with --push or --push-disk",
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
func (h *Handler) applyRegistryCredentialsToRequest(req *buildcontract.BuildRequest) error {
	if h.opts.Registry.UseInternalRegistry {
		req.UseInternalRegistry = true
		req.InternalRegistryImageName = h.opts.Registry.InternalRegistryImageName
		req.InternalRegistryTag = h.opts.Registry.InternalRegistryTag
		if h.opts.Registry.ContainerPush == "" && !h.hasRegistryCredentials() {
			return nil
		}
	}

	effectiveRegistryURL, registryUsername, registryPassword := registryauth.ExtractRegistryCredentials(h.opts.Registry.ContainerPush, h.opts.Registry.ExportOCI)
	registryCreds, err := registryauth.ResolveRegistryCredentials(
		effectiveRegistryURL,
		registryUsername,
		registryPassword,
		h.opts.Registry.AuthFile,
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
	if strings.TrimSpace(h.opts.Registry.AuthFile) != "" {
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
		h.opts.Build.Target = manifestTarget
		clilog.Infof("Using target %q from manifest\n", manifestTarget)
		return
	}

	h.opts.Build.Target = "qemu"
}

func (h *Handler) validateManifestSchema(config *buildcontract.OperatorConfigResponse, manifest []byte) bool {
	if os.Getenv("CAIB_SKIP_MANIFEST_VALIDATION") != "" {
		return true
	}

	imageRef := h.opts.Build.AutomotiveImageBuilder
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
) (*buildcontract.OperatorConfigResponse, error) {
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
func ApplyTargetDefaults(cmd *cobra.Command, config *buildcontract.OperatorConfigResponse, req *buildcontract.BuildRequest) {
	if config == nil || len(config.TargetDefaults) == 0 {
		return
	}

	defaults, exists := config.TargetDefaults[string(req.Target)]
	if !exists {
		return
	}

	if defaults.Architecture != "" && !cmd.Flags().Changed("arch") {
		req.Architecture = buildcontract.Architecture(defaults.Architecture)
		clilog.Infof("Using architecture %q from target defaults for %q\n", defaults.Architecture, req.Target)
	}

	if len(defaults.ExtraArgs) > 0 {
		// Default args come first, user args appended.
		req.AIBExtraArgs = append(defaults.ExtraArgs, req.AIBExtraArgs...)
		clilog.Infof("Prepending extra args %v from target defaults for %q\n", defaults.ExtraArgs, req.Target)
	}

	if defaults.DefaultFormat != "" && !cmd.Flags().Changed("format") {
		req.ExportFormat = buildcontract.ExportFormat(defaults.DefaultFormat)
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
func (h *Handler) displayBuildResults(ctx context.Context, api *buildapiclient.Client, buildName string) *buildcontract.BuildResponse {
	st, err := api.GetBuild(ctx, buildName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to get build results for %s: %v\n", buildName, err)
		return nil
	}

	if h.isStructuredOutput() {
		credsFile := h.handleBuildArtifacts(st)
		format, _ := common.ResolveOutputFormat(&h.opts.Output.Format)
		result := BuildResult{
			ExternalID:              st.ExternalID,
			Notification:            st.Notification,
			Name:                    st.Name,
			Phase:                   st.Phase,
			Message:                 st.Message,
			ContainerImage:          st.ContainerImage,
			DiskImage:               st.DiskImage,
			LeaseID:                 h.lastLeaseID,
			RegistryCredentialsFile: credsFile,
		}
		if st.RegistryToken != "" && h.opts.Registry.UseInternalRegistry {
			result.RegistryUsername = "serviceaccount"
			result.RegistryToken = st.RegistryToken
		}
		common.RenderFormatted(format, result, nil, h.handleError)
		return st
	}

	credsFile := h.handleBuildArtifacts(st)
	h.displayBuildResultsText(st, credsFile)
	return st
}

func (h *Handler) finishBuild(ctx context.Context, api *buildapiclient.Client, buildName string, wait bool) {
	var waitErr error
	if wait {
		waitErr = h.waitForBuildCompletion(ctx, api, buildName)
	}
	st := h.displayBuildResults(ctx, api, buildName)
	if waitErr == nil {
		return
	}
	if st != nil && ((st.Flash != nil && st.Flash.State == "Failed") || strings.Contains(strings.ToLower(st.Message), errPrefixFlash)) {
		h.handleFlashError(waitErr, st)
		return
	}
	h.handleError(waitErr)
}

// handleBuildArtifacts performs side effects (download, creds file) and returns the creds file path.
func (h *Handler) handleBuildArtifacts(st *buildcontract.BuildResponse) string {
	if h.opts.Registry.UseInternalRegistry {
		if st.RegistryToken != "" {
			if h.opts.Output.Dir != "" && st.DiskImage != "" {
				if err := common.PullOCIArtifact(
					st.DiskImage,
					h.opts.Output.Dir,
					"serviceaccount",
					st.RegistryToken,
					h.opts.Connection.InsecureSkipTLS,
				); err != nil {
					h.handleError(fmt.Errorf("failed to download OCI artifact: %w", err))
					return ""
				}
			} else {
				credsFile, credsErr := common.WriteRegistryCredentialsFile(st.RegistryToken)
				if credsErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to write registry credentials file: %v\n", credsErr)
					return ""
				}
				return credsFile
			}
		}
		return ""
	}

	if h.opts.Output.Dir != "" && st.DiskImage != "" {
		_, registryUsername, registryPassword := registryauth.ExtractRegistryCredentials(h.opts.Registry.ContainerPush, h.opts.Registry.ExportOCI)
		if err := common.PullOCIArtifact(
			h.opts.Registry.ExportOCI,
			h.opts.Output.Dir,
			registryUsername,
			registryPassword,
			h.opts.Connection.InsecureSkipTLS,
		); err != nil {
			h.handleError(fmt.Errorf("failed to download OCI artifact: %w", err))
		}
	}
	return ""
}

// displayBuildResultsText prints the human-readable (table) build results.
func (h *Handler) displayBuildResultsText(st *buildcontract.BuildResponse, credsFile string) {
	labelColor := func(a ...any) string { return fmt.Sprint(a...) }
	valueColor := func(a ...any) string { return fmt.Sprint(a...) }
	if h.supportsColorOutput() {
		labelColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		valueColor = color.New(color.FgHiGreen).SprintFunc()
	}

	if h.opts.Registry.UseInternalRegistry {
		if st.ContainerImage != "" {
			clilog.Infof("%s %s\n", labelColor("Container image:"), valueColor(st.ContainerImage))
		}
		if st.DiskImage != "" {
			clilog.Infof("%s %s\n", labelColor("Disk image:"), valueColor(st.DiskImage))
		}
		if credsFile != "" {
			clilog.Infof("\n%s %s (valid ~4 hours)\n",
				labelColor("Registry credentials written to:"),
				valueColor(credsFile),
			)
		} else if st.RegistryToken != "" && h.opts.Output.Dir == "" {
			clilog.Infof("\n%s\n", labelColor("Registry credentials (valid ~4 hours):"))
			clilog.Infof("  %s %s\n", labelColor("Username:"), valueColor("serviceaccount"))
			clilog.Infof("  %s %s\n", labelColor("Token:"), valueColor(st.RegistryToken))
		}
		return
	}

	if st.ContainerImage != "" && h.opts.Registry.ContainerPush != "" {
		clilog.Infof("%s %s\n", labelColor("Container image pushed to:"), valueColor(h.opts.Registry.ContainerPush))
	}
	if st.DiskImage != "" && h.opts.Registry.ExportOCI != "" {
		clilog.Infof("%s %s\n", labelColor("Disk image pushed to:"), valueColor(h.opts.Registry.ExportOCI))
	}
}

func (h *Handler) applyNotificationOptions(req *buildcontract.BuildRequest) error {
	callbackURL, callbackSecretFile, externalID := "", "", ""
	if h.opts.Callback.URL != "" {
		callbackURL = h.opts.Callback.URL
	}
	if h.opts.Callback.SecretFile != "" {
		callbackSecretFile = h.opts.Callback.SecretFile
	}
	if h.opts.Callback.ExternalID != "" {
		externalID = h.opts.Callback.ExternalID
	}
	callback, err := common.LoadBuildCallback(callbackURL, callbackSecretFile)
	if err != nil {
		return err
	}
	req.ExternalID = externalID
	req.Callback = callback
	return nil
}

func (h *Handler) validateFlashLeaseFlags(cmd *cobra.Command) error {
	if h.opts.Flash.AfterBuild && h.opts.Flash.LeaseName != "" && cmd.Flags().Changed("lease-duration") {
		return common.NewActionableError(
			fmt.Errorf("--lease and --lease-duration are mutually exclusive"),
			fmt.Sprintf("caib image build --flash --lease %s", h.opts.Flash.LeaseName),
			"caib image build --flash --lease-duration <duration>",
		)
	}
	return nil
}

// applyFlashOptions validates flash flags and populates flash fields on req.
// The pushRequiredFlag is the flag name shown in the error message (e.g. "--push-disk" or "--push").
func (h *Handler) applyFlashOptions(req *buildcontract.BuildRequest, pushRequiredFlag string) error {
	if !h.opts.Flash.AfterBuild {
		return nil
	}
	if h.opts.Registry.ExportOCI == "" && !h.opts.Registry.UseInternalRegistry {
		return common.NewActionableError(
			fmt.Errorf("cannot enable --flash without exporting a disk image (%s)", pushRequiredFlag),
			fmt.Sprintf("caib image build --flash %s <registry>", pushRequiredFlag),
		)
	}
	clientInfo, err := common.ResolveJumpstarterClient(strings.TrimSpace(h.opts.Flash.JumpstarterClient))
	if err != nil {
		return fmt.Errorf("--flash: %w", err)
	}
	clilog.Infof("Using Jumpstarter client %q (endpoint: %s)\n", clientInfo.Name, clientInfo.Endpoint)
	req.FlashEnabled = true
	req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientInfo.Data)
	req.FlashLeaseName = h.opts.Flash.LeaseName
	if req.FlashLeaseName == "" {
		req.FlashLeaseDuration = h.opts.Flash.LeaseDuration
	}
	req.FlashCmd = h.opts.Flash.Cmd
	req.FlashExporterSelector = h.opts.Flash.ExporterSelector
	req.FlashLeaseTags, err = common.ValidateAndJoinLeaseTags(&h.opts.Flash.LeaseTags)
	if err != nil {
		return err
	}
	return nil
}

// s3DefaultsFn is the function used to load S3 defaults from the config file.
// Overridden in tests.
var s3DefaultsFn = config.S3Defaults

func (h *Handler) applyS3Options(cmd *cobra.Command, req *buildcontract.BuildRequest) error {
	bucket := h.opts.S3.Bucket

	s3Cfg, err := s3DefaultsFn()
	if err != nil {
		return err
	}

	if !flagChanged(cmd, "s3-bucket") && bucket == "" && s3Cfg != nil {
		bucket = s3Cfg.Bucket
	}
	if bucket == "" {
		return nil
	}
	req.S3Bucket = bucket

	h.applyS3ConnectionParams(cmd, req, s3Cfg)

	return h.applyS3Credentials(req, s3Cfg)
}

func (h *Handler) applyS3ConnectionParams(cmd *cobra.Command, req *buildcontract.BuildRequest, s3Cfg *config.S3Config) {
	if flagChanged(cmd, "s3-prefix") {
		req.S3Prefix = h.opts.S3.Prefix
	} else if v := h.opts.S3.Prefix; v != "" {
		req.S3Prefix = v
	} else if s3Cfg != nil {
		req.S3Prefix = s3Cfg.Prefix
	}

	if flagChanged(cmd, "s3-endpoint") {
		req.S3Endpoint = h.opts.S3.Endpoint
	} else if v := h.opts.S3.Endpoint; v != "" {
		req.S3Endpoint = v
	} else if s3Cfg != nil {
		req.S3Endpoint = s3Cfg.Endpoint
	}

	if flagChanged(cmd, "s3-region") {
		req.S3Region = h.opts.S3.Region
	} else if v := h.opts.S3.Region; v != "" {
		req.S3Region = v
	} else if s3Cfg != nil {
		req.S3Region = s3Cfg.Region
	}

	if flagChanged(cmd, "s3-insecure") {
		req.S3InsecureSkipTLSVerify = h.opts.S3.Insecure
	} else if h.opts.S3.Insecure {
		req.S3InsecureSkipTLSVerify = true
	} else if s3Cfg != nil {
		req.S3InsecureSkipTLSVerify = s3Cfg.InsecureSkipTLSVerify
	}
}

func (h *Handler) applyS3Credentials(req *buildcontract.BuildRequest, s3Cfg *config.S3Config) error {
	secretProvided := h.opts.S3.CredentialsSecret != ""
	explicitAccess := h.opts.S3.AccessKeyID != ""
	explicitSecret := h.opts.S3.SecretAccessKey != ""
	inlineCredsProvided := explicitAccess || explicitSecret
	envAccess := os.Getenv("AWS_ACCESS_KEY_ID")
	envSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	envCredsProvided := envAccess != "" || envSecret != ""

	sourcesCount := 0
	if secretProvided {
		sourcesCount++
	}
	if inlineCredsProvided {
		sourcesCount++
	}
	if envCredsProvided {
		sourcesCount++
	}
	if sourcesCount > 1 {
		return fmt.Errorf("multiple S3 credential sources provided; use only one of: --s3-credentials-secret, --s3-access-key-id/--s3-secret-access-key, or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env vars")
	}

	if secretProvided {
		req.S3CredentialsSecretName = h.opts.S3.CredentialsSecret
	} else if inlineCredsProvided {
		if !explicitAccess {
			return fmt.Errorf("--s3-secret-access-key is set but --s3-access-key-id is missing")
		}
		if !explicitSecret {
			return fmt.Errorf("--s3-access-key-id is set but --s3-secret-access-key is missing")
		}
		req.S3Credentials = &buildcontract.S3Credentials{
			AccessKeyID:     h.opts.S3.AccessKeyID,
			SecretAccessKey: h.opts.S3.SecretAccessKey,
		}
	} else if envCredsProvided {
		if envAccess == "" {
			return fmt.Errorf("AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is missing")
		}
		if envSecret == "" {
			return fmt.Errorf("AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is missing")
		}
		req.S3Credentials = &buildcontract.S3Credentials{
			AccessKeyID:     envAccess,
			SecretAccessKey: envSecret,
		}
	} else if s3Cfg != nil && s3Cfg.CredentialsSecret != "" {
		req.S3CredentialsSecretName = s3Cfg.CredentialsSecret
	}

	return nil
}

func flagChanged(cmd *cobra.Command, name string) bool {
	return cmd != nil && cmd.Flags().Changed(name)
}

func (h *Handler) displayBuildLogsCommand(buildName string) {
	if clilog.IsQuiet() || h.isStructuredOutput() {
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
	if len(h.opts.Build.DefineFiles) > 0 {
		fileDefs, err := common.LoadDefineFiles(h.opts.Build.DefineFiles)
		if err != nil {
			return nil, err
		}
		defs = append(defs, fileDefs...)
	}
	if len(h.opts.Build.CustomDefs) > 0 {
		defs = append(defs, h.opts.Build.CustomDefs...)
	}
	return defs, nil
}

func parseRootPassword(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("root password value cannot be empty, must be env:VAR or file:PATH")
	}
	parts := strings.SplitN(input, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid root password format %q, must be env:VAR or file:PATH", input)
	}
	prefix, value := parts[0], parts[1]
	switch prefix {
	case "env":
		v, ok := os.LookupEnv(value)
		if !ok {
			return "", fmt.Errorf("environment variable %q not set", value)
		}
		return v, nil
	case "file":
		data, err := os.ReadFile(value)
		if err != nil {
			return "", fmt.Errorf("reading root password file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	default:
		return "", fmt.Errorf("unknown root password prefix %q, must be env or file", prefix)
	}
}

func (h *Handler) resolveRootPassword() (string, error) {
	if h.opts.Build.RootPassword == "" {
		return "", nil
	}
	return parseRootPassword(h.opts.Build.RootPassword)
}

// resolveRepoFlags processes --extra-repo and --local-repo into workspace repos,
// OCI image refs, and whether local-repo mode is active.
func resolveRepoFlags(extraRepos []string, localRepoFlag string) (workspaceRepos []string, ociImages []string, isLocalRepo bool, err error) {
	workspaceRepos, ociImages, err = splitExtraRepos(extraRepos)
	if err != nil {
		return nil, nil, false, err
	}

	if len(ociImages) > 1 {
		return nil, nil, false, fmt.Errorf("at most one --extra-repo oci: is supported, got %d", len(ociImages))
	}

	localRef := strings.TrimSpace(localRepoFlag)
	if localRef == "" {
		return workspaceRepos, ociImages, false, nil
	}

	localRef = strings.TrimPrefix(localRef, "oci:")
	if localRef == "" {
		return nil, nil, false, fmt.Errorf("--local-repo requires an OCI image reference (e.g. quay.io/org/rpms:latest)")
	}
	if len(ociImages) > 0 {
		return nil, nil, false, fmt.Errorf("--local-repo and --extra-repo oci: are mutually exclusive")
	}
	return workspaceRepos, []string{localRef}, true, nil
}

func parseDevMode(mode string) (buildcontract.Mode, error) {
	switch mode {
	case "image":
		return buildcontract.ModeImage, nil
	case "package":
		return buildcontract.ModePackage, nil
	default:
		return "", fmt.Errorf("invalid --mode %q (expected: %q or %q)", mode, buildcontract.ModeImage, buildcontract.ModePackage)
	}
}

func (h *Handler) resolveManifestBuildName(manifestPath string) error {
	if h.opts.Build.Name != "" {
		return common.ValidateBuildName(h.opts.Build.Name)
	}

	base := filepath.Base(manifestPath)
	base = strings.TrimSuffix(base, ".aib.yml")
	base = strings.TrimSuffix(base, ".mpp.yml")
	h.opts.Build.Name = common.SanitizeBuildName(base)
	clilog.Infof("Auto-generated build name: %s\n", h.opts.Build.Name)
	return nil
}

// Entries with the "oci:" prefix are OCI image references (stripped of the prefix);
// all other entries are workspace repos passed through unchanged.
func splitExtraRepos(repos []string) (workspaceRepos []string, ociImages []string, err error) {
	for _, repo := range repos {
		if after, ok := strings.CutPrefix(repo, "oci:"); ok {
			ref := after
			if ref == "" {
				return nil, nil, fmt.Errorf("--extra-repo oci: requires an image reference (e.g. oci:quay.io/org/rpms:latest)")
			}
			ociImages = append(ociImages, ref)
		} else {
			workspaceRepos = append(workspaceRepos, repo)
		}
	}
	return workspaceRepos, ociImages, nil
}

// RunBuild handles the main `caib image build` command.
func (h *Handler) RunBuild(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, true)

	ctx := context.Background()
	manifestPath := args[0]
	h.opts.Build.Manifest = manifestPath

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

	if err := h.resolveManifestBuildName(manifestPath); err != nil {
		h.handleError(err)
		return
	}

	h.runManifestBuild(ctx, cmd, manifestPath, false)
}

// RunDisk handles `caib image disk`.
func (h *Handler) RunDisk(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, false)

	ctx := context.Background()
	containerRef := args[0]
	h.opts.Build.ContainerRef = containerRef

	if strings.TrimSpace(h.opts.Connection.ServerURL) == "" {
		h.handleError(common.ServerURLRequiredError(fmt.Sprintf("caib image disk --server <server-url> %s", containerRef)))
		return
	}

	// Default to internal registry when no push destination is specified
	if h.opts.Registry.ExportOCI == "" && !h.opts.Registry.UseInternalRegistry {
		h.opts.Registry.UseInternalRegistry = true
	}

	if h.opts.Registry.UseInternalRegistry && h.opts.Registry.ExportOCI != "" {
		h.handleError(common.NewActionableError(
			fmt.Errorf("--internal-registry cannot be used with --push"),
			fmt.Sprintf("caib image disk --push %s %s", h.opts.Registry.ExportOCI, containerRef),
		))
		return
	}

	if h.opts.Build.Name == "" {
		parts := strings.Split(containerRef, "/")
		imagePart := parts[len(parts)-1]
		imagePart = strings.Split(imagePart, ":")[0]
		sanitized := common.SanitizeBuildName(imagePart)
		h.opts.Build.Name = fmt.Sprintf("disk-%s", sanitized)
		clilog.Infof("Auto-generated build name: %s\n", h.opts.Build.Name)
	} else if err := common.ValidateBuildName(h.opts.Build.Name); err != nil {
		h.handleError(err)
		return
	}
	if err := h.validateFlashLeaseFlags(cmd); err != nil {
		h.handleError(err)
		return
	}

	api, err := common.CreateBuildAPIClient(h.opts.Connection.ServerURL, &h.opts.Connection.AuthToken, h.opts.Connection.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	h.resolveTarget(cmd, "") // no manifest for disk command

	req := buildcontract.BuildRequest{
		Name:                   h.opts.Build.Name,
		ContainerRef:           containerRef,
		Distro:                 buildcontract.Distro(h.opts.Build.Distro),
		Target:                 buildcontract.Target(h.opts.Build.Target),
		Architecture:           buildcontract.Architecture(h.opts.Build.Architecture),
		ExportFormat:           buildcontract.ExportFormat(h.opts.Build.DiskFormat),
		Mode:                   buildcontract.ModeDisk,
		AutomotiveImageBuilder: h.opts.Build.AutomotiveImageBuilder,
		StorageClass:           h.opts.Build.StorageClass,
		AIBExtraArgs:           h.opts.Build.AIBExtraArgs,
		Compression:            buildcontract.Compression(h.opts.Build.CompressionAlgo),
		ExportOCI:              h.opts.Registry.ExportOCI,
		SecureBuild:            h.opts.Build.SecureBuild,
		TaskBundleRef:          h.opts.Build.TaskBundleRef,
		RestoreSourcesRef:      h.opts.Build.RestoreSourcesRef,
		TTL:                    h.opts.Build.TTL,
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	validateFlash := h.opts.Flash.AfterBuild && h.opts.Flash.ExporterSelector == ""
	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, h.opts.Build.Target, validateFlash)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}
	ApplyTargetDefaults(cmd, operatorConfig, &req)

	if err := h.applyFlashOptions(&req, "--push"); err != nil {
		h.handleError(err)
		return
	}

	if err := h.applyS3Options(cmd, &req); err != nil {
		h.handleError(err)
		return
	}
	if err := h.applyNotificationOptions(&req); err != nil {
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

	h.finishBuild(ctx, api, resp.Name, h.opts.Output.Wait || h.opts.Output.FollowLogs || h.opts.Output.Dir != "" || h.opts.Flash.AfterBuild)
}

func (h *Handler) validateDevExportFlags(manifestPath string) error {
	if h.opts.Registry.UseInternalRegistry {
		if h.opts.Registry.ExportOCI != "" {
			return common.NewActionableError(
				fmt.Errorf("--internal-registry cannot be used with --push"),
				fmt.Sprintf("caib image build-dev --push %s %s", h.opts.Registry.ExportOCI, manifestPath),
			)
		}
		return nil
	}
	if h.opts.S3.Bucket != "" {
		return nil
	}
	return common.ValidateOutputRequiresPush(h.opts.Output.Dir, h.opts.Registry.ExportOCI, "--push")
}

func (h *Handler) validateBuildDevOptions(manifestPath string) error {
	if err := common.ValidateManifestSuffix(manifestPath); err != nil {
		return err
	}
	if strings.TrimSpace(h.opts.Connection.ServerURL) == "" {
		return common.ServerURLRequiredError(fmt.Sprintf("caib image build-dev --server <server-url> %s", manifestPath))
	}
	if err := h.validateRegistryFlags("--push",
		fmt.Sprintf("caib image build-dev --push %s %s", h.opts.Registry.ExportOCI, manifestPath)); err != nil {
		return err
	}
	if err := h.validateDevExportFlags(manifestPath); err != nil {
		return err
	}
	return h.validateSecurityFlags()
}

// RunBuildDev handles `caib image build-dev` (traditional ostree/package builds).
func (h *Handler) RunBuildDev(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, true)

	ctx := context.Background()
	manifestPath := args[0]
	h.opts.Build.Manifest = manifestPath

	if err := h.validateBuildDevOptions(manifestPath); err != nil {
		h.handleError(err)
		return
	}

	if err := h.resolveManifestBuildName(manifestPath); err != nil {
		h.handleError(err)
		return
	}
	if err := h.validateFlashLeaseFlags(cmd); err != nil {
		h.handleError(err)
		return
	}

	h.runManifestBuild(ctx, cmd, manifestPath, true)
}

func (h *Handler) runManifestBuild(ctx context.Context, cmd *cobra.Command, manifestPath string, development bool) {
	api, err := common.CreateBuildAPIClient(h.opts.Connection.ServerURL, &h.opts.Connection.AuthToken, h.opts.Connection.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	manifestBytes, gitSource, err := h.readBuildSource(manifestPath)
	if err != nil {
		h.handleError(fmt.Errorf("error reading manifest: %w", err))
		return
	}

	h.resolveTarget(cmd, common.ManifestTarget(manifestBytes))

	validateFlash := gitSource == nil && h.opts.Flash.AfterBuild && h.opts.Flash.ExporterSelector == ""
	operatorConfig, cfgErr := h.fetchTargetDefaults(ctx, api, h.opts.Build.Target, validateFlash)
	if cfgErr != nil {
		h.handleError(cfgErr)
		return
	}

	if gitSource == nil && !h.validateManifestSchema(operatorConfig, manifestBytes) {
		return
	}

	customDefs, err := h.resolveCustomDefs()
	if err != nil {
		h.handleError(err)
		return
	}

	lockfile, err := h.readLockfile()
	if err != nil {
		h.handleError(err)
		return
	}

	rootPassword, err := h.resolveRootPassword()
	if err != nil {
		h.handleError(err)
		return
	}

	mode := buildcontract.ModeBootc
	exportFormat := h.opts.Build.DiskFormat
	pushFlag := "--push-disk"
	if development {
		mode, err = parseDevMode(h.opts.Build.Mode)
		if err != nil {
			h.handleError(err)
			return
		}
		exportFormat = h.opts.Build.ExportFormat
		pushFlag = "--push"
	}

	workspaceRepos, ociRepoImages, localRepo, err := resolveRepoFlags(h.opts.Build.ExtraRepos, h.opts.Build.LocalRepo)
	if err != nil {
		h.handleError(err)
		return
	}

	req := buildcontract.BuildRequest{
		Name:                   h.opts.Build.Name,
		Manifest:               string(manifestBytes),
		GitSource:              gitSource,
		ManifestFileName:       filepath.Base(manifestPath),
		Distro:                 buildcontract.Distro(h.opts.Build.Distro),
		Target:                 buildcontract.Target(h.opts.Build.Target),
		Architecture:           buildcontract.Architecture(h.opts.Build.Architecture),
		ExportFormat:           buildcontract.ExportFormat(exportFormat),
		Mode:                   mode,
		AutomotiveImageBuilder: h.opts.Build.AutomotiveImageBuilder,
		StorageClass:           h.opts.Build.StorageClass,
		CustomDefs:             customDefs,
		AIBExtraArgs:           h.opts.Build.AIBExtraArgs,
		Lockfile:               lockfile,
		RootPassword:           rootPassword,
		ExtraRepos:             workspaceRepos,
		OCIRepoImages:          ociRepoImages,
		LocalRepo:              localRepo,
		Workspace:              h.opts.Build.Workspace,
		Compression:            buildcontract.Compression(h.opts.Build.CompressionAlgo),
		ExportOCI:              h.opts.Registry.ExportOCI,
		SecureBuild:            h.opts.Build.SecureBuild,
		Reproducible:           h.opts.Build.Reproducible,
		TaskBundleRef:          h.opts.Build.TaskBundleRef,
		RestoreSourcesRef:      h.opts.Build.RestoreSourcesRef,
		TTL:                    h.opts.Build.TTL,
	}

	if !development {
		req.ContainerPush = h.opts.Registry.ContainerPush
		req.BuildDiskImage = h.opts.Build.BuildDiskImage
		req.BuilderImage = h.opts.Build.BuilderImage
		req.RebuildBuilder = h.opts.Build.RebuildBuilder
	}

	if err := h.applyRegistryCredentialsToRequest(&req); err != nil {
		h.handleError(err)
		return
	}

	if req.GitSource == nil {
		ApplyTargetDefaults(cmd, operatorConfig, &req)
	}
	deferGitDefaults(cmd, &req)

	if err := h.applyFlashOptions(&req, pushFlag); err != nil {
		h.handleError(err)
		return
	}

	if err := h.applyS3Options(cmd, &req); err != nil {
		h.handleError(err)
		return
	}
	if err := h.applyNotificationOptions(&req); err != nil {
		h.handleError(err)
		return
	}

	localRefs, cleanup, refsErr := h.prepareManifestUploads(ctx, api, &req, manifestPath)
	if refsErr != nil {
		h.handleError(fmt.Errorf("manifest file reference error: %w", refsErr))
		return
	}
	defer cleanup()
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

	h.finishBuild(ctx, api, resp.Name, h.opts.Output.Wait || h.opts.Output.FollowLogs || h.opts.Output.Dir != "" || h.opts.Flash.AfterBuild)
}

func nopWorkspaceCleanup() {}

func (h *Handler) prepareManifestUploads(
	ctx context.Context,
	api *buildapiclient.Client,
	req *buildcontract.BuildRequest,
	manifestPath string,
) ([]map[string]string, func(), error) {
	if req.GitSource != nil {
		return nil, nopWorkspaceCleanup, nil
	}
	workspaceBuild := strings.TrimSpace(h.opts.Build.Workspace) != ""
	rewritten, localRefs, err := common.PrepareLocalFileUploads(req.Manifest, filepath.Dir(manifestPath), workspaceBuild)
	if err != nil {
		return nil, nil, err
	}
	req.Manifest = rewritten
	if !workspaceBuild {
		return localRefs, nopWorkspaceCleanup, nil
	}
	// CAIB_CLIENT_WORKSPACE_UPLOAD=0: send /workspace paths unchanged so the
	// operator hydrate path can be tested (no client-side copy).
	if os.Getenv("CAIB_CLIENT_WORKSPACE_UPLOAD") == "0" {
		return localRefs, nopWorkspaceCleanup, nil
	}
	rewritten, wsRefs, cleanup, err := h.materializeWorkspaceFiles(ctx, api, strings.TrimSpace(h.opts.Build.Workspace), req.Manifest)
	if err != nil {
		return nil, nil, err
	}
	if cleanup == nil {
		cleanup = nopWorkspaceCleanup
	}
	req.Manifest = rewritten
	return append(localRefs, wsRefs...), cleanup, nil
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
			DestPath:   ref["dest"],
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
		attemptTimeout := min(remaining, perAttemptTimeout)

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
	if strings.TrimSpace(h.opts.Connection.ServerURL) == "" {
		h.handleError(common.ServerURLRequiredError(fmt.Sprintf("caib image %s --server <server-url> %s", verb, buildName)))
		return
	}

	api, err := common.CreateBuildAPIClient(h.opts.Connection.ServerURL, &h.opts.Connection.AuthToken, h.opts.Connection.InsecureSkipTLS)
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
