// Package image defines the `caib image` command tree.
package image

import (
	"os"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

// Options wires the image command tree to caller-owned state and handlers.
type Options struct {
	RunBuild             func(*cobra.Command, []string)
	RunDisk              func(*cobra.Command, []string)
	RunBuildDev          func(*cobra.Command, []string)
	RunList              func(*cobra.Command, []string)
	RunShow              func(*cobra.Command, []string)
	RunDownload          func(*cobra.Command, []string)
	RunLogs              func(*cobra.Command, []string)
	RunFlash             func(*cobra.Command, []string)
	RunPrepareReseal     func(*cobra.Command, []string)
	RunReseal            func(*cobra.Command, []string)
	RunExtractForSigning func(*cobra.Command, []string)
	RunInjectSigned      func(*cobra.Command, []string)

	GetDefaultArch func() string

	ServerURL              *string
	AuthToken              *string
	BuildName              *string
	ShowOutputFormat       *string
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
	ContainerPush          *string
	BuildDiskImage         *bool
	DiskFormat             *string
	ExportOCI              *string
	BuilderImage           *string
	RegistryAuthFile       *string
	RebuildBuilder         *bool

	FlashAfterBuild   *bool
	JumpstarterClient *string
	FlashName         *string
	ExporterSelector  *string
	LeaseDuration     *string
	LeaseName         *string
	FlashCmd          *string

	UseInternalRegistry       *bool
	InternalRegistryImageName *string
	InternalRegistryTag       *string

	SealedBuilderImage      *string
	SealedArchitecture      *string
	SealedKeySecret         *string
	SealedKeyPasswordSecret *string
	SealedKeyFile           *string
	SealedKeyPassword       *string
	SealedInputRef          *string
	SealedOutputRef         *string
	SealedSignedRef         *string
}

// NewImageCmd creates the top-level `caib image` command with all image workflow subcommands.
func NewImageCmd(opts Options) *cobra.Command {
	defaultServer := config.DefaultServer()
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Build and manage image workflows",
		Long:  `Commands for creating, managing, and inspecting image builds.`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if opts.ServerURL != nil && strings.TrimSpace(*opts.ServerURL) == "" {
				*opts.ServerURL = config.DefaultServerWithDerive()
			}
			return nil
		},
	}

	buildCmd := newBuildCmd(opts)
	diskCmd := newDiskCmd(opts)
	buildDevCmd := newBuildDevCmd(opts)
	listCmd := newListCmd(opts)
	showCmd := newShowCmd(opts)
	downloadCmd := newDownloadCmd(opts)
	logsCmd := newLogsCmd(opts)
	flashCmd := newFlashCmd(opts)

	prepareResealCmd := newPrepareResealCmd(opts)
	resealCmd := newResealCmd(opts)
	extractForSigningCmd := newExtractForSigningCmd(opts)
	injectSignedCmd := newInjectSignedCmd(opts)

	// build command flags (bootc - the default)
	buildCmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "REST API server base URL")
	buildCmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	buildCmd.Flags().StringVarP(opts.BuildName, "name", "n", "", "name for the ImageBuild (auto-generated if omitted)")
	buildCmd.Flags().StringVarP(opts.Distro, "distro", "d", "autosd", "distribution to build")
	buildCmd.Flags().StringVarP(opts.Target, "target", "t", "qemu", "target platform")
	buildCmd.Flags().StringVarP(opts.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	buildCmd.Flags().StringVar(opts.ContainerPush, "push", "", "push bootc container to registry (optional if --disk is used)")
	buildCmd.Flags().BoolVar(opts.BuildDiskImage, "disk", false, "also build disk image from container")
	buildCmd.Flags().StringVarP(opts.OutputDir, "output", "o", "", "download disk image to file from registry (implies --disk; requires --push-disk or --internal-registry)")
	buildCmd.Flags().StringVar(
		opts.DiskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	buildCmd.Flags().StringVar(opts.CompressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	buildCmd.Flags().StringVar(opts.ExportOCI, "push-disk", "", "push disk image as OCI artifact to registry (implies --disk)")
	buildCmd.Flags().StringVar(
		opts.RegistryAuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	buildCmd.Flags().StringVar(
		opts.AutomotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	buildCmd.Flags().StringVar(opts.BuilderImage, "builder-image", "", "custom builder container")
	buildCmd.Flags().BoolVar(opts.RebuildBuilder, "rebuild-builder", false, "force rebuild of the bootc builder image")
	buildCmd.Flags().StringVar(opts.StorageClass, "storage-class", "", "Kubernetes storage class for build workspace")
	buildCmd.Flags().StringArrayVarP(opts.CustomDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildCmd.Flags().StringArrayVar(opts.AIBExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildCmd.Flags().IntVar(opts.Timeout, "timeout", 60, "timeout in minutes")
	buildCmd.Flags().BoolVarP(opts.WaitForBuild, "wait", "w", true, "wait for build to complete")
	buildCmd.Flags().BoolVarP(opts.FollowLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Note: --push is optional when --disk is used (disk image becomes the output)
	// Jumpstarter flash options
	buildCmd.Flags().BoolVar(opts.FlashAfterBuild, "flash", false, "flash the image to device after build completes")
	buildCmd.Flags().StringVar(opts.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	buildCmd.Flags().StringVar(opts.LeaseDuration, "lease-duration", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	buildCmd.Flags().StringVar(opts.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	buildCmd.Flags().StringVar(opts.FlashCmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	buildCmd.Flags().StringVar(opts.ExporterSelector, "exporter", "", "direct exporter selector for flash (alternative to --target lookup)")
	// Internal registry options
	buildCmd.Flags().BoolVar(opts.UseInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	buildCmd.Flags().StringVar(opts.InternalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	buildCmd.Flags().StringVar(opts.InternalRegistryTag, "image-tag", "", "tag for internal registry image (default: bootc)")

	listCmd.Flags().StringVar(
		opts.ServerURL, "server", defaultServer, "REST API server base URL (e.g. https://api.example)",
	)
	listCmd.Flags().StringVar(
		opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)
	showCmd.Flags().StringVar(
		opts.ServerURL, "server", defaultServer, "REST API server base URL (e.g. https://api.example)",
	)
	showCmd.Flags().StringVar(
		opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)
	showCmd.Flags().StringVarP(
		opts.ShowOutputFormat, "output", "o", "table", "Output format (table, json, yaml)",
	)

	// disk command flags (create disk from existing container)
	diskCmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "REST API server base URL")
	diskCmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	diskCmd.Flags().StringVarP(opts.BuildName, "name", "n", "", "name for the build job (auto-generated if omitted)")
	diskCmd.Flags().StringVarP(opts.OutputDir, "output", "o", "", "download disk image to file from registry (requires --push)")
	diskCmd.Flags().StringVar(
		opts.DiskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	diskCmd.Flags().StringVar(opts.CompressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	diskCmd.Flags().StringVar(opts.ExportOCI, "push", "", "push disk image as OCI artifact to registry")
	diskCmd.Flags().StringVar(
		opts.RegistryAuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	diskCmd.Flags().StringVarP(opts.Distro, "distro", "d", "autosd", "distribution")
	diskCmd.Flags().StringVarP(opts.Target, "target", "t", "qemu", "target platform")
	diskCmd.Flags().StringVarP(opts.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	diskCmd.Flags().StringVar(
		opts.AutomotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	diskCmd.Flags().StringVar(opts.StorageClass, "storage-class", "", "Kubernetes storage class")
	diskCmd.Flags().StringArrayVar(opts.AIBExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	diskCmd.Flags().IntVar(opts.Timeout, "timeout", 60, "timeout in minutes")
	diskCmd.Flags().BoolVarP(opts.WaitForBuild, "wait", "w", false, "wait for build to complete")
	diskCmd.Flags().BoolVarP(opts.FollowLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Jumpstarter flash options
	diskCmd.Flags().BoolVar(opts.FlashAfterBuild, "flash", false, "flash the image to device after build completes")
	diskCmd.Flags().StringVar(opts.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	diskCmd.Flags().StringVar(opts.LeaseDuration, "lease-duration", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	diskCmd.Flags().StringVar(opts.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	diskCmd.Flags().StringVar(opts.FlashCmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	diskCmd.Flags().StringVar(opts.ExporterSelector, "exporter", "", "direct exporter selector for flash (alternative to --target lookup)")
	// Internal registry options
	diskCmd.Flags().BoolVar(opts.UseInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	diskCmd.Flags().StringVar(opts.InternalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	diskCmd.Flags().StringVar(opts.InternalRegistryTag, "image-tag", "", "tag for internal registry image (default: disk)")

	// build-dev command flags (traditional ostree/package builds)
	buildDevCmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "REST API server base URL")
	buildDevCmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	buildDevCmd.Flags().StringVarP(opts.BuildName, "name", "n", "", "name for the ImageBuild")
	buildDevCmd.Flags().StringVarP(opts.Distro, "distro", "d", "autosd", "distribution to build")
	buildDevCmd.Flags().StringVarP(opts.Target, "target", "t", "qemu", "target platform")
	buildDevCmd.Flags().StringVarP(opts.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	buildDevCmd.Flags().StringVar(opts.Mode, "mode", "package", "build mode: image (ostree) or package (package-based)")
	buildDevCmd.Flags().StringVar(opts.ExportFormat, "format", "", "export format: qcow2, raw, simg, etc.")
	buildDevCmd.Flags().StringVarP(opts.OutputDir, "output", "o", "", "download artifact to file from registry (requires --push)")
	buildDevCmd.Flags().StringVar(opts.CompressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	buildDevCmd.Flags().StringVar(opts.ExportOCI, "push", "", "push disk image as OCI artifact to registry")
	buildDevCmd.Flags().StringVar(
		opts.RegistryAuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	buildDevCmd.Flags().StringVar(
		opts.AutomotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	buildDevCmd.Flags().StringVar(opts.StorageClass, "storage-class", "", "Kubernetes storage class")
	buildDevCmd.Flags().StringArrayVarP(opts.CustomDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildDevCmd.Flags().StringArrayVar(opts.AIBExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildDevCmd.Flags().IntVar(opts.Timeout, "timeout", 60, "timeout in minutes")
	buildDevCmd.Flags().BoolVarP(opts.WaitForBuild, "wait", "w", false, "wait for build to complete")
	buildDevCmd.Flags().BoolVarP(opts.FollowLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Jumpstarter flash options
	buildDevCmd.Flags().BoolVar(opts.FlashAfterBuild, "flash", false, "flash the image to device after build completes")
	buildDevCmd.Flags().StringVar(opts.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	buildDevCmd.Flags().StringVar(opts.LeaseDuration, "lease-duration", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	buildDevCmd.Flags().StringVar(opts.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	buildDevCmd.Flags().StringVar(opts.FlashCmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	buildDevCmd.Flags().StringVar(opts.ExporterSelector, "exporter", "", "direct exporter selector for flash (alternative to --target lookup)")
	// Internal registry options
	buildDevCmd.Flags().BoolVar(opts.UseInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	buildDevCmd.Flags().StringVar(opts.InternalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	buildDevCmd.Flags().StringVar(opts.InternalRegistryTag, "image-tag", "", "tag for internal registry image (default: disk)")

	// logs command flags
	logsCmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "REST API server base URL")
	logsCmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	logsCmd.Flags().IntVar(opts.Timeout, "timeout", 60, "timeout in minutes")

	// download command flags
	downloadCmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "REST API server base URL")
	downloadCmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	downloadCmd.Flags().StringVarP(opts.OutputDir, "output", "o", "", "destination file or directory for the artifact")

	// flash command flags
	flashCmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "REST API server base URL")
	flashCmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	flashCmd.Flags().StringVar(opts.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	flashCmd.Flags().StringVarP(opts.FlashName, "name", "n", "", "name for the flash job (auto-generated if omitted)")
	flashCmd.Flags().StringVarP(opts.Target, "target", "t", "", "target platform for exporter lookup")
	flashCmd.Flags().StringVar(opts.ExporterSelector, "exporter", "", "direct exporter selector (alternative to --target)")
	flashCmd.Flags().StringVar(opts.LeaseDuration, "lease-duration", "03:00:00", "device lease duration (HH:MM:SS)")
	flashCmd.Flags().StringVar(opts.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	flashCmd.Flags().StringVar(opts.FlashCmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	flashCmd.Flags().StringVar(
		opts.RegistryAuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for OCI image pull authentication (takes precedence over env vars and auto-discovery)",
	)
	flashCmd.Flags().BoolVarP(opts.FollowLogs, "follow", "f", false, "follow flash logs (shows full log output instead of progress bar)")
	flashCmd.Flags().BoolVarP(opts.WaitForBuild, "wait", "w", true, "wait for flash to complete")
	// Sealed operation shared flags
	addSealedFlags(prepareResealCmd, opts, defaultServer)
	addSealedFlags(resealCmd, opts, defaultServer)
	addSealedFlags(extractForSigningCmd, opts, defaultServer)
	addSealedFlags(injectSignedCmd, opts, defaultServer)
	injectSignedCmd.Flags().StringVar(opts.SealedSignedRef, "signed", "", "Signed artifact ref for inject-signed")

	cmd.AddCommand(
		buildCmd,
		diskCmd,
		buildDevCmd,
		listCmd,
		showCmd,
		downloadCmd,
		logsCmd,
		flashCmd,
		prepareResealCmd,
		resealCmd,
		extractForSigningCmd,
		injectSignedCmd,
	)

	return cmd
}

func newBuildCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "build <manifest.aib.yml>",
		Short: "Build bootc container image with optional disk image",
		Long: `Build creates a bootc container image from an AIB manifest.

Bootc images are immutable, atomically updatable OS images based on
container technology. This is the recommended approach for production.

Examples:
  # Build and push container to registry
  caib image build manifest.aib.yml --push quay.io/org/my-os:v1

  # Build container + create disk image
  caib image build manifest.aib.yml --push quay.io/org/my-os:v1 --disk -o disk.qcow2`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunBuild,
	}
}

func newDiskCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "disk <container-ref>",
		Short: "Create disk image from existing bootc container",
		Long: `Create a disk image from an existing bootc container in a registry.

This uses 'aib to-disk-image' to convert a bootc container to a disk
image that can be flashed onto hardware.

Examples:
  # Create disk image from container
  caib image disk quay.io/org/my-os:v1 -o disk.qcow2 --format qcow2

  # Push disk as OCI artifact instead of downloading
  caib image disk quay.io/org/my-os:v1 --push quay.io/org/my-disk:v1`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunDisk,
	}
}

func newBuildDevCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "build-dev <manifest.aib.yml>",
		Short: "Build disk image for development (ostree or package-based)",
		Long: `Build a disk image using ostree or package-based mode for development workflows.

This creates standalone disk images without bootc container integration.

Examples:
  # Ostree-based image
  caib image build-dev manifest.aib.yml --mode image --format qcow2 -o disk.qcow2

  # Package-based image
  caib image build-dev manifest.aib.yml --mode package --format raw -o disk.raw`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunBuildDev,
	}
}

func newFlashCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "flash <oci-registry-reference>",
		Short: "Flash a disk image to hardware via Jumpstarter",
		Long: `Flash a disk image from an OCI registry to a hardware device using Jumpstarter.

This command connects to a Jumpstarter exporter to flash the specified disk image
onto physical hardware. The Jumpstarter client config is auto-detected from
~/.config/jumpstarter/ (or $JMP_CLIENT_CONFIG_HOME), or can be specified with --client.

Examples:
  # Flash using auto-detected client config
  caib image flash quay.io/org/disk:v1 --target j784s4evm

  # Flash with explicit client config
  caib image flash quay.io/org/disk:v1 --client ~/.jumpstarter/client.yaml --target j784s4evm

  # Flash with explicit exporter selector
  caib image flash quay.io/org/disk:v1 --exporter "board-type=j784s4evm"`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunFlash,
	}
}

func newListCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List existing ImageBuilds",
		Run:   opts.RunList,
	}
}

func newShowCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "show <build-name>",
		Short: "Show detailed information for an ImageBuild",
		Long: `Show retrieves detailed status and output fields for a single ImageBuild.

Examples:
  # Show details in table format
  caib image show my-build

  # Show details as JSON
  caib image show my-build -o json`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunShow,
	}
}

func newDownloadCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "download <build-name>",
		Short: "Download disk image artifact from a completed build",
		Long: `Download retrieves the disk image artifact from a completed build.

The build must have pushed a disk image to an OCI registry (via --push-disk
or --push on disk/build-dev commands). The artifact is pulled from the
registry to a local file.

Examples:
  # Download disk image from a completed build
  caib image download my-build -o ./disk.qcow2

  # Download to a directory (multi-layer artifacts extract here)
  caib image download my-build -o ./output/`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunDownload,
	}
}

func newLogsCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "logs <build-name>",
		Short: "Follow logs of an existing build",
		Long: `Follow the log output of an active or completed build.

This is useful when you kicked off a build and need to reconnect later
(e.g., after restarting your terminal or computer).

Examples:
  # Follow logs of an active build
  caib image logs my-build-20250101-120000

  # List builds first, then follow one
  caib image list
  caib image logs <build-name>`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunLogs,
	}
}

func newPrepareResealCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "prepare-reseal [source-container] [output-container]",
		Short: "Prepare a bootc container image for resealing",
		Long: `Prepare a bootc container image for resealing. With --server, runs on
the cluster via the Build API; otherwise runs locally using the AIB container.

Input and output can be given as positionals or via --input and --output (any order).

Examples:

  # Run locally
  caib image prepare-reseal ./input.qcow2 ./output.qcow2 --workspace ./work`,
		Args: cobra.RangeArgs(0, 2),
		Run:  opts.RunPrepareReseal,
	}
}

func newResealCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "reseal [source-container] [output-container]",
		Short: "Reseal a prepared bootc container image with a new key",
		Long: `Reseal a bootc container image that was prepared with prepare-reseal.
With --server, runs on the cluster via the Build API; otherwise runs locally.

Input and output can be given as positionals or via --input and --output (any order).
If no seal key is provided, an ephemeral key is generated for one-time use.`,
		Args: cobra.RangeArgs(0, 2),
		Run:  opts.RunReseal,
	}
}

func newExtractForSigningCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "extract-for-signing [source-container] [output-artifact]",
		Short: "Extract components from a container image for external signing",
		Long: `Extract components that need to be signed (e.g. for secure boot) from a
container image. Sign the extracted contents externally, then use inject-signed.

Input and output can be given as positionals or via --input and --output (any order).`,
		Args: cobra.RangeArgs(0, 2),
		Run:  opts.RunExtractForSigning,
	}
}

func newInjectSignedCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "inject-signed [source-container] [signed-artifact] [output-container]",
		Short: "Inject signed components back into a container image",
		Long: `Inject externally signed components (from extract-for-signing) back into the
container image. Optionally reseals in the same step with --key.

Input, signed artifact, and output can be given as positionals or via --input, --signed, --output (any order).`,
		Args: cobra.RangeArgs(0, 3),
		Run:  opts.RunInjectSigned,
	}
}

func addSealedFlags(cmd *cobra.Command, opts Options, defaultServer string) {
	cmd.Flags().StringVar(opts.ServerURL, "server", defaultServer, "Build API server URL")
	cmd.Flags().StringVar(opts.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	cmd.Flags().StringVar(opts.SealedInputRef, "input", "", "Input/source container or artifact ref")
	cmd.Flags().StringVar(opts.SealedOutputRef, "output", "", "Output container or artifact ref")
	cmd.Flags().StringVar(
		opts.RegistryAuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for registry authentication (takes precedence over env vars and auto-discovery)",
	)
	cmd.Flags().StringVar(
		opts.AutomotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	cmd.Flags().StringVar(opts.SealedBuilderImage, "builder-image", "", "Builder container image (overrides --arch default)")
	cmd.Flags().StringVar(opts.SealedArchitecture, "arch", "", "Target architecture for default builder image (amd64, arm64); auto-detected if not set")
	cmd.Flags().StringArrayVar(opts.AIBExtraArgs, "extra-args", nil, "Extra arguments to pass to AIB (repeatable)")
	cmd.Flags().BoolVarP(opts.WaitForBuild, "wait", "w", false, "Wait for completion")
	cmd.Flags().BoolVarP(opts.FollowLogs, "follow", "f", true, "Stream task logs")
	cmd.Flags().StringVar(opts.SealedKeySecret, "key-secret", "", "Name of existing cluster secret containing sealing key (data key 'private-key')")
	cmd.Flags().StringVar(opts.SealedKeyPasswordSecret, "key-password-secret", "", "Name of existing cluster secret containing key password (data key 'password')")
	cmd.Flags().StringVar(opts.SealedKeyFile, "key", "", "Path to local PEM key file (uploaded to cluster automatically)")
	cmd.Flags().StringVar(opts.SealedKeyPassword, "passwd", "", "Password for encrypted key file (used with --key)")
	cmd.Flags().IntVar(opts.Timeout, "timeout", 120, "Timeout in minutes")
}
