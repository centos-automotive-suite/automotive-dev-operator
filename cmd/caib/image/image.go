// Package image defines the `caib image` command tree.
package image

import (
	"fmt"
	"os"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

// Options wires the image command tree to caller-owned state and handlers.
type Options struct {
	Connection *commandopts.Connection
	Output     *commandopts.Output
	Callback   *commandopts.Callback
	Registry   *commandopts.Registry
	S3         *commandopts.S3
	Flash      *commandopts.Flash
	Sealed     *commandopts.Sealed
	Build      *commandopts.Build

	RunBuild             func(*cobra.Command, []string)
	RunResolve           func(*cobra.Command, []string)
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
	RunToken             func(*cobra.Command, []string)
	RunDelete            func(*cobra.Command, []string)
	RunCancel            func(*cobra.Command, []string)
	RunInspect           func(*cobra.Command, []string)

	GetDefaultArch func() string
}

// NewImageCmd creates the top-level `caib image` command with all image workflow subcommands.
func NewImageCmd(opts Options) *cobra.Command {
	defaultServer := config.DefaultServer()
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Build and manage image workflows",
		Long:  `Commands for creating, managing, and inspecting image builds.`,
		PersistentPreRunE: func(runCmd *cobra.Command, _ []string) error {
			if err := applyCommandOutputDefaults(runCmd); err != nil {
				return err
			}
			if strings.TrimSpace(opts.Connection.ServerURL) == "" {
				opts.Connection.ServerURL = config.DefaultServerWithDerive()
			}
			return nil
		},
	}

	buildCmd := newBuildCmd(opts)
	resolveCmd := newResolveCmd(opts)
	diskCmd := newDiskCmd(opts)
	buildDevCmd := newBuildDevCmd(opts)
	listCmd := newListCmd(opts)
	showCmd := newShowCmd(opts)
	downloadCmd := newDownloadCmd(opts)
	logsCmd := newLogsCmd(opts)
	flashCmd := newFlashCmd(opts)

	tokenCmd := newTokenCmd(opts)
	deleteCmd := newDeleteCmd(opts)
	cancelCmd := newCancelCmd(opts)

	prepareResealCmd := newPrepareResealCmd(opts)
	resealCmd := newResealCmd(opts)
	extractForSigningCmd := newExtractForSigningCmd(opts)
	injectSignedCmd := newInjectSignedCmd(opts)

	// build command flags (bootc - the default)
	buildCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	buildCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	addNotificationFlags(buildCmd, opts)
	buildCmd.Flags().StringVarP(&opts.Build.Name, "name", "n", "", "name for the ImageBuild (auto-generated if omitted)")
	buildCmd.Flags().StringVarP(&opts.Build.Distro, "distro", "d", "autosd", "distribution to build")
	buildCmd.Flags().StringVarP(&opts.Build.Target, "target", "t", "", "target platform (default: from manifest, or qemu)")
	buildCmd.Flags().StringVarP(&opts.Build.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	buildCmd.Flags().StringVar(&opts.Registry.ContainerPush, "push", "", "push bootc container to registry (optional if --disk is used)")
	buildCmd.Flags().BoolVar(&opts.Build.BuildDiskImage, "disk", false, "also build disk image from container")
	buildCmd.Flags().StringVarP(&opts.Output.Dir, "output", "o", "", "download disk image to file from registry (uses --disk and --internal-registry when no --push-disk given)")
	buildCmd.Flags().StringVar(
		&opts.Build.DiskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	buildCmd.Flags().StringVar(&opts.Build.CompressionAlgo, "compress", "gzip", "compression algorithm (gzip, xz)")
	buildCmd.Flags().StringVar(&opts.Registry.ExportOCI, "push-disk", "", "push disk image as OCI artifact to registry (implies --disk)")
	buildCmd.Flags().StringVar(
		&opts.Registry.AuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	buildCmd.Flags().StringVar(
		&opts.Build.AutomotiveImageBuilder, "aib-image",
		automotivev1alpha1.DefaultAutomotiveImageBuilderImage, "AIB container image",
	)
	buildCmd.Flags().StringVar(&opts.Build.BuilderImage, "builder-image", "", "custom builder container")
	addBuilderCacheFlags(buildCmd, opts.Build)
	buildCmd.Flags().StringArrayVarP(&opts.Build.CustomDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildCmd.Flags().StringArrayVar(&opts.Build.DefineFiles, "define-file", []string{}, "load defines from YAML dictionary file (can be repeated)")
	buildCmd.Flags().StringArrayVar(&opts.Build.AIBExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildCmd.Flags().StringVar(&opts.Build.Lockfile, "lockfile", "", "Path to an AIB JSON lockfile generated by resolve")
	addGitSourceFlags(buildCmd, opts)
	buildCmd.Flags().StringVar(&opts.Build.RootPassword, "root-password", "", "set hashed root password (env:VAR or file:PATH)")
	buildCmd.Flags().StringArrayVar(&opts.Build.ExtraRepos, "extra-repo", []string{}, "extra RPM repo (workspace:path or oci:image-ref, can be repeated)")
	buildCmd.Flags().StringVar(&opts.Build.LocalRepo, "local-repo", "", "OCI image with RPM repo to use as primary package source (preferred over network repos)")
	buildCmd.Flags().StringVar(&opts.Build.Workspace, "workspace", "", "workspace name for build caching and lease forwarding")
	buildCmd.Flags().IntVar(&opts.Output.Timeout, "timeout", 60, "timeout in minutes")
	buildCmd.Flags().BoolVarP(&opts.Output.Wait, "wait", "w", true, "wait for build to complete")
	buildCmd.Flags().BoolVarP(&opts.Output.FollowLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Note: --push is optional when --disk is used (disk image becomes the output)
	// Jumpstarter flash options
	buildCmd.Flags().BoolVar(&opts.Flash.AfterBuild, "flash", false, "flash the image to device after build completes")
	buildCmd.Flags().StringVar(&opts.Flash.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	buildCmd.Flags().StringVar(&opts.Flash.LeaseDuration, "lease-duration", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	buildCmd.Flags().StringVar(&opts.Flash.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	buildCmd.Flags().StringVar(&opts.Flash.Cmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	buildCmd.Flags().StringVar(&opts.Flash.ExporterSelector, "exporter", "", "direct exporter selector for flash (alternative to --target lookup)")
	buildCmd.Flags().StringArrayVar(&opts.Flash.LeaseTags, "lease-tag", []string{}, "tag for Jumpstarter lease (key=value, can be repeated)")
	// Secure build
	buildCmd.Flags().BoolVar(&opts.Build.SecureBuild, "secure", false, "use digest-pinned tasks and locked inputs for network-isolated AIB assembly (requires taskBundleRef; OCI output requires referrer support)")
	buildCmd.Flags().StringVar(&opts.Build.TTL, "ttl", "", "time-to-live for the build (e.g. 24h, 72h, 168h); empty=server default, 0=no expiry")
	// Reproducible build
	buildCmd.Flags().BoolVar(&opts.Build.Reproducible, "reproducible", false, "save RPMs, manifest, lockfile, and task bundle for future reproduction (requires --secure)")
	buildCmd.Flags().StringVar(&opts.Build.TaskBundleRef, "task-bundle-ref", "", "digest-pinned Tekton bundle ref for reproducible rebuild (e.g. quay.io/org/tasks@sha256:abc...)")
	buildCmd.Flags().StringVar(&opts.Build.RestoreSourcesRef, "restore-sources", "", "OCI image ref from prior build — restores archived sources for exact reproducible rebuild")
	// Internal registry options
	buildCmd.Flags().BoolVar(&opts.Registry.UseInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	buildCmd.Flags().StringVar(&opts.Registry.InternalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	buildCmd.Flags().StringVar(&opts.Registry.InternalRegistryTag, "image-tag", "", "tag for internal registry image (default: bootc)")
	addS3Flags(buildCmd, opts)

	resolveCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	resolveCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	resolveCmd.Flags().StringVarP(&opts.Build.Name, "name", "n", "", "cluster operation name (default: manifest name with -resolve suffix)")
	resolveCmd.Flags().IntVar(&opts.Output.Timeout, "timeout", 30, "resolution timeout in minutes")
	resolveCmd.Flags().StringVar(&opts.Build.TTL, "ttl", "", "retention after completion (0 keeps the operation)")
	resolveCmd.Flags().StringVarP(&opts.Build.Distro, "distro", "d", "autosd", "distribution to resolve")
	resolveCmd.Flags().StringVarP(&opts.Build.Target, "target", "t", "", "target platform (default: from manifest, or qemu)")
	resolveCmd.Flags().StringVarP(&opts.Build.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	resolveCmd.Flags().StringVarP(&opts.Output.Dir, "output", "o", "", "output lockfile path (default: <manifest>.lock)")
	resolveCmd.Flags().StringVar(
		&opts.Build.AutomotiveImageBuilder, "aib-image",
		automotivev1alpha1.DefaultAutomotiveImageBuilderImage, "AIB container image",
	)
	resolveCmd.Flags().StringArrayVarP(&opts.Build.CustomDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	resolveCmd.Flags().StringArrayVar(&opts.Build.DefineFiles, "define-file", []string{}, "load defines from YAML dictionary file (can be repeated)")
	resolveCmd.Flags().StringArrayVar(&opts.Build.AIBExtraArgs, "extra-args", []string{}, "extra argument passed to AIB (can be repeated)")

	listCmd.Flags().StringVar(
		&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL (e.g. https://api.example)",
	)
	listCmd.Flags().StringVar(
		&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)
	showCmd.Flags().StringVar(
		&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL (e.g. https://api.example)",
	)
	showCmd.Flags().StringVar(
		&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)

	// disk command flags (create disk from existing container)
	diskCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	diskCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	addNotificationFlags(diskCmd, opts)
	diskCmd.Flags().StringVarP(&opts.Build.Name, "name", "n", "", "name for the build job (auto-generated if omitted)")
	diskCmd.Flags().StringVarP(&opts.Output.Dir, "output", "o", "", "download disk image to file from registry (uses --internal-registry when no --push given)")
	diskCmd.Flags().StringVar(
		&opts.Build.DiskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	diskCmd.Flags().StringVar(&opts.Build.CompressionAlgo, "compress", "gzip", "compression algorithm (gzip, xz)")
	diskCmd.Flags().StringVar(&opts.Registry.ExportOCI, "push", "", "push disk image as OCI artifact to registry")
	diskCmd.Flags().StringVar(
		&opts.Registry.AuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	diskCmd.Flags().StringVarP(&opts.Build.Distro, "distro", "d", "autosd", "distribution")
	diskCmd.Flags().StringVarP(&opts.Build.Target, "target", "t", "", "target platform (default: qemu)")
	diskCmd.Flags().StringVarP(&opts.Build.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	diskCmd.Flags().StringVar(
		&opts.Build.AutomotiveImageBuilder, "aib-image",
		automotivev1alpha1.DefaultAutomotiveImageBuilderImage, "AIB container image",
	)
	addBuilderCacheFlags(diskCmd, opts.Build)
	diskCmd.Flags().StringArrayVar(&opts.Build.AIBExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	diskCmd.Flags().IntVar(&opts.Output.Timeout, "timeout", 60, "timeout in minutes")
	diskCmd.Flags().BoolVarP(&opts.Output.Wait, "wait", "w", false, "wait for build to complete")
	diskCmd.Flags().BoolVarP(&opts.Output.FollowLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Jumpstarter flash options
	diskCmd.Flags().BoolVar(&opts.Flash.AfterBuild, "flash", false, "flash the image to device after build completes")
	diskCmd.Flags().StringVar(&opts.Flash.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	diskCmd.Flags().StringVar(&opts.Flash.LeaseDuration, "lease-duration", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	diskCmd.Flags().StringVar(&opts.Flash.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	diskCmd.Flags().StringVar(&opts.Flash.Cmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	diskCmd.Flags().StringVar(&opts.Flash.ExporterSelector, "exporter", "", "direct exporter selector for flash (alternative to --target lookup)")
	diskCmd.Flags().StringArrayVar(&opts.Flash.LeaseTags, "lease-tag", []string{}, "tag for Jumpstarter lease (key=value, can be repeated)")
	// Secure build
	diskCmd.Flags().BoolVar(&opts.Build.SecureBuild, "secure", false, "not supported for disk-only conversion; use image build or build-dev for secure builds")
	diskCmd.Flags().StringVar(&opts.Build.TTL, "ttl", "", "time-to-live for the build (e.g. 24h, 72h, 168h); empty=server default, 0=no expiry")
	diskCmd.Flags().StringVar(&opts.Build.TaskBundleRef, "task-bundle-ref", "", "digest-pinned Tekton bundle ref for reproducible rebuild (e.g. quay.io/org/tasks@sha256:abc...)")
	// Internal registry options
	diskCmd.Flags().BoolVar(&opts.Registry.UseInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	diskCmd.Flags().StringVar(&opts.Registry.InternalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	diskCmd.Flags().StringVar(&opts.Registry.InternalRegistryTag, "image-tag", "", "tag for internal registry image (default: disk)")
	addS3Flags(diskCmd, opts)

	// build-dev command flags (traditional ostree/package builds)
	buildDevCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	buildDevCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	addNotificationFlags(buildDevCmd, opts)
	buildDevCmd.Flags().StringVarP(&opts.Build.Name, "name", "n", "", "name for the ImageBuild")
	buildDevCmd.Flags().StringVarP(&opts.Build.Distro, "distro", "d", "autosd", "distribution to build")
	buildDevCmd.Flags().StringVarP(&opts.Build.Target, "target", "t", "", "target platform (default: from manifest, or qemu)")
	buildDevCmd.Flags().StringVarP(&opts.Build.Architecture, "arch", "a", opts.GetDefaultArch(), "architecture (amd64, arm64)")
	buildDevCmd.Flags().StringVar(&opts.Build.Mode, "mode", "package", "build mode: image (ostree) or package (package-based)")
	buildDevCmd.Flags().StringVar(&opts.Build.ExportFormat, "format", "", "export format: qcow2, raw, simg, etc.")
	buildDevCmd.Flags().StringVarP(&opts.Output.Dir, "output", "o", "", "download artifact to file from registry (uses --internal-registry when no --push given)")
	buildDevCmd.Flags().StringVar(&opts.Build.CompressionAlgo, "compress", "gzip", "compression algorithm (gzip, xz)")
	buildDevCmd.Flags().StringVar(&opts.Registry.ExportOCI, "push", "", "push disk image as OCI artifact to registry")
	buildDevCmd.Flags().StringVar(
		&opts.Registry.AuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	buildDevCmd.Flags().StringVar(
		&opts.Build.AutomotiveImageBuilder, "aib-image",
		automotivev1alpha1.DefaultAutomotiveImageBuilderImage, "AIB container image",
	)
	buildDevCmd.Flags().StringArrayVarP(&opts.Build.CustomDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildDevCmd.Flags().StringArrayVar(&opts.Build.DefineFiles, "define-file", []string{}, "load defines from YAML dictionary file (can be repeated)")
	buildDevCmd.Flags().StringArrayVar(&opts.Build.AIBExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildDevCmd.Flags().StringVar(&opts.Build.Lockfile, "lockfile", "", "Path to an AIB JSON lockfile generated by resolve")
	addGitSourceFlags(buildDevCmd, opts)
	buildDevCmd.Flags().StringVar(&opts.Build.RootPassword, "root-password", "", "set hashed root password (env:VAR or file:PATH)")
	buildDevCmd.Flags().StringArrayVar(&opts.Build.ExtraRepos, "extra-repo", []string{}, "extra RPM repo (workspace:path or oci:image-ref, can be repeated)")
	buildDevCmd.Flags().StringVar(&opts.Build.LocalRepo, "local-repo", "", "OCI image with RPM repo to use as primary package source (preferred over network repos)")
	buildDevCmd.Flags().StringVar(&opts.Build.Workspace, "workspace", "", "workspace name for build caching and lease forwarding")
	buildDevCmd.Flags().IntVar(&opts.Output.Timeout, "timeout", 60, "timeout in minutes")
	buildDevCmd.Flags().BoolVarP(&opts.Output.Wait, "wait", "w", false, "wait for build to complete")
	buildDevCmd.Flags().BoolVarP(&opts.Output.FollowLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Jumpstarter flash options
	buildDevCmd.Flags().BoolVar(&opts.Flash.AfterBuild, "flash", false, "flash the image to device after build completes")
	buildDevCmd.Flags().StringVar(&opts.Flash.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	buildDevCmd.Flags().StringVar(&opts.Flash.LeaseDuration, "lease-duration", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	buildDevCmd.Flags().StringVar(&opts.Flash.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	buildDevCmd.Flags().StringVar(&opts.Flash.Cmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	buildDevCmd.Flags().StringVar(&opts.Flash.ExporterSelector, "exporter", "", "direct exporter selector for flash (alternative to --target lookup)")
	buildDevCmd.Flags().StringArrayVar(&opts.Flash.LeaseTags, "lease-tag", []string{}, "tag for Jumpstarter lease (key=value, can be repeated)")
	// Secure build
	buildDevCmd.Flags().BoolVar(&opts.Build.SecureBuild, "secure", false, "use digest-pinned tasks and locked inputs for network-isolated AIB assembly (requires taskBundleRef; OCI output requires referrer support)")
	buildDevCmd.Flags().StringVar(&opts.Build.TTL, "ttl", "", "time-to-live for the build (e.g. 24h, 72h, 168h); empty=server default, 0=no expiry")
	// Reproducible build
	buildDevCmd.Flags().BoolVar(&opts.Build.Reproducible, "reproducible", false, "save RPMs, manifest, lockfile, and task bundle for future reproduction (requires --secure)")
	buildDevCmd.Flags().StringVar(&opts.Build.TaskBundleRef, "task-bundle-ref", "", "digest-pinned Tekton bundle ref for reproducible rebuild (e.g. quay.io/org/tasks@sha256:abc...)")
	buildDevCmd.Flags().StringVar(&opts.Build.RestoreSourcesRef, "restore-sources", "", "OCI image ref from prior build — restores archived sources for exact reproducible rebuild")
	// Internal registry options
	buildDevCmd.Flags().BoolVar(&opts.Registry.UseInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	buildDevCmd.Flags().StringVar(&opts.Registry.InternalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	buildDevCmd.Flags().StringVar(&opts.Registry.InternalRegistryTag, "image-tag", "", "tag for internal registry image (default: disk)")
	addS3Flags(buildDevCmd, opts)

	// logs command flags
	logsCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	logsCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	logsCmd.Flags().IntVar(&opts.Output.Timeout, "timeout", 60, "timeout in minutes")

	// download command flags
	downloadCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	downloadCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	downloadCmd.Flags().StringVarP(&opts.Output.Dir, "output", "o", "", "destination file or directory for the artifact")

	// token command flags
	tokenCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	tokenCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")

	// delete command flags
	deleteCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	deleteCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")

	// cancel command flags
	cancelCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	cancelCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")

	// flash command flags
	flashCmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "REST API server base URL")
	flashCmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	addNotificationFlags(flashCmd, opts)
	flashCmd.Flags().StringVar(&opts.Flash.JumpstarterClient, "client", "", "path to Jumpstarter client config file (auto-detected if omitted)")
	flashCmd.Flags().StringVarP(&opts.Flash.Name, "name", "n", "", "name for the flash job (auto-generated if omitted)")
	flashCmd.Flags().StringVarP(&opts.Build.Target, "target", "t", "", "target platform for exporter lookup")
	flashCmd.Flags().StringVar(&opts.Flash.ExporterSelector, "exporter", "", "direct exporter selector (alternative to --target)")
	flashCmd.Flags().StringVar(&opts.Flash.LeaseDuration, "lease-duration", "03:00:00", "device lease duration (HH:MM:SS)")
	flashCmd.Flags().StringVar(&opts.Flash.LeaseName, "lease", "", "existing Jumpstarter lease name (mutually exclusive with --lease-duration)")
	flashCmd.Flags().StringVar(&opts.Flash.Cmd, "flash-cmd", "", "override flash command (default: from OperatorConfig target mapping)")
	flashCmd.Flags().StringArrayVar(&opts.Flash.LeaseTags, "lease-tag", []string{}, "tag for Jumpstarter lease (key=value, can be repeated)")
	flashCmd.Flags().StringVar(
		&opts.Registry.AuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for OCI image pull authentication (takes precedence over env vars and auto-discovery)",
	)
	flashCmd.Flags().BoolVarP(&opts.Output.FollowLogs, "follow", "f", false, "follow flash logs (shows full log output instead of progress bar)")
	flashCmd.Flags().BoolVarP(&opts.Output.Wait, "wait", "w", true, "wait for flash to complete")
	inspectCmd := newInspectCmd(opts)
	inspectCmd.Flags().StringVar(
		&opts.Registry.AuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for registry authentication",
	)
	inspectCmd.Flags().StringVarP(&opts.Output.Dir, "output-dir", "o", "", "download referrer artifacts (manifest, lockfile, RPMs) to this directory")

	// Sealed operation shared flags
	addSealedFlags(prepareResealCmd, opts, defaultServer)
	addSealedFlags(resealCmd, opts, defaultServer)
	addSealedFlags(extractForSigningCmd, opts, defaultServer)
	addSealedFlags(injectSignedCmd, opts, defaultServer)
	injectSignedCmd.Flags().StringVar(&opts.Sealed.SignedRef, "signed", "", "Signed artifact ref for inject-signed")

	cmd.AddCommand(
		buildCmd,
		resolveCmd,
		diskCmd,
		buildDevCmd,
		listCmd,
		showCmd,
		downloadCmd,
		logsCmd,
		tokenCmd,
		deleteCmd,
		cancelCmd,
		flashCmd,
		inspectCmd,
		prepareResealCmd,
		resealCmd,
		extractForSigningCmd,
		injectSignedCmd,
	)

	return cmd
}

// pflag initializes each shared output field as commands register their flags.
// Restore the invoked command's own defaults when the user did not set them.
func applyCommandOutputDefaults(cmd *cobra.Command) error {
	for _, name := range []string{"timeout", "wait", "follow"} {
		flag := cmd.Flags().Lookup(name)
		if flag == nil || flag.Changed {
			continue
		}
		if err := flag.Value.Set(flag.DefValue); err != nil {
			return fmt.Errorf("restore default for --%s: %w", name, err)
		}
	}
	return nil
}

func newResolveCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "resolve <manifest.aib.yml>",
		Short: "Resolve manifest dependencies into an AIB lockfile",
		Long: `Resolve manifest dependencies on the cluster with the selected AIB container image.

The generated lockfile records exact RPM URLs and checksums and can be passed
to caib image build-dev with --lockfile. The CLI downloads the resulting lockfile.`,
		Example: `  caib image resolve manifest.aib.yml --arch arm64 -o manifest.aib.lock
  caib image build-dev manifest.aib.yml --arch arm64 --lockfile manifest.aib.lock`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunResolve,
	}
}

func addNotificationFlags(cmd *cobra.Command, opts Options) {
	cmd.Flags().StringVar(&opts.Callback.ExternalID, "external-id", "", "external correlation value included in operation status and webhook events")
	cmd.Flags().StringVar(&opts.Callback.URL, "callback-url", "", "URL for the signed terminal webhook (HTTPS required unless webhookNotifications.allowHTTP is enabled)")
	cmd.Flags().StringVar(&opts.Callback.SecretFile, "callback-secret-file", "", "file containing the 32 to 4096 byte webhook HMAC secret")
}

func newBuildCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "build <manifest.aib.yml>",
		Short: "Build bootc container image with optional disk image",
		Long: `Build creates a bootc container image from an AIB manifest.

Bootc images are immutable, atomically updatable OS images based on
container technology. This is the recommended approach for production.
With --git-url, the manifest path is relative to the repository root.

Examples:
  # Build and push container to registry
  caib image build manifest.aib.yml --push quay.io/org/my-os:v1

  # Build container + create disk image
  caib image build manifest.aib.yml --push quay.io/org/my-os:v1 --disk -o disk.qcow2

  # Build a manifest from a Git commit (its adjacent <manifest>.lock is used when present)
  caib image build images/my-os.aib.yml --git-url https://git.example.com/team/os.git --git-ref main --push quay.io/org/my-os:v1`,
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
With --git-url, the manifest path is relative to the repository root.

Examples:
  # Ostree-based image
  caib image build-dev manifest.aib.yml --mode image --format qcow2 -o disk.qcow2

  # Package-based image
  caib image build-dev manifest.aib.yml --mode package --format raw -o disk.raw

  # Build development image from Git
  caib image build-dev images/dev.aib.yml --git-url https://git.example.com/team/os.git --git-ref main --mode package -o disk.raw`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunBuildDev,
	}
}

func newFlashCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "flash <oci-registry-reference|catalog-image-name>",
		Short: "Flash a disk image to hardware via Jumpstarter",
		Long: `Flash a disk image from an OCI registry or catalog name to a hardware device using Jumpstarter.

A name without '/' is treated as a CatalogImage (for example qa-ebbr). The API
resolves it to a digest-pinned registry URL. A value containing '/' is an OCI
reference (quay.io/org/disk:v1).

This command connects to a Jumpstarter exporter to flash the specified disk image
onto physical hardware. The Jumpstarter client config is auto-detected from
~/.config/jumpstarter/ (or $JMP_CLIENT_CONFIG_HOME), or can be specified with --client.

If --target and --exporter are both omitted, the target is auto-detected from the
OCI image manifest annotations (set by the operator during image push).

Examples:
  # Flash a catalog head by name
  caib image flash qa-ebbr --target j784s4evm

  # Flash with auto-detected target (from image annotations)
  caib image flash quay.io/org/disk:v1

  # Flash with explicit target
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
  caib image show my-build --output-format json`,
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

func newTokenCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "token <build-name>",
		Short: "Request a fresh registry token for an internal-registry build",
		Long: `Request a fresh, short-lived registry token for a completed build that
used the internal OpenShift registry (--internal-registry).

The token is valid for 4 hours and can be used with podman, skopeo, or
any OCI-compatible tool to pull images from the internal registry.

Examples:
  # Get a token for a completed build
  caib image token my-build

  # Use the printed podman login command to authenticate
  echo '<token>' | podman login <registry> --username serviceaccount --password-stdin

  # Then pull the image
  podman pull <image-ref>`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunToken,
	}
}

func newDeleteCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <build-name>",
		Short: "Delete an ImageBuild and its associated resources",
		Long: `Delete removes an ImageBuild and all its associated Kubernetes resources
(PipelineRuns, TaskRuns, PVCs, Secrets). If the build used the internal
registry (--internal-registry), the build's ImageStream tags are removed.
The ImageStream itself is deleted only if no other tags remain in it.

You can only delete builds that you created.

Examples:
  # Delete a completed build
  caib image delete my-build

  # Delete a build (including internal registry images)
  caib image delete my-internal-build`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunDelete,
	}
}

func newCancelCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "cancel <build-name>",
		Short: "Cancel an in-progress build",
		Long: `Cancel stops an in-progress build by cancelling its Tekton PipelineRun.
The ImageBuild resource is preserved so you can inspect its logs and status.

Only builds in Pending, Uploading, or Building phase can be cancelled.
You can only cancel builds that you created.

Examples:
  # Cancel a running build
  caib image cancel my-build

  # List builds first, then cancel one
  caib image list
  caib image cancel <build-name>`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunCancel,
	}
}

func newInspectCmd(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <oci-registry-reference>",
		Short: "Show build provenance and reproducibility info for an OCI artifact",
		Long: `Inspect reads OCI manifest annotations and referrer artifacts to display
build provenance information: distro, target, architecture, builder versions,
and the exact command to reproduce the build.

If --output-dir is given, referrer artifacts (AIB manifest, lockfile, RPM archive,
osbuild manifest) are downloaded to the specified directory.

Examples:
  # Show build provenance
  caib image inspect quay.io/org/my-os:v1

  # Show provenance and download artifacts for reproduction
  caib image inspect quay.io/org/my-os:v1 -o ./rebuild/`,
		Args: cobra.ExactArgs(1),
		Run:  opts.RunInspect,
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

func addS3Flags(cmd *cobra.Command, opts Options) {
	cmd.Flags().StringVar(&opts.S3.Bucket, "s3-bucket", "", "S3 bucket name for artifact upload")
	cmd.Flags().StringVar(&opts.S3.Prefix, "s3-prefix", "", "S3 key prefix (path within bucket)")
	cmd.Flags().StringVar(&opts.S3.Region, "s3-region", "", "S3 region (defaults to us-east-1 if not specified)")
	cmd.Flags().StringVar(&opts.S3.Endpoint, "s3-endpoint", "", "Custom S3 endpoint URL (for MinIO/Ceph)")
	cmd.Flags().StringVar(&opts.S3.AccessKeyID, "s3-access-key-id", "", "S3 access key ID (env: AWS_ACCESS_KEY_ID)")
	cmd.Flags().StringVar(&opts.S3.SecretAccessKey, "s3-secret-access-key", "", "S3 secret access key (env: AWS_SECRET_ACCESS_KEY)")
	cmd.Flags().StringVar(&opts.S3.CredentialsSecret, "s3-credentials-secret", "", "Existing K8s secret with S3 credentials")
	cmd.Flags().BoolVar(&opts.S3.Insecure, "s3-insecure", false, "Skip TLS verification for S3 endpoint")
}

func addSealedFlags(cmd *cobra.Command, opts Options, defaultServer string) {
	cmd.Flags().StringVar(&opts.Connection.ServerURL, "server", defaultServer, "Build API server URL")
	cmd.Flags().StringVar(&opts.Connection.AuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	cmd.Flags().StringVar(&opts.Sealed.InputRef, "input", "", "Input/source container or artifact ref")
	cmd.Flags().StringVar(&opts.Sealed.OutputRef, "output", "", "Output container or artifact ref")
	cmd.Flags().StringVar(
		&opts.Registry.AuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for registry authentication (takes precedence over env vars and auto-discovery)",
	)
	cmd.Flags().StringVar(
		&opts.Build.AutomotiveImageBuilder, "aib-image",
		automotivev1alpha1.DefaultAutomotiveImageBuilderImage, "AIB container image",
	)
	cmd.Flags().StringVar(&opts.Sealed.BuilderImage, "builder-image", "", "Builder container image (overrides --arch default)")
	cmd.Flags().StringVar(&opts.Sealed.Architecture, "arch", "", "Target architecture for default builder image (amd64, arm64); auto-detected if not set")
	cmd.Flags().StringArrayVar(&opts.Build.AIBExtraArgs, "extra-args", nil, "Extra arguments to pass to AIB (repeatable)")
	cmd.Flags().BoolVarP(&opts.Output.Wait, "wait", "w", false, "Wait for completion")
	cmd.Flags().BoolVarP(&opts.Output.FollowLogs, "follow", "f", true, "Stream task logs")
	cmd.Flags().StringVar(&opts.Sealed.KeySecret, "key-secret", "", "Name of existing cluster secret containing sealing key (data key 'private-key')")
	cmd.Flags().StringVar(&opts.Sealed.KeyPasswordSecret, "key-password-secret", "", "Name of existing cluster secret containing key password (data key 'password')")
	cmd.Flags().StringVar(&opts.Sealed.KeyFile, "key", "", "Path to local PEM key file (uploaded to cluster automatically)")
	cmd.Flags().StringVar(&opts.Sealed.KeyPassword, "passwd", "", "Password for encrypted key file (used with --key)")
	cmd.Flags().IntVar(&opts.Output.Timeout, "timeout", 120, "Timeout in minutes")
}

func addBuilderCacheFlags(cmd *cobra.Command, build *commandopts.Build) {
	cmd.Flags().BoolVar(&build.RebuildBuilder, "rebuild-builder", false, "force rebuild of the bootc builder image")
	cmd.Flags().StringVar(&build.BuilderCachePolicy, "builder-cache-policy", "validate", "builder cache policy: validate freshness online, or reuse a cached helper without depsolving (cache misses still build; --rebuild-builder overrides)")
}
