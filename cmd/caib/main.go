// Package main provides the caib CLI tool for interacting with the automotive image build system.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"gopkg.in/yaml.v3"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/catalog"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	archAMD64   = "amd64"
	archARM64   = "arm64"
	phaseFailed = "Failed"
)

// getDefaultArch returns the current system architecture in caib format
func getDefaultArch() string {
	switch runtime.GOARCH {
	case archAMD64:
		return archAMD64
	case archARM64:
		return archARM64
	default:
		return archAMD64
	}
}

var (
	serverURL              string
	manifest               string
	buildName              string
	distro                 string
	target                 string
	architecture           string
	exportFormat           string
	mode                   string
	automotiveImageBuilder string
	storageClass           string
	outputDir              string
	timeout                int
	waitForBuild           bool
	customDefs             []string
	aibExtraArgs           []string
	followLogs             bool
	version                string
	compressionAlgo        string
	authToken              string

	containerPush  string
	buildDiskImage bool
	diskFormat     string
	exportOCI      string
	builderImage   string

	containerRef string

	// Flash options
	flashAfterBuild   bool
	jumpstarterClient string
	flashName         string
	exporterSelector  string
	leaseDuration     string
)

// createBuildAPIClient creates a build API client with authentication token from flags or kubeconfig
// It will attempt OIDC re-authentication if token is missing or expired
func createBuildAPIClient(serverURL string, authToken *string) (*buildapiclient.Client, error) {
	ctx := context.Background()

	explicitToken := strings.TrimSpace(*authToken) != "" || os.Getenv("CAIB_TOKEN") != ""

	// If no explicit token, try OIDC if config is available
	if !explicitToken {
		token, didAuth, err := auth.GetTokenWithReauth(ctx, serverURL, "")
		if err != nil {
			// OIDC is configured but failed - don't silently fall back to kubeconfig
			// This indicates a real authentication failure that should be reported
			// Falling back could authenticate with an unexpected identity
			fmt.Printf("Error: OIDC authentication failed: %v\n", err)
			// Only try kubeconfig as last resort, but warn the user
			fmt.Println("Attempting kubeconfig fallback (this may use a different identity)")
			if tok, err := loadTokenFromKubeconfig(); err == nil && strings.TrimSpace(tok) != "" {
				*authToken = tok
			} else {
				// No kubeconfig available either - return error
				return nil, fmt.Errorf("OIDC authentication failed and no kubeconfig token available: %w", err)
			}
		} else if token != "" {
			// OIDC succeeded
			*authToken = token
			if didAuth {
				fmt.Println("OIDC authentication successful")
			}
		} else {
			// OIDC not configured (no error, no token) - safe to fall back to kubeconfig
			if tok, err := loadTokenFromKubeconfig(); err == nil && strings.TrimSpace(tok) != "" {
				*authToken = tok
			}
		}
	} else {
		// Token was explicitly provided, use it (but still try kubeconfig if empty)
		if strings.TrimSpace(*authToken) == "" {
			if tok, err := loadTokenFromKubeconfig(); err == nil && strings.TrimSpace(tok) != "" {
				*authToken = tok
			}
		}
	}

	var opts []buildapiclient.Option
	if strings.TrimSpace(*authToken) != "" {
		opts = append(opts, buildapiclient.WithAuthToken(strings.TrimSpace(*authToken)))
	}

	// Configure TLS
	// Check for custom CA certificate
	if caCertFile := os.Getenv("SSL_CERT_FILE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	} else if caCertFile := os.Getenv("REQUESTS_CA_BUNDLE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	} else {
		if strings.EqualFold(os.Getenv("CAIB_INSECURE_TLS"), "true") || os.Getenv("CAIB_INSECURE_TLS") == "1" {
			opts = append(opts, buildapiclient.WithInsecureTLS())
		}
	}

	return buildapiclient.New(serverURL, opts...)
}

// executeWithReauth executes an API call and automatically retries with re-authentication on auth errors
func executeWithReauth(serverURL string, authToken *string, fn func(*buildapiclient.Client) error) error {
	ctx := context.Background()

	client, err := createBuildAPIClient(serverURL, authToken)
	if err != nil {
		return err
	}

	err = fn(client)
	if err == nil {
		return nil
	}

	if !auth.IsAuthError(err) {
		return err
	}

	// Auth error - try to re-authenticate
	fmt.Println("Token is expired, triggering re-authentication")

	newToken, _, err := auth.GetTokenWithReauth(ctx, serverURL, *authToken)
	if err != nil {
		return fmt.Errorf("re-authentication failed: %w", err)
	}

	// Update token and retry
	*authToken = newToken
	client, err = createBuildAPIClient(serverURL, authToken)
	if err != nil {
		return err
	}

	fmt.Println("Re-authentication successful, retrying...")
	return fn(client)
}

// extractRegistryCredentials extracts registry URL and returns registry URL and credentials from env vars
func extractRegistryCredentials(primaryRef, secondaryRef string) (string, string, string) {
	// Get credentials from environment variables only
	username := os.Getenv("REGISTRY_USERNAME")
	password := os.Getenv("REGISTRY_PASSWORD")

	// Determine the reference to use for URL extraction
	ref := primaryRef
	if ref == "" {
		ref = secondaryRef
	}

	// If no reference, return empty
	if ref == "" {
		return "", username, password
	}

	// Warn if credentials missing (will fall back to Docker/Podman auth files)
	if username == "" || password == "" {
		fmt.Println("Warning: No registry credentials provided via environment variables.")
		fmt.Println("Will attempt to use Docker/Podman auth files as fallback.")
	}

	// Extract registry URL from reference
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		return parts[0], username, password
	}
	return "docker.io", username, password
}

// validateRegistryCredentials validates registry credentials and returns an error for partial credentials
func validateRegistryCredentials(registryURL, username, password string) error {
	// If no registry URL, no credentials needed
	if registryURL == "" {
		return nil
	}

	// Both username and password must be provided together, or neither
	if (username == "") != (password == "") {
		if username == "" {
			return fmt.Errorf("REGISTRY_PASSWORD is set but REGISTRY_USERNAME is missing")
		}
		return fmt.Errorf("REGISTRY_USERNAME is set but REGISTRY_PASSWORD is missing")
	}

	return nil
}

func validateOutputRequiresPush(output, pushRef, flagName string) {
	if output == "" {
		return
	}
	if pushRef == "" {
		handleError(fmt.Errorf("--output requires %s to download from registry", flagName))
	}
}

func downloadOCIArtifactIfRequested(output, exportOCI, registryUsername, registryPassword string) {
	if output == "" {
		return
	}
	if err := pullOCIArtifact(exportOCI, output, registryUsername, registryPassword); err != nil {
		handleError(fmt.Errorf("failed to download OCI artifact: %w", err))
	}
}
func main() {
	rootCmd := &cobra.Command{
		Use:     "caib",
		Short:   "Cloud Automotive Image Builder",
		Version: version,
	}

	rootCmd.InitDefaultVersionFlag()
	rootCmd.SetVersionTemplate("caib version: {{.Version}}\n")

	// Main build command (bootc - the default, future-focused approach)
	buildCmd := &cobra.Command{
		Use:   "build <manifest.aib.yml>",
		Short: "Build bootc container image with optional disk image",
		Long: `Build creates a bootc container image from an AIB manifest.

Bootc images are immutable, atomically updatable OS images based on
container technology. This is the recommended approach for production.

Examples:
  # Build and push container to registry
  caib build manifest.aib.yml --push quay.io/org/my-os:v1

  # Build container + create disk image
  caib build manifest.aib.yml --push quay.io/org/my-os:v1 --disk -o disk.qcow2`,
		Args: cobra.ExactArgs(1),
		Run:  runBuild,
	}

	// Disk command - create disk from existing container
	diskCmd := &cobra.Command{
		Use:   "disk <container-ref>",
		Short: "Create disk image from existing bootc container",
		Long: `Create a disk image from an existing bootc container in a registry.

This uses 'aib to-disk-image' to convert a bootc container to a disk
image that can be flashed onto hardware.

Examples:
  # Create disk image from container
  caib disk quay.io/org/my-os:v1 -o disk.qcow2 --format qcow2

  # Push disk as OCI artifact instead of downloading
  caib disk quay.io/org/my-os:v1 --push quay.io/org/my-disk:v1`,
		Args: cobra.ExactArgs(1),
		Run:  runDisk,
	}

	// Dev build command (traditional ostree/package-based)
	buildDevCmd := &cobra.Command{
		Use:   "build-dev <manifest.aib.yml>",
		Short: "Build disk image for development (ostree or package-based)",
		Long: `Build a disk image using ostree or package-based mode for development workflows.

This creates standalone disk images without bootc container integration.

Examples:
  # Ostree-based image
  caib build-dev manifest.aib.yml --mode image --format qcow2 -o disk.qcow2

  # Package-based image
  caib build-dev manifest.aib.yml --mode package --format raw -o disk.raw`,
		Args: cobra.ExactArgs(1),
		Run:  runBuildDev,
	}

	// Deprecated aliases (hidden but functional for backwards compatibility)
	buildBootcAliasCmd := &cobra.Command{
		Use:        "build-bootc <manifest.aib.yml>",
		Short:      "Build bootc container image (deprecated: use 'build' instead)",
		Args:       cobra.ExactArgs(1),
		Run:        runBuild,
		Deprecated: "use 'build' instead (bootc is now the default)",
		Hidden:     true,
	}

	buildLegacyAliasCmd := &cobra.Command{
		Use:        "build-legacy <manifest.aib.yml>",
		Short:      "Build disk image (deprecated: use 'build-dev' instead)",
		Args:       cobra.ExactArgs(1),
		Run:        runBuildDev,
		Deprecated: "use 'build-dev' instead",
		Hidden:     true,
	}

	buildTraditionalAliasCmd := &cobra.Command{
		Use:        "build-traditional <manifest.aib.yml>",
		Short:      "Build traditional disk image (deprecated: use 'build-dev' instead)",
		Args:       cobra.ExactArgs(1),
		Run:        runBuildDev,
		Deprecated: "use 'build-dev' instead",
		Hidden:     true,
	}

	// Flash command - flash a disk image to hardware via Jumpstarter
	flashCmd := &cobra.Command{
		Use:   "flash <oci-registry-reference>",
		Short: "Flash a disk image to hardware via Jumpstarter",
		Long: `Flash a disk image from an OCI registry to a hardware device using Jumpstarter.

This command connects to a Jumpstarter exporter to flash the specified disk image
onto physical hardware. Requires a Jumpstarter client configuration file.

Examples:
  # Flash using target platform lookup
  caib flash quay.io/org/disk:v1 --client ~/.jumpstarter/client.yaml --target j784s4evm

  # Flash with explicit exporter selector
  caib flash quay.io/org/disk:v1 --client ~/.jumpstarter/client.yaml --exporter "board-type=j784s4evm"`,
		Args: cobra.ExactArgs(1),
		Run:  runFlash,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List existing ImageBuilds",
		Run:   runList,
	}

	// build command flags (bootc - the default)
	buildCmd.Flags().StringVar(&serverURL, "server", os.Getenv("CAIB_SERVER"), "REST API server base URL")
	buildCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	buildCmd.Flags().StringVarP(&buildName, "name", "n", "", "name for the ImageBuild (auto-generated if omitted)")
	buildCmd.Flags().StringVarP(&distro, "distro", "d", "autosd", "distribution to build")
	buildCmd.Flags().StringVarP(&target, "target", "t", "qemu", "target platform")
	buildCmd.Flags().StringVarP(&architecture, "arch", "a", getDefaultArch(), "architecture (amd64, arm64)")
	buildCmd.Flags().StringVar(&containerPush, "push", "", "push bootc container to registry (optional if --disk is used)")
	buildCmd.Flags().BoolVar(&buildDiskImage, "disk", false, "also build disk image from container")
	buildCmd.Flags().StringVarP(&outputDir, "output", "o", "", "download disk image to file from registry (implies --disk; requires --push-disk)")
	buildCmd.Flags().StringVar(
		&diskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	buildCmd.Flags().StringVar(&compressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	buildCmd.Flags().StringVar(&exportOCI, "push-disk", "", "push disk image as OCI artifact to registry")
	buildCmd.Flags().StringVar(
		&automotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	buildCmd.Flags().StringVar(&builderImage, "builder-image", "", "custom builder container")
	buildCmd.Flags().StringVar(&storageClass, "storage-class", "", "Kubernetes storage class for build workspace")
	buildCmd.Flags().StringArrayVarP(&customDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildCmd.Flags().StringArrayVar(&aibExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildCmd.Flags().IntVar(&timeout, "timeout", 60, "timeout in minutes")
	buildCmd.Flags().BoolVarP(&waitForBuild, "wait", "w", false, "wait for build to complete")
	buildCmd.Flags().BoolVarP(&followLogs, "follow", "f", true, "follow build logs")
	// Note: --push is optional when --disk is used (disk image becomes the output)
	// Jumpstarter flash options
	buildCmd.Flags().BoolVar(&flashAfterBuild, "flash", false, "flash the image to device after build completes")
	buildCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required for --flash)")
	buildCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration for flash (HH:MM:SS)")

	listCmd.Flags().StringVar(
		&serverURL, "server", os.Getenv("CAIB_SERVER"), "REST API server base URL (e.g. https://api.example)",
	)
	listCmd.Flags().StringVar(
		&authToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)

	// disk command flags (create disk from existing container)
	diskCmd.Flags().StringVar(&serverURL, "server", os.Getenv("CAIB_SERVER"), "REST API server base URL")
	diskCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	diskCmd.Flags().StringVarP(&buildName, "name", "n", "", "name for the build job (auto-generated if omitted)")
	diskCmd.Flags().StringVarP(&outputDir, "output", "o", "", "download disk image to file from registry (requires --push)")
	diskCmd.Flags().StringVar(
		&diskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	diskCmd.Flags().StringVar(&compressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	diskCmd.Flags().StringVar(&exportOCI, "push", "", "push disk image as OCI artifact to registry")
	diskCmd.Flags().StringVarP(&distro, "distro", "d", "autosd", "distribution")
	diskCmd.Flags().StringVarP(&target, "target", "t", "qemu", "target platform")
	diskCmd.Flags().StringVarP(&architecture, "arch", "a", getDefaultArch(), "architecture (amd64, arm64)")
	diskCmd.Flags().StringVar(
		&automotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	diskCmd.Flags().StringVar(&storageClass, "storage-class", "", "Kubernetes storage class")
	diskCmd.Flags().StringArrayVar(&aibExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	diskCmd.Flags().IntVar(&timeout, "timeout", 60, "timeout in minutes")
	diskCmd.Flags().BoolVarP(&waitForBuild, "wait", "w", false, "wait for build to complete")
	diskCmd.Flags().BoolVarP(&followLogs, "follow", "f", true, "follow build logs")
	// Jumpstarter flash options
	diskCmd.Flags().BoolVar(&flashAfterBuild, "flash", false, "flash the image to device after build completes")
	diskCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required for --flash)")
	diskCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration for flash (HH:MM:SS)")

	// build-dev command flags (traditional ostree/package builds)
	buildDevCmd.Flags().StringVar(&serverURL, "server", os.Getenv("CAIB_SERVER"), "REST API server base URL")
	buildDevCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	buildDevCmd.Flags().StringVarP(&buildName, "name", "n", "", "name for the ImageBuild")
	buildDevCmd.Flags().StringVarP(&distro, "distro", "d", "autosd", "distribution to build")
	buildDevCmd.Flags().StringVarP(&target, "target", "t", "qemu", "target platform")
	buildDevCmd.Flags().StringVarP(&architecture, "arch", "a", getDefaultArch(), "architecture (amd64, arm64)")
	buildDevCmd.Flags().StringVar(&mode, "mode", "package", "build mode: image (ostree) or package (package-based)")
	buildDevCmd.Flags().StringVar(&exportFormat, "format", "", "export format: qcow2, raw, simg, etc.")
	buildDevCmd.Flags().StringVarP(&outputDir, "output", "o", "", "download artifact to file from registry (requires --push)")
	buildDevCmd.Flags().StringVar(&compressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	buildDevCmd.Flags().StringVar(&exportOCI, "push", "", "push disk image as OCI artifact to registry")
	buildDevCmd.Flags().StringVar(
		&automotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	buildDevCmd.Flags().StringVar(&storageClass, "storage-class", "", "Kubernetes storage class")
	buildDevCmd.Flags().StringArrayVarP(&customDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildDevCmd.Flags().StringArrayVar(&aibExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildDevCmd.Flags().IntVar(&timeout, "timeout", 60, "timeout in minutes")
	buildDevCmd.Flags().BoolVarP(&waitForBuild, "wait", "w", false, "wait for build to complete")
	buildDevCmd.Flags().BoolVarP(&followLogs, "follow", "f", true, "follow build logs")
	// Jumpstarter flash options
	buildDevCmd.Flags().BoolVar(&flashAfterBuild, "flash", false, "flash the image to device after build completes")
	buildDevCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required for --flash)")
	buildDevCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration for flash (HH:MM:SS)")

	// flash command flags
	flashCmd.Flags().StringVar(&serverURL, "server", os.Getenv("CAIB_SERVER"), "REST API server base URL")
	flashCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	flashCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required)")
	flashCmd.Flags().StringVarP(&flashName, "name", "n", "", "name for the flash job (auto-generated if omitted)")
	flashCmd.Flags().StringVarP(&target, "target", "t", "", "target platform for exporter lookup")
	flashCmd.Flags().StringVar(&exporterSelector, "exporter", "", "direct exporter selector (alternative to --target)")
	flashCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration (HH:MM:SS)")
	flashCmd.Flags().BoolVarP(&followLogs, "follow", "f", true, "follow flash logs")
	flashCmd.Flags().BoolVarP(&waitForBuild, "wait", "w", true, "wait for flash to complete")
	_ = flashCmd.MarkFlagRequired("client")

	// Add all commands
	rootCmd.AddCommand(buildCmd, diskCmd, buildDevCmd, listCmd, flashCmd, catalog.NewCatalogCmd())
	// Add deprecated aliases for backwards compatibility
	rootCmd.AddCommand(buildBootcAliasCmd, buildLegacyAliasCmd, buildTraditionalAliasCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runBuild handles the main 'build' command (bootc builds)
func runBuild(_ *cobra.Command, args []string) {
	ctx := context.Background()
	manifest = args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER env)"))
	}
	validateOutputRequiresPush(outputDir, exportOCI, "--push")

	// Auto-generate build name if not provided
	if buildName == "" {
		base := strings.TrimSuffix(filepath.Base(manifest), ".aib.yml")
		base = strings.TrimSuffix(base, ".yml")
		buildName = fmt.Sprintf("%s-%s", base, time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	}

	// Validate: if --output is specified, --disk must also be specified
	if outputDir != "" && !buildDiskImage {
		buildDiskImage = true // imply --disk when --output is specified
	}
	validateOutputRequiresPush(outputDir, exportOCI, "--push-disk")

	// Validate: --push is required unless we're building a disk image
	// (disk image becomes the output, so container push is optional)
	if containerPush == "" && !buildDiskImage {
		err := fmt.Errorf(
			"--push is required when not building a disk image " +
				"(use --disk or --output to create a disk image without pushing the container)",
		)
		handleError(err)
	}

	// Note: diskFormat can be empty - AIB will default to raw (or infer from output filename extension)

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
		handleError(err)
	}

	manifestBytes, err := os.ReadFile(manifest)
	if err != nil {
		handleError(fmt.Errorf("error reading manifest: %w", err))
	}

	// Extract registry URL and credentials
	effectiveRegistryURL, registryUsername, registryPassword := extractRegistryCredentials(containerPush, exportOCI)

	// Validate credentials (error on partial credentials)
	if err := validateRegistryCredentials(effectiveRegistryURL, registryUsername, registryPassword); err != nil {
		handleError(err)
	}

	req := buildapitypes.BuildRequest{
		Name:                   buildName,
		Manifest:               string(manifestBytes),
		ManifestFileName:       filepath.Base(manifest),
		Distro:                 buildapitypes.Distro(distro),
		Target:                 buildapitypes.Target(target),
		Architecture:           buildapitypes.Architecture(architecture),
		ExportFormat:           buildapitypes.ExportFormat(diskFormat),
		Mode:                   buildapitypes.ModeBootc,
		AutomotiveImageBuilder: automotiveImageBuilder,
		StorageClass:           storageClass,
		CustomDefs:             customDefs,
		AIBExtraArgs:           aibExtraArgs,
		Compression:            compressionAlgo,
		ContainerPush:          containerPush,
		BuildDiskImage:         buildDiskImage,
		ExportOCI:              exportOCI,
		BuilderImage:           builderImage,
	}

	// Add flash configuration if enabled
	if flashAfterBuild {
		// Flash requires a disk image pushed to a registry
		if exportOCI == "" {
			handleError(fmt.Errorf("cannot enable --flash without exporting a disk image (--push-disk)"))
		}
		if jumpstarterClient == "" {
			handleError(fmt.Errorf("--flash requires --client to specify Jumpstarter client config file"))
		}
		clientConfigBytes, err := os.ReadFile(jumpstarterClient)
		if err != nil {
			handleError(fmt.Errorf("failed to read Jumpstarter client config: %w", err))
		}
		req.FlashEnabled = true
		req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientConfigBytes)
		req.FlashLeaseDuration = leaseDuration
	}

	if effectiveRegistryURL != "" && registryUsername != "" && registryPassword != "" {
		req.RegistryCredentials = &buildapitypes.RegistryCredentials{
			Enabled:     true,
			AuthType:    "username-password",
			RegistryURL: effectiveRegistryURL,
			Username:    registryUsername,
			Password:    registryPassword,
		}
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)

	// Handle local file uploads if needed
	localRefs, err := findLocalFileReferences(string(manifestBytes))
	if err != nil {
		handleError(fmt.Errorf("manifest file reference error: %w", err))
	}
	if len(localRefs) > 0 {
		handleFileUploads(ctx, api, resp.Name, localRefs)
	}

	if waitForBuild || followLogs || outputDir != "" || flashAfterBuild {
		waitForBuildCompletion(ctx, api, resp.Name)
	}

	// Show push locations after successful build completion
	if containerPush != "" {
		fmt.Printf("Container image pushed to: %s\n", containerPush)
	}
	if exportOCI != "" {
		fmt.Printf("Disk image pushed to: %s\n", exportOCI)
	}

	downloadOCIArtifactIfRequested(outputDir, exportOCI, registryUsername, registryPassword)

	// Note: When flashAfterBuild is enabled, flash config is sent with the build request
	// and the controller handles flashing after push. The waitForBuildCompletion above
	// will wait until the full pipeline (including flash) completes.
}

func runDisk(_ *cobra.Command, args []string) {
	ctx := context.Background()
	containerRef = args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER env)"))
	}

	// Validate: need either --output or --push
	if outputDir == "" && exportOCI == "" {
		handleError(fmt.Errorf("either --output or --push is required"))
	}
	validateOutputRequiresPush(outputDir, exportOCI, "--push")

	// Auto-generate build name if not provided
	if buildName == "" {
		// Extract image name from container ref for the build name
		parts := strings.Split(containerRef, "/")
		imagePart := parts[len(parts)-1]
		imagePart = strings.Split(imagePart, ":")[0] // remove tag
		buildName = fmt.Sprintf("disk-%s-%s", imagePart, time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	}

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
		handleError(err)
	}

	// Extract registry URL and credentials
	effectiveRegistryURL, registryUsername, registryPassword := extractRegistryCredentials(containerRef, exportOCI)

	// Validate credentials (error on partial credentials)
	if err := validateRegistryCredentials(effectiveRegistryURL, registryUsername, registryPassword); err != nil {
		handleError(err)
	}

	req := buildapitypes.BuildRequest{
		Name:                   buildName,
		ContainerRef:           containerRef,
		Distro:                 buildapitypes.Distro(distro),
		Target:                 buildapitypes.Target(target),
		Architecture:           buildapitypes.Architecture(architecture),
		ExportFormat:           buildapitypes.ExportFormat(diskFormat),
		Mode:                   buildapitypes.ModeDisk,
		AutomotiveImageBuilder: automotiveImageBuilder,
		StorageClass:           storageClass,
		AIBExtraArgs:           aibExtraArgs,
		Compression:            compressionAlgo,
		ExportOCI:              exportOCI,
	}

	// Add flash configuration if enabled
	if flashAfterBuild {
		// Flash requires a disk image pushed to a registry
		if exportOCI == "" {
			handleError(fmt.Errorf("cannot enable --flash without exporting a disk image (--push)"))
		}
		if jumpstarterClient == "" {
			handleError(fmt.Errorf("--flash requires --client to specify Jumpstarter client config file"))
		}
		clientConfigBytes, err := os.ReadFile(jumpstarterClient)
		if err != nil {
			handleError(fmt.Errorf("failed to read Jumpstarter client config: %w", err))
		}
		req.FlashEnabled = true
		req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientConfigBytes)
		req.FlashLeaseDuration = leaseDuration
	}

	if effectiveRegistryURL != "" && registryUsername != "" && registryPassword != "" {
		req.RegistryCredentials = &buildapitypes.RegistryCredentials{
			Enabled:     true,
			AuthType:    "username-password",
			RegistryURL: effectiveRegistryURL,
			Username:    registryUsername,
			Password:    registryPassword,
		}
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)

	if waitForBuild || followLogs || outputDir != "" || flashAfterBuild {
		waitForBuildCompletion(ctx, api, resp.Name)
	}

	// Show push location after successful build completion
	if exportOCI != "" {
		fmt.Printf("Disk image pushed to: %s\n", exportOCI)
	}

	downloadOCIArtifactIfRequested(outputDir, exportOCI, registryUsername, registryPassword)

	// Note: When flashAfterBuild is enabled, flash config is sent with the build request
	// and the controller handles flashing after push. The waitForBuildCompletion above
	// will wait until the full pipeline (including flash) completes.
}

func pullOCIArtifact(ociRef, destPath, username, password string) error {
	fmt.Printf("Pulling OCI artifact %s to %s\n", ociRef, destPath)

	// Ensure output directory exists
	destDir := filepath.Dir(destPath)
	if destDir != "" && destDir != "." {
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}

	ctx := context.Background()

	// Set up system context with authentication
	systemCtx := &types.SystemContext{}
	if username != "" && password != "" {
		fmt.Printf("Using provided username/password credentials\n")
		systemCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: username,
			Password: password,
		}
	} else {
		fmt.Printf("No explicit credentials provided, will use Docker/Podman auth files if available\n")
		// containers/image will automatically use:
		// - $HOME/.docker/config.json
		// - $XDG_RUNTIME_DIR/containers/auth.json
		// - /run/containers/$UID/auth.json
		// - $HOME/.config/containers/auth.json
	}

	// Set up policy context (allow all)
	policy := &signature.Policy{
		Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()},
	}
	policyCtx, err := signature.NewPolicyContext(policy)
	if err != nil {
		return fmt.Errorf("create policy context: %w", err)
	}

	// Source: docker registry reference
	srcRef, err := docker.ParseReference("//" + ociRef)
	if err != nil {
		return fmt.Errorf("parse source reference: %w", err)
	}

	// Create temporary directory for OCI layout
	tempDir, err := os.MkdirTemp("", "oci-pull-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp directory: %v\n", err)
		}
	}()

	// Destination: local OCI layout
	destRef, err := layout.ParseReference(tempDir + ":latest")
	if err != nil {
		return fmt.Errorf("parse destination reference: %w", err)
	}

	// Copy the image from registry to local OCI layout
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

	// Extract the artifact blob to the destination file
	if err := extractOCIArtifactBlob(tempDir, destPath); err != nil {
		return fmt.Errorf("extract artifact: %w", err)
	}

	// Check if file is compressed and add appropriate extension if needed
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

func extractOCIArtifactBlob(ociLayoutPath, destPath string) error {
	// Read the index.json to find the manifest
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

	// Get the manifest digest and read the manifest
	manifestDigest := strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")
	manifestPath := filepath.Join(ociLayoutPath, "blobs", "sha256", manifestDigest)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return fmt.Errorf("no layers found in manifest")
	}

	// Extract the first layer (should contain the disk image)
	layerDigest := strings.TrimPrefix(manifest.Layers[0].Digest, "sha256:")
	layerPath := filepath.Join(ociLayoutPath, "blobs", "sha256", layerDigest)

	// Copy the layer blob to destination
	src, err := os.Open(layerPath)
	if err != nil {
		return fmt.Errorf("open layer blob: %w", err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close source file: %v\n", err)
		}
	}()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create destination file: %w", err)
	}
	defer func() {
		if err := dst.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close destination file: %v\n", err)
		}
	}()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy layer blob: %w", err)
	}

	return nil
}

// runBuildDev handles the 'build-dev' command (traditional ostree/package builds)
func runBuildDev(_ *cobra.Command, args []string) {
	ctx := context.Background()
	manifest = args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER env)"))
	}
	validateOutputRequiresPush(outputDir, exportOCI, "--push")

	// Auto-generate build name if not provided
	if buildName == "" {
		base := strings.TrimSuffix(filepath.Base(manifest), ".aib.yml")
		base = strings.TrimSuffix(base, ".yml")
		buildName = fmt.Sprintf("%s-%s", base, time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	}

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
		handleError(err)
	}

	manifestBytes, err := os.ReadFile(manifest)
	if err != nil {
		handleError(fmt.Errorf("error reading manifest: %w", err))
	}

	// Validate mode
	var parsedMode buildapitypes.Mode
	switch mode {
	case "image":
		parsedMode = buildapitypes.ModeImage
	case "package":
		parsedMode = buildapitypes.ModePackage
	default:
		handleError(fmt.Errorf("invalid --mode %q (expected: %q or %q)", mode, buildapitypes.ModeImage, buildapitypes.ModePackage))
	}

	// Extract registry URL and credentials
	effectiveRegistryURL, registryUsername, registryPassword := extractRegistryCredentials("", exportOCI)

	// Validate credentials (error on partial credentials)
	if err := validateRegistryCredentials(effectiveRegistryURL, registryUsername, registryPassword); err != nil {
		handleError(err)
	}

	req := buildapitypes.BuildRequest{
		Name:                   buildName,
		Manifest:               string(manifestBytes),
		ManifestFileName:       filepath.Base(manifest),
		Distro:                 buildapitypes.Distro(distro),
		Target:                 buildapitypes.Target(target),
		Architecture:           buildapitypes.Architecture(architecture),
		ExportFormat:           buildapitypes.ExportFormat(exportFormat),
		Mode:                   parsedMode,
		AutomotiveImageBuilder: automotiveImageBuilder,
		StorageClass:           storageClass,
		CustomDefs:             customDefs,
		AIBExtraArgs:           aibExtraArgs,
		Compression:            compressionAlgo,
		ExportOCI:              exportOCI,
	}

	// Add flash configuration if enabled
	if flashAfterBuild {
		// Flash requires a disk image pushed to a registry
		if exportOCI == "" {
			handleError(fmt.Errorf("cannot enable --flash without exporting a disk image (--push)"))
		}
		if jumpstarterClient == "" {
			handleError(fmt.Errorf("--flash requires --client to specify Jumpstarter client config file"))
		}
		clientConfigBytes, err := os.ReadFile(jumpstarterClient)
		if err != nil {
			handleError(fmt.Errorf("failed to read Jumpstarter client config: %w", err))
		}
		req.FlashEnabled = true
		req.FlashClientConfig = base64.StdEncoding.EncodeToString(clientConfigBytes)
		req.FlashLeaseDuration = leaseDuration
	}

	if effectiveRegistryURL != "" && registryUsername != "" && registryPassword != "" {
		req.RegistryCredentials = &buildapitypes.RegistryCredentials{
			Enabled:     true,
			AuthType:    "username-password",
			RegistryURL: effectiveRegistryURL,
			Username:    registryUsername,
			Password:    registryPassword,
		}
	}

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)

	// Handle local file uploads if needed
	localRefs, err := findLocalFileReferences(string(manifestBytes))
	if err != nil {
		handleError(fmt.Errorf("manifest file reference error: %w", err))
	}
	if len(localRefs) > 0 {
		handleFileUploads(ctx, api, resp.Name, localRefs)
	}

	if waitForBuild || followLogs || outputDir != "" || flashAfterBuild {
		waitForBuildCompletion(ctx, api, resp.Name)
	}
	downloadOCIArtifactIfRequested(outputDir, exportOCI, registryUsername, registryPassword)

	// Note: When flashAfterBuild is enabled, flash config is sent with the build request
	// and the controller handles flashing after push. The waitForBuildCompletion above
	// will wait until the full pipeline (including flash) completes.
}

func handleFileUploads(
	ctx context.Context,
	api *buildapiclient.Client,
	buildName string,
	localRefs []map[string]string,
) {
	for _, ref := range localRefs {
		if _, err := os.Stat(ref["source_path"]); err != nil {
			handleError(fmt.Errorf("referenced file %s does not exist: %w", ref["source_path"], err))
		}
	}

	fmt.Println("Waiting for upload server to be ready...")
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		if err := readyCtx.Err(); err != nil {
			handleError(fmt.Errorf("timed out waiting for upload server to be ready"))
		}
		reqCtx, c := context.WithTimeout(ctx, 15*time.Second)
		st, err := api.GetBuild(reqCtx, buildName)
		c()
		if err == nil {
			if st.Phase == "Uploading" {
				break
			}
			if st.Phase == phaseFailed {
				handleError(fmt.Errorf("build failed while waiting for upload server: %s", st.Message))
			}
		}
		time.Sleep(3 * time.Second)
	}

	uploads := make([]buildapiclient.Upload, 0, len(localRefs))
	for _, ref := range localRefs {
		uploads = append(uploads, buildapiclient.Upload{SourcePath: ref["source_path"], DestPath: ref["source_path"]})
	}

	uploadDeadline := time.Now().Add(10 * time.Minute)
	for {
		if err := api.UploadFiles(ctx, buildName, uploads); err != nil {
			lower := strings.ToLower(err.Error())
			if time.Now().After(uploadDeadline) {
				handleError(fmt.Errorf("upload files failed: %w", err))
			}
			isServiceUnavailable := strings.Contains(lower, "503") ||
				strings.Contains(lower, "service unavailable") ||
				strings.Contains(lower, "upload pod not ready")
			if isServiceUnavailable {
				fmt.Println("Upload server not ready yet. Retrying...")
				time.Sleep(5 * time.Second)
				continue
			}
			handleError(fmt.Errorf("upload files failed: %w", err))
		}
		break
	}
	fmt.Println("Local files uploaded. Build will proceed.")
}

//nolint:gocyclo // Complex state machine for build progress tracking with log streaming
func waitForBuildCompletion(ctx context.Context, api *buildapiclient.Client, name string) {
	fmt.Println("Waiting for build to complete...")
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
	defer cancel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	userFollowRequested := followLogs
	var lastPhase, lastMessage string
	pendingWarningShown := false
	retryLimitWarningShown := false

	logClient := &http.Client{
		Timeout: 10 * time.Minute,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       2 * time.Minute,
		},
	}
	streamState := &logStreamState{}

	for {
		select {
		case <-timeoutCtx.Done():
			handleError(fmt.Errorf("timed out waiting for build"))
		case <-ticker.C:
			reqCtx, cancelReq := context.WithTimeout(ctx, 2*time.Minute)
			st, err := api.GetBuild(reqCtx, name)
			cancelReq()
			if err != nil {
				fmt.Printf("status check failed: %v\n", err)
				continue
			}

			// Update status display (only when not streaming)
			if !streamState.active && (!userFollowRequested || !streamState.canRetry()) {
				if st.Phase != lastPhase || st.Message != lastMessage {
					fmt.Printf("status: %s - %s\n", st.Phase, st.Message)
					lastPhase = st.Phase
					lastMessage = st.Message
				}
			}

			// Handle terminal build states
			if st.Phase == "Completed" {
				flashWasExecuted := strings.Contains(st.Message, "flash")
				if flashWasExecuted {
					fmt.Println("\n" + strings.Repeat("=", 50))
					fmt.Println("Build and flash completed successfully!")
					fmt.Println(strings.Repeat("=", 50))
					fmt.Println("\nThe device has been flashed and a lease has been acquired.")
					// Get lease ID from API response (preferred) or fall back to log parsing
					leaseID := ""
					if st.Jumpstarter != nil && st.Jumpstarter.LeaseID != "" {
						leaseID = st.Jumpstarter.LeaseID
					} else if streamState.leaseID != "" {
						leaseID = streamState.leaseID
					}
					if leaseID != "" {
						fmt.Printf("\nLease ID: %s\n", leaseID)
						fmt.Println("\nTo access the device:")
						fmt.Printf("  jmp shell --lease %s\n", leaseID)
						fmt.Println("\nTo release the lease when done:")
						fmt.Printf("  jmp delete leases %s\n", leaseID)
					} else {
						fmt.Println("Check the logs above for lease details, or use:")
						fmt.Println("  jmp list leases")
						fmt.Println("\nTo access the device:")
						fmt.Println("  jmp shell --lease <lease-id>")
						fmt.Println("\nTo release the lease when done:")
						fmt.Println("  jmp delete leases <lease-id>")
					}
				} else {
					fmt.Println("Build completed successfully!")
					if flashAfterBuild {
						fmt.Println("\nWarning: --flash was requested but flash was not executed.")
						fmt.Println("This may be because no Jumpstarter target mapping exists for this target.")
						fmt.Println("Check OperatorConfig for JumpstarterTargetMappings configuration.")
					}
					if st.Jumpstarter != nil && st.Jumpstarter.Available {
						fmt.Println("\nJumpstarter is available")
						if st.Jumpstarter.ExporterSelector != "" {
							fmt.Println("matching exporter(s) found")
							fmt.Printf("  Exporter selector: %s\n", st.Jumpstarter.ExporterSelector)
						}
						if st.Jumpstarter.FlashCmd != "" {
							fmt.Printf("  Flash command: %s\n", st.Jumpstarter.FlashCmd)
						}
					}
				}
				return
			}
			if st.Phase == phaseFailed {
				// Provide phase-specific error messages
				errPrefix := "build"
				if strings.Contains(strings.ToLower(st.Message), "flash") {
					errPrefix = "flash"
				} else if strings.Contains(strings.ToLower(st.Message), "push") {
					errPrefix = "push"
				} else if lastPhase == "Flashing" {
					errPrefix = "flash"
				} else if lastPhase == "Pushing" {
					errPrefix = "push"
				}
				handleError(fmt.Errorf("%s failed: %s", errPrefix, st.Message))
			}

			// Attempt log streaming for active builds
			if !followLogs || streamState.active || !streamState.canRetry() {
				continue
			}

			if st.Phase == "Pending" {
				streamState.reset()
				if userFollowRequested && !pendingWarningShown {
					fmt.Println("Waiting for build to start before streaming logs...")
					pendingWarningShown = true
				}
				continue
			}

			if isBuildActive(st.Phase) {
				if streamState.retryCount == 0 {
					fmt.Println("Build is active. Attempting to stream logs...")
					pendingWarningShown = false
				}

				if err := tryLogStreaming(ctx, logClient, name, streamState); err != nil {
					streamState.retryCount++
					if !streamState.canRetry() && !retryLimitWarningShown {
						msg := "Log streaming failed after %d attempts (~2 minutes). " +
							"Falling back to status updates only.\n"
						fmt.Printf(msg, maxLogRetries)
						retryLimitWarningShown = true
					}
				} else {
					followLogs = userFollowRequested
				}
			}
		}
	}
}

// logStreamState encapsulates state for log streaming with automatic reconnection
type logStreamState struct {
	active       bool
	retryCount   int
	warningShown bool
	startTime    time.Time
	completed    bool   // Set when stream ends normally, prevents reconnection
	leaseID      string // Captured lease ID from flash logs
}

const maxLogRetries = 24 // ~2 minutes at 5s intervals

func (s *logStreamState) canRetry() bool {
	return s.retryCount <= maxLogRetries && !s.completed
}

func (s *logStreamState) reset() {
	s.retryCount = 0
	s.warningShown = false
}

func isBuildActive(phase string) bool {
	return phase == "Building" || phase == "Running" || phase == "Uploading" || phase == "Flashing"
}

// tryLogStreaming attempts to stream logs and returns error if it fails
func tryLogStreaming(ctx context.Context, logClient *http.Client, name string, state *logStreamState) error {
	logURL := buildLogURL(name, state.startTime)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if authToken := strings.TrimSpace(authToken); authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := logClient.Do(req)
	if err != nil {
		return fmt.Errorf("log request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusOK {
		return streamLogsToStdout(resp.Body, state)
	}

	return handleLogStreamError(resp, state)
}

func buildLogURL(buildName string, startTime time.Time) string {
	logURL := strings.TrimRight(serverURL, "/") + "/v1/builds/" + url.PathEscape(buildName) + "/logs?follow=1"
	if !startTime.IsZero() {
		logURL += "&since=" + url.QueryEscape(startTime.Format(time.RFC3339))
	}
	return logURL
}

func streamLogsToStdout(body io.Reader, state *logStreamState) error {
	if state.startTime.IsZero() {
		state.startTime = time.Now()
	}

	fmt.Println("Streaming logs...")
	state.active = true
	state.reset()

	// Use line-by-line streaming for real-time output
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // Handle long lines
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)

		// Capture lease ID from flash logs
		// Format: "jmp shell --lease <lease-id>" or "Lease acquired: <lease-id>"
		// Extract only the first token after the marker to avoid trailing flags/text
		if strings.Contains(line, "jmp shell --lease ") {
			parts := strings.Split(line, "jmp shell --lease ")
			if len(parts) > 1 {
				tokens := strings.Fields(parts[1])
				if len(tokens) > 0 {
					state.leaseID = tokens[0]
				}
			}
		} else if strings.Contains(line, "Lease acquired: ") {
			parts := strings.Split(line, "Lease acquired: ")
			if len(parts) > 1 {
				tokens := strings.Fields(parts[1])
				if len(tokens) > 0 {
					state.leaseID = tokens[0]
				}
			}
		}
	}
	state.active = false

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("log stream interrupted: %w", err)
	}

	// Stream ended normally (server closed connection after sending all logs)
	// Mark as completed to prevent reconnection attempts
	state.completed = true
	return nil
}

func handleLogStreamError(resp *http.Response, state *logStreamState) error {
	body, _ := io.ReadAll(resp.Body)
	msg := strings.TrimSpace(string(body))

	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		if !state.warningShown {
			fmt.Printf("log stream not ready (HTTP %d). Retrying... (attempt %d/%d)\n",
				resp.StatusCode, state.retryCount+1, maxLogRetries)
			state.warningShown = true
		}
		return fmt.Errorf("log endpoint not ready (HTTP %d)", resp.StatusCode)
	}

	if msg != "" {
		fmt.Printf("log stream error (%d): %s\n", resp.StatusCode, msg)
	} else {
		fmt.Printf("log stream error: HTTP %d\n", resp.StatusCode)
	}
	return fmt.Errorf("log stream failed with HTTP %d", resp.StatusCode)
}

func handleError(err error) {
	fmt.Printf("Error: %v\n", err)
	os.Exit(1)
}

func findLocalFileReferences(manifestContent string) ([]map[string]string, error) {
	var manifestData map[string]any
	var localFiles []map[string]string

	if err := yaml.Unmarshal([]byte(manifestContent), &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse manifest YAML: %w", err)
	}

	isPathSafe := func(path string) error {
		if path == "" || path == "/" {
			return fmt.Errorf("empty or root path is not allowed")
		}

		if strings.Contains(path, "..") {
			return fmt.Errorf("directory traversal detected in path: %s", path)
		}

		if filepath.IsAbs(path) {
			// TODO add safe dirs flag
			safeDirectories := []string{}
			isInSafeDir := false
			for _, dir := range safeDirectories {
				if strings.HasPrefix(path, dir+"/") {
					isInSafeDir = true
					break
				}
			}
			if !isInSafeDir {
				return fmt.Errorf("absolute path outside safe directories: %s", path)
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

// compressionExtension returns the file extension for a compression algorithm
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

// hasCompressionExtension checks if a filename already has a compression extension
func hasCompressionExtension(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".gz") ||
		strings.HasSuffix(lower, ".lz4") ||
		strings.HasSuffix(lower, ".xz")
}

// detectFileCompression examines file magic bytes to determine compression type
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

	// Read first few bytes to check magic numbers
	header := make([]byte, 10)
	n, err := file.Read(header)
	if err != nil || n < 3 {
		return ""
	}

	// Check for gzip magic number
	if n >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		// Check if it's a gzipped tar by decompressing and looking for tar magic
		if isTarInsideGzip(filePath) {
			return "tar.gz"
		}
		return "gzip"
	}

	// Check for lz4 magic number
	if n >= 4 && header[0] == 0x04 && header[1] == 0x22 && header[2] == 0x4d && header[3] == 0x18 {
		return "lz4"
	}

	// Check for xz magic number
	if n >= 6 && header[0] == 0xfd && header[1] == 0x37 && header[2] == 0x7a &&
		header[3] == 0x58 && header[4] == 0x5a && header[5] == 0x00 {
		return "xz"
	}

	return ""
}

// isTarInsideGzip checks if a gzip file contains a tar archive
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

	// Read enough bytes to check for tar magic at offset 257 ("ustar")
	header := make([]byte, 512)
	n, err := io.ReadFull(gzReader, header)
	if err != nil && n < 262 {
		return false
	}

	// Tar magic "ustar" is at offset 257
	return n >= 262 && string(header[257:262]) == "ustar"
}

func runList(_ *cobra.Command, _ []string) {
	ctx := context.Background()
	if strings.TrimSpace(serverURL) == "" {
		fmt.Println("Error: --server is required (or set CAIB_SERVER)")
		os.Exit(1)
	}

	var items []buildapitypes.BuildListItem
	err := executeWithReauth(serverURL, &authToken, func(api *buildapiclient.Client) error {
		var err error
		items, err = api.ListBuilds(ctx)
		return err
	})
	if err != nil {
		fmt.Printf("Error listing ImageBuilds: %v\n", err)
		os.Exit(1)
	}
	if len(items) == 0 {
		fmt.Println("No ImageBuilds found")
		return
	}
	fmt.Printf("%-20s %-12s %-20s %-20s %-20s\n", "NAME", "STATUS", "MESSAGE", "CREATED", "ARTIFACT")
	for _, it := range items {
		fmt.Printf("%-20s %-12s %-20s %-20s %-20s\n", it.Name, it.Phase, it.Message, it.CreatedAt, "")
	}
}

func loadTokenFromKubeconfig() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	// First, ask client-go to build a client config. This will execute any exec credential plugins
	// (e.g., OpenShift login) and populate a usable BearerToken.
	deferred := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	if restCfg, err := deferred.ClientConfig(); err == nil && restCfg != nil {
		if t := strings.TrimSpace(restCfg.BearerToken); t != "" {
			return t, nil
		}
		if f := strings.TrimSpace(restCfg.BearerTokenFile); f != "" {
			if b, rerr := os.ReadFile(f); rerr == nil {
				if t := strings.TrimSpace(string(b)); t != "" {
					return t, nil
				}
			}
		}
	}

	// Fallback to parsing raw kubeconfig for legacy token fields
	rawCfg, err := loadingRules.Load()
	if err != nil || rawCfg == nil {
		return "", fmt.Errorf("cannot load kubeconfig: %w", err)
	}
	ctxName := rawCfg.CurrentContext
	if strings.TrimSpace(ctxName) == "" {
		return "", fmt.Errorf("no current kube context")
	}
	ctx := rawCfg.Contexts[ctxName]
	if ctx == nil {
		return "", fmt.Errorf("missing context %s", ctxName)
	}
	ai := rawCfg.AuthInfos[ctx.AuthInfo]
	if ai == nil {
		return "", fmt.Errorf("missing auth info for context %s", ctxName)
	}
	if strings.TrimSpace(ai.Token) != "" {
		return strings.TrimSpace(ai.Token), nil
	}
	if ai.AuthProvider != nil && ai.AuthProvider.Config != nil {
		if t := strings.TrimSpace(ai.AuthProvider.Config["access-token"]); t != "" {
			return t, nil
		}
		if t := strings.TrimSpace(ai.AuthProvider.Config["id-token"]); t != "" {
			return t, nil
		}
		if t := strings.TrimSpace(ai.AuthProvider.Config["token"]); t != "" {
			return t, nil
		}
	}
	if path, err := exec.LookPath("oc"); err == nil && path != "" {
		out, err := exec.Command(path, "whoami", "-t").Output()
		if err == nil {
			if t := strings.TrimSpace(string(out)); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("no bearer token found in kubeconfig")
}

// parseLeaseDuration converts HH:MM:SS format to time.Duration
func parseLeaseDuration(duration string) time.Duration {
	parts := strings.Split(duration, ":")
	if len(parts) != 3 {
		return time.Hour // Default 1 hour
	}
	var hours, mins, secs int
	_, _ = fmt.Sscanf(parts[0], "%d", &hours)
	_, _ = fmt.Sscanf(parts[1], "%d", &mins)
	_, _ = fmt.Sscanf(parts[2], "%d", &secs)
	return time.Duration(hours)*time.Hour + time.Duration(mins)*time.Minute + time.Duration(secs)*time.Second
}

// runFlash handles the standalone 'flash' command
func runFlash(_ *cobra.Command, args []string) {
	ctx := context.Background()
	imageRef := args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER env)"))
	}

	if jumpstarterClient == "" {
		handleError(fmt.Errorf("--client is required"))
	}

	// Validate that either target or exporter is specified
	if target == "" && exporterSelector == "" {
		handleError(fmt.Errorf("either --target or --exporter is required"))
	}

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
		handleError(err)
	}

	// Read and encode client config
	clientConfigBytes, err := os.ReadFile(jumpstarterClient)
	if err != nil {
		handleError(fmt.Errorf("failed to read client config file: %w", err))
	}
	clientConfigB64 := base64.StdEncoding.EncodeToString(clientConfigBytes)

	req := buildapitypes.FlashRequest{
		Name:             flashName,
		ImageRef:         imageRef,
		Target:           target,
		ExporterSelector: exporterSelector,
		ClientConfig:     clientConfigB64,
		LeaseDuration:    leaseDuration,
	}

	resp, err := api.CreateFlash(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Flash job %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)

	if waitForBuild || followLogs {
		waitForFlashCompletion(ctx, api, resp.Name)
	}
}

// waitForFlashCompletion waits for a flash job to complete, optionally streaming logs
func waitForFlashCompletion(ctx context.Context, api *buildapiclient.Client, name string) {
	fmt.Println("Waiting for flash to complete...")
	// Parse lease duration and add buffer for wait timeout
	timeoutDuration := parseLeaseDuration(leaseDuration) + 10*time.Minute
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastPhase, lastMessage string
	pendingWarningShown := false

	logClient := &http.Client{
		Timeout: 10 * time.Minute,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       2 * time.Minute,
		},
	}
	streamState := &logStreamState{}

	for {
		select {
		case <-timeoutCtx.Done():
			handleError(fmt.Errorf("timed out waiting for flash"))
		case <-ticker.C:
			reqCtx, cancelReq := context.WithTimeout(ctx, 2*time.Minute)
			st, err := api.GetFlash(reqCtx, name)
			cancelReq()
			if err != nil {
				fmt.Printf("status check failed: %v\n", err)
				continue
			}

			// Update status display when not streaming
			if !streamState.active {
				if st.Phase != lastPhase || st.Message != lastMessage {
					fmt.Printf("status: %s - %s\n", st.Phase, st.Message)
					lastPhase = st.Phase
					lastMessage = st.Message
				}
			}

			// Handle terminal states
			if st.Phase == "Completed" {
				fmt.Println("Flash completed successfully!")
				return
			}
			if st.Phase == phaseFailed {
				handleError(fmt.Errorf("flash failed: %s", st.Message))
			}

			// Attempt log streaming for active flash jobs
			if !followLogs || streamState.active || !streamState.canRetry() {
				continue
			}

			if st.Phase == "Pending" {
				streamState.reset()
				if !pendingWarningShown {
					fmt.Println("Waiting for flash to start before streaming logs...")
					pendingWarningShown = true
				}
				continue
			}

			if st.Phase == "Running" {
				if streamState.retryCount == 0 {
					fmt.Println("Flash is running. Attempting to stream logs...")
					pendingWarningShown = false
				}

				if err := tryFlashLogStreaming(ctx, logClient, name, streamState); err != nil {
					streamState.retryCount++
				}
			}
		}
	}
}

// tryFlashLogStreaming attempts to stream flash logs
func tryFlashLogStreaming(ctx context.Context, logClient *http.Client, name string, state *logStreamState) error {
	logURL := strings.TrimRight(serverURL, "/") + "/v1/flash/" + url.PathEscape(name) + "/logs?follow=1"
	if !state.startTime.IsZero() {
		logURL += "&since=" + url.QueryEscape(state.startTime.Format(time.RFC3339))
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if authToken := strings.TrimSpace(authToken); authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := logClient.Do(req)
	if err != nil {
		return fmt.Errorf("log request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusOK {
		return streamLogsToStdout(resp.Body, state)
	}

	return handleLogStreamError(resp, state)
}
