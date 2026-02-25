// Package main provides the caib CLI tool for interacting with the automotive image build system.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"gopkg.in/yaml.v3"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/catalog"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/container"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/ui"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	archAMD64      = "amd64"
	archARM64      = "arm64"
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
	phaseFlashing  = "Flashing"
	phasePending   = "Pending"
	phaseUploading = "Uploading"
	errPrefixBuild = "build"
	errPrefixFlash = "flash"
	errPrefixPush  = "push"
)

var (
	multiHyphenRe = regexp.MustCompile(`-{2,}`)
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
	showOutputFormat       string
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

	containerRef   string
	rebuildBuilder bool

	// Flash options
	flashAfterBuild   bool
	jumpstarterClient string
	flashName         string
	exporterSelector  string
	leaseDuration     string

	// Internal registry options
	useInternalRegistry       bool
	internalRegistryImageName string
	internalRegistryTag       string

	// TLS options
	insecureSkipTLS bool
)

// envBool parses a boolean from environment variable
func envBool(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

func supportsColorOutput() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}

	termType := os.Getenv("TERM")
	if termType == "dumb" {
		return false
	}

	shell := os.Getenv("SHELL")

	isSupportedShell := strings.Contains(shell, "bash") ||
		strings.Contains(shell, "fish") ||
		strings.Contains(shell, "zsh")

	hasColorTerm := termType != "" &&
		!strings.Contains(termType, "mono")

	return !color.NoColor || isSupportedShell || hasColorTerm
}

// createBuildAPIClient creates a build API client with authentication token from flags or kubeconfig
// It will attempt OIDC re-authentication if token is missing or expired
func createBuildAPIClient(serverURL string, authToken *string) (*buildapiclient.Client, error) {
	ctx := context.Background()

	explicitToken := strings.TrimSpace(*authToken) != "" || os.Getenv("CAIB_TOKEN") != ""

	// If no explicit token, try OIDC if config is available
	if !explicitToken {
		token, didAuth, err := auth.GetTokenWithReauth(ctx, serverURL, "", insecureSkipTLS)
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
			// OIDC not configured in OperatorConfig
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
	if insecureSkipTLS {
		opts = append(opts, buildapiclient.WithInsecureTLS())
	}
	// Check for custom CA certificate
	if caCertFile := os.Getenv("SSL_CERT_FILE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	} else if caCertFile := os.Getenv("REQUESTS_CA_BUNDLE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	}

	return buildapiclient.New(serverURL, opts...)
}

// executeWithReauth executes an API call and automatically retries with re-authentication on auth errors.
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

	// Auth error (401) - try re-authentication; token may be rejected, not necessarily expired
	fmt.Println("Authentication failed (401), re-authenticating...")

	newToken, _, err := auth.GetTokenWithReauth(ctx, serverURL, *authToken, insecureSkipTLS)
	if err != nil {
		return fmt.Errorf("re-authentication failed: %w", err)
	}

	*authToken = newToken
	// If re-auth returned no token (API says OIDC not configured), try kubeconfig before retrying
	if strings.TrimSpace(*authToken) == "" {
		if tok, kerr := loadTokenFromKubeconfig(); kerr == nil && strings.TrimSpace(tok) != "" {
			*authToken = tok
			client, err = createBuildAPIClient(serverURL, authToken)
			if err != nil {
				return err
			}
			fmt.Println("Using kubeconfig token, retrying...")
			return fn(client)
		}
	}

	client, err = createBuildAPIClient(serverURL, authToken)
	if err != nil {
		return err
	}

	fmt.Println("Retrying request...")
	err = fn(client)
	if err == nil {
		return nil
	}

	// Still 401 after OIDC re-auth (e.g. server OIDC broken, or wrong client/audience) - try kubeconfig fallback
	if !auth.IsAuthError(err) {
		return err
	}
	if tok, kerr := loadTokenFromKubeconfig(); kerr == nil && strings.TrimSpace(tok) != "" {
		*authToken = tok
		client, err = createBuildAPIClient(serverURL, authToken)
		if err != nil {
			return err
		}
		fmt.Println("Attempting kubeconfig fallback...")
		return fn(client)
	}

	return err
}

// writeRegistryCredentialsFile writes registry credentials to a mode-0600 temp file and returns its path.
func writeRegistryCredentialsFile(token string) (string, error) {
	creds, err := json.Marshal(map[string]string{
		"username": "serviceaccount",
		"token":    token,
	})
	if err != nil {
		return "", err
	}

	f, err := os.CreateTemp("", "caib-registry-creds-*.json")
	if err != nil {
		return "", err
	}
	name := f.Name()

	if _, err := f.Write(creds); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Chmod(name, 0600); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

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

func downloadOCIArtifactIfRequested(output, exportOCI, registryUsername, registryPassword string, insecureSkipTLS bool) {
	if output == "" {
		return
	}
	if err := pullOCIArtifact(exportOCI, output, registryUsername, registryPassword, insecureSkipTLS); err != nil {
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

	// Global flags
	rootCmd.PersistentFlags().BoolVar(
		&insecureSkipTLS,
		"insecure",
		envBool("CAIB_INSECURE"),
		"skip TLS certificate verification (insecure, for testing only; env: CAIB_INSECURE)",
	)

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

	showCmd := &cobra.Command{
		Use:   "show <build-name>",
		Short: "Show detailed information for an ImageBuild",
		Long: `Show retrieves detailed status and output fields for a single ImageBuild.

Examples:
  # Show details in table format
  caib show my-build

  # Show details as JSON
  caib show my-build -o json`,
		Args: cobra.ExactArgs(1),
		Run:  runShow,
	}

	downloadCmd := &cobra.Command{
		Use:   "download <build-name>",
		Short: "Download disk image artifact from a completed build",
		Long: `Download retrieves the disk image artifact from a completed build.

The build must have pushed a disk image to an OCI registry (via --push-disk
or --push on disk/build-dev commands). The artifact is pulled from the
registry to a local file.

Examples:
  # Download disk image from a completed build
  caib download my-build -o ./disk.qcow2

  # Download to a directory (multi-layer artifacts extract here)
  caib download my-build -o ./output/`,
		Args: cobra.ExactArgs(1),
		Run:  runDownload,
	}

	logsCmd := &cobra.Command{
		Use:   "logs <build-name>",
		Short: "Follow logs of an existing build",
		Long: `Follow the log output of an active or completed build.

This is useful when you kicked off a build and need to reconnect later
(e.g., after restarting your terminal or computer).

Examples:
  # Follow logs of an active build
  caib logs my-build-20250101-120000

  # List builds first, then follow one
  caib list
  caib logs <build-name>`,
		Args: cobra.ExactArgs(1),
		Run:  runLogs,
	}

	loginCmd := &cobra.Command{
		Use:   "login [server-url]",
		Short: "Save server endpoint and authenticate for subsequent commands",
		Long: `Login saves the Build API server URL locally (~/.caib/cli.json) so you do not need
to pass --server or set CAIB_SERVER for later commands. If the server uses OIDC,
this command also performs authentication and caches the token.

Example:
  caib login https://build-api.my-cluster.example.com`,
		Args: cobra.ExactArgs(1),
		Run:  runLogin,
	}

	// build command flags (bootc - the default)
	buildCmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
	buildCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	buildCmd.Flags().StringVarP(&buildName, "name", "n", "", "name for the ImageBuild (auto-generated if omitted)")
	buildCmd.Flags().StringVarP(&distro, "distro", "d", "autosd", "distribution to build")
	buildCmd.Flags().StringVarP(&target, "target", "t", "qemu", "target platform")
	buildCmd.Flags().StringVarP(&architecture, "arch", "a", getDefaultArch(), "architecture (amd64, arm64)")
	buildCmd.Flags().StringVar(&containerPush, "push", "", "push bootc container to registry (optional if --disk is used)")
	buildCmd.Flags().BoolVar(&buildDiskImage, "disk", false, "also build disk image from container")
	buildCmd.Flags().StringVarP(&outputDir, "output", "o", "", "download disk image to file from registry (implies --disk; requires --push-disk or --internal-registry)")
	buildCmd.Flags().StringVar(
		&diskFormat, "format", "", "disk image format (qcow2, raw, simg); inferred from output filename if not set",
	)
	buildCmd.Flags().StringVar(&compressionAlgo, "compress", "gzip", "compression algorithm (gzip, lz4, xz)")
	buildCmd.Flags().StringVar(&exportOCI, "push-disk", "", "push disk image as OCI artifact to registry (implies --disk)")
	buildCmd.Flags().StringVar(
		&automotiveImageBuilder, "aib-image",
		"quay.io/centos-sig-automotive/automotive-image-builder:latest", "AIB container image",
	)
	buildCmd.Flags().StringVar(&builderImage, "builder-image", "", "custom builder container")
	buildCmd.Flags().BoolVar(&rebuildBuilder, "rebuild-builder", false, "force rebuild of the bootc builder image")
	buildCmd.Flags().StringVar(&storageClass, "storage-class", "", "Kubernetes storage class for build workspace")
	buildCmd.Flags().StringArrayVarP(&customDefs, "define", "D", []string{}, "custom definition KEY=VALUE")
	buildCmd.Flags().StringArrayVar(&aibExtraArgs, "extra-args", []string{}, "extra arguments to pass to AIB (can be repeated)")
	buildCmd.Flags().IntVar(&timeout, "timeout", 60, "timeout in minutes")
	buildCmd.Flags().BoolVarP(&waitForBuild, "wait", "w", false, "wait for build to complete")
	buildCmd.Flags().BoolVarP(&followLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Note: --push is optional when --disk is used (disk image becomes the output)
	// Jumpstarter flash options
	buildCmd.Flags().BoolVar(&flashAfterBuild, "flash", false, "flash the image to device after build completes")
	buildCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required for --flash)")
	buildCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	// Internal registry options
	buildCmd.Flags().BoolVar(&useInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	buildCmd.Flags().StringVar(&internalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	buildCmd.Flags().StringVar(&internalRegistryTag, "image-tag", "", "tag for internal registry image (default: build name)")

	listCmd.Flags().StringVar(
		&serverURL, "server", config.DefaultServer(), "REST API server base URL (e.g. https://api.example)",
	)
	listCmd.Flags().StringVar(
		&authToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)
	showCmd.Flags().StringVar(
		&serverURL, "server", config.DefaultServer(), "REST API server base URL (e.g. https://api.example)",
	)
	showCmd.Flags().StringVar(
		&authToken, "token", os.Getenv("CAIB_TOKEN"),
		"Bearer token for authentication (e.g., OpenShift access token)",
	)
	showCmd.Flags().StringVarP(
		&showOutputFormat, "output", "o", "table", "Output format (table, json, yaml)",
	)

	// disk command flags (create disk from existing container)
	diskCmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
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
	diskCmd.Flags().BoolVarP(&followLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Jumpstarter flash options
	diskCmd.Flags().BoolVar(&flashAfterBuild, "flash", false, "flash the image to device after build completes")
	diskCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required for --flash)")
	diskCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	// Internal registry options
	diskCmd.Flags().BoolVar(&useInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	diskCmd.Flags().StringVar(&internalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	diskCmd.Flags().StringVar(&internalRegistryTag, "image-tag", "", "tag for internal registry image (default: build name)")

	// build-dev command flags (traditional ostree/package builds)
	buildDevCmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
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
	buildDevCmd.Flags().BoolVarP(&followLogs, "follow", "f", false, "follow build logs (shows full log output instead of progress bar)")
	// Jumpstarter flash options
	buildDevCmd.Flags().BoolVar(&flashAfterBuild, "flash", false, "flash the image to device after build completes")
	buildDevCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required for --flash)")
	buildDevCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration for flash (HH:MM:SS)")
	// Internal registry options
	buildDevCmd.Flags().BoolVar(&useInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")
	buildDevCmd.Flags().StringVar(&internalRegistryImageName, "image-name", "", "override image name for internal registry (default: build name)")
	buildDevCmd.Flags().StringVar(&internalRegistryTag, "image-tag", "", "tag for internal registry image (default: build name)")

	// logs command flags
	logsCmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
	logsCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	logsCmd.Flags().IntVar(&timeout, "timeout", 60, "timeout in minutes")

	// download command flags
	downloadCmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
	downloadCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	downloadCmd.Flags().StringVarP(&outputDir, "output", "o", "", "destination file or directory for the artifact")

	// flash command flags
	flashCmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
	flashCmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	flashCmd.Flags().StringVar(&jumpstarterClient, "client", "", "path to Jumpstarter client config file (required)")
	flashCmd.Flags().StringVarP(&flashName, "name", "n", "", "name for the flash job (auto-generated if omitted)")
	flashCmd.Flags().StringVarP(&target, "target", "t", "", "target platform for exporter lookup")
	flashCmd.Flags().StringVar(&exporterSelector, "exporter", "", "direct exporter selector (alternative to --target)")
	flashCmd.Flags().StringVar(&leaseDuration, "lease", "03:00:00", "device lease duration (HH:MM:SS)")
	flashCmd.Flags().BoolVarP(&followLogs, "follow", "f", false, "follow flash logs (shows full log output instead of progress bar)")
	flashCmd.Flags().BoolVarP(&waitForBuild, "wait", "w", true, "wait for flash to complete")
	_ = flashCmd.MarkFlagRequired("client")

	// build-container command (Shipwright-based container builds)
	containerCmd := container.NewContainerCmd()

	// Add all commands
	rootCmd.AddCommand(buildCmd, diskCmd, buildDevCmd, listCmd, showCmd, downloadCmd, flashCmd, logsCmd, loginCmd, containerCmd, catalog.NewCatalogCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runLogin saves the server URL and optionally performs OIDC authentication.
func runLogin(_ *cobra.Command, args []string) {
	raw := strings.TrimSpace(args[0])
	if raw == "" {
		handleError(fmt.Errorf("server URL is required"))
	}
	server := raw
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "https://" + server
	}
	if err := config.SaveServerURL(server); err != nil {
		handleError(fmt.Errorf("failed to save server URL: %w", err))
	}
	fmt.Printf("Server saved: %s\n", server)

	ctx := context.Background()
	token, didAuth, err := auth.GetTokenWithReauth(ctx, server, "", insecureSkipTLS)
	if err != nil {
		fmt.Printf("Warning: authentication failed (you may need --token or kubeconfig for API calls): %v\n", err)
		return
	}
	if token != "" && didAuth {
		fmt.Println("OIDC authentication successful. Token cached for subsequent commands.")
	} else if token != "" {
		fmt.Println("Using existing or kubeconfig token. You can run build/list/disk commands without --server.")
	}
}

// validateBootcBuildFlags validates flag combinations for the build command
func validateBootcBuildFlags() {
	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}

	if useInternalRegistry {
		if exportOCI != "" {
			handleError(fmt.Errorf("--internal-registry cannot be used with --push-disk"))
		}
	}

	if outputDir != "" && !buildDiskImage {
		buildDiskImage = true
	}
	if exportOCI != "" && !buildDiskImage {
		buildDiskImage = true
	}
	if flashAfterBuild && !buildDiskImage {
		buildDiskImage = true
	}
	if !useInternalRegistry {
		validateOutputRequiresPush(outputDir, exportOCI, "--push-disk")
	}

	if containerPush == "" && !buildDiskImage && !useInternalRegistry {
		handleError(fmt.Errorf(
			"--push is required when not building a disk image " +
				"(use --disk or --output to create a disk image without pushing the container)",
		))
	}
}

// applyRegistryCredentialsToRequest sets registry credentials on the build request.
// When --internal-registry is combined with --push, both are configured so the
// container is pushed externally while the disk image uses the internal registry.
func applyRegistryCredentialsToRequest(req *buildapitypes.BuildRequest) {
	if useInternalRegistry {
		req.UseInternalRegistry = true
		req.InternalRegistryImageName = internalRegistryImageName
		req.InternalRegistryTag = internalRegistryTag
		if containerPush == "" {
			return
		}
		// Hybrid: fall through to also set external registry credentials
		// for the container push.
	}

	effectiveRegistryURL, registryUsername, registryPassword := extractRegistryCredentials(containerPush, exportOCI)
	if err := validateRegistryCredentials(effectiveRegistryURL, registryUsername, registryPassword); err != nil {
		handleError(err)
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
}

// fetchTargetDefaults fetches the operator config once and returns it.
// If flash is enabled, it also validates that the target has a Jumpstarter mapping.
func fetchTargetDefaults(ctx context.Context, api *buildapiclient.Client, target string, validateFlash bool) *buildapitypes.OperatorConfigResponse {
	config, err := api.GetOperatorConfig(ctx)
	if err != nil {
		// Non-fatal for defaults: if we can't reach the config endpoint, just skip defaults
		if !validateFlash {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch operator config for target defaults: %v\n", err)
			return nil
		}
		handleError(fmt.Errorf("failed to get operator configuration for Jumpstarter validation: %w", err))
	}

	if validateFlash {
		if len(config.JumpstarterTargets) == 0 {
			handleError(fmt.Errorf("flash enabled but no Jumpstarter target mappings configured in operator"))
		}

		if _, exists := config.JumpstarterTargets[target]; !exists {
			availableTargets := make([]string, 0, len(config.JumpstarterTargets))
			for t := range config.JumpstarterTargets {
				availableTargets = append(availableTargets, t)
			}
			handleError(
				fmt.Errorf(
					"flash enabled but no Jumpstarter target mapping found for target %q. Available targets: %v",
					target,
					availableTargets,
				),
			)
		}
	}

	return config
}

// applyTargetDefaults applies architecture and extra-args defaults from the operator config
// target defaults (ConfigMap). CLI flags override defaults when explicitly set.
func applyTargetDefaults(cmd *cobra.Command, config *buildapitypes.OperatorConfigResponse, req *buildapitypes.BuildRequest) {
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
		// Default args come first, user args appended
		req.AIBExtraArgs = append(defaults.ExtraArgs, req.AIBExtraArgs...)
		fmt.Printf("Prepending extra args %v from target defaults for %q\n", defaults.ExtraArgs, req.Target)
	}
}

// displayBuildResults shows push locations after build completion
func displayBuildResults(ctx context.Context, api *buildapiclient.Client, buildName string) {
	labelColor := func(a ...any) string { return fmt.Sprint(a...) }
	valueColor := func(a ...any) string { return fmt.Sprint(a...) }
	if supportsColorOutput() {
		labelColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		valueColor = color.New(color.FgHiGreen).SprintFunc()
	}

	if useInternalRegistry {
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
			if outputDir != "" && st.DiskImage != "" {
				downloadOCIArtifactIfRequested(outputDir, st.DiskImage, "serviceaccount", st.RegistryToken, insecureSkipTLS)
			} else {
				credsFile, err := writeRegistryCredentialsFile(st.RegistryToken)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to write registry credentials file: %v\n", err)
					fmt.Printf("\n%s\n", labelColor("Registry credentials (valid ~4 hours):"))
					fmt.Printf("  %s %s\n", labelColor("Username:"), valueColor("serviceaccount"))
					fmt.Printf("  %s %s\n", labelColor("Token:"), valueColor(st.RegistryToken))
				} else {
					fmt.Printf("\n%s %s (valid ~4 hours)\n",
						labelColor("Registry credentials written to:"),
						valueColor(credsFile))
				}
			}
		}
	} else {
		if containerPush != "" {
			fmt.Printf("%s %s\n", labelColor("Container image pushed to:"), valueColor(containerPush))
		}
		if exportOCI != "" {
			fmt.Printf("%s %s\n", labelColor("Disk image pushed to:"), valueColor(exportOCI))
		}
		_, registryUsername, registryPassword := extractRegistryCredentials(containerPush, exportOCI)
		downloadOCIArtifactIfRequested(outputDir, exportOCI, registryUsername, registryPassword, insecureSkipTLS)
	}
}

// runBuild handles the main 'build' command (bootc builds)
func runBuild(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	manifest = args[0]

	validateManifestSuffix(manifest)
	validateBootcBuildFlags()

	if buildName == "" {
		base := filepath.Base(manifest)
		for _, suffix := range validManifestSuffixes {
			base = strings.TrimSuffix(base, suffix)
		}
		buildName = fmt.Sprintf("%s-%s", sanitizeBuildName(base), time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	} else {
		validateBuildName(buildName)
	}

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
		handleError(err)
	}

	manifestBytes, err := os.ReadFile(manifest)
	if err != nil {
		handleError(fmt.Errorf("error reading manifest: %w", err))
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
		RebuildBuilder:         rebuildBuilder,
	}

	applyRegistryCredentialsToRequest(&req)

	// Fetch target defaults and apply them to the request
	operatorConfig := fetchTargetDefaults(ctx, api, target, flashAfterBuild)
	applyTargetDefaults(cmd, operatorConfig, &req)

	// Add flash configuration if enabled
	if flashAfterBuild {
		if exportOCI == "" && !useInternalRegistry {
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

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	fmt.Printf("To follow this build later: caib logs %s\n", resp.Name)

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

	displayBuildResults(ctx, api, resp.Name)
}

func runDisk(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	containerRef = args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}

	if useInternalRegistry {
		if exportOCI != "" {
			handleError(fmt.Errorf("--internal-registry cannot be used with --push"))
		}
	} else {
		// Validate: need either --output or --push
		if outputDir == "" && exportOCI == "" {
			handleError(fmt.Errorf("either --output or --push is required"))
		}
		validateOutputRequiresPush(outputDir, exportOCI, "--push")
	}

	// Auto-generate build name if not provided
	if buildName == "" {
		parts := strings.Split(containerRef, "/")
		imagePart := parts[len(parts)-1]
		imagePart = strings.Split(imagePart, ":")[0] // remove tag
		buildName = fmt.Sprintf("disk-%s-%s", sanitizeBuildName(imagePart), time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	} else {
		validateBuildName(buildName)
	}

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
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

	applyRegistryCredentialsToRequest(&req)

	// Fetch target defaults and apply them to the request
	operatorConfig := fetchTargetDefaults(ctx, api, target, flashAfterBuild)
	applyTargetDefaults(cmd, operatorConfig, &req)

	// Add flash configuration if enabled
	if flashAfterBuild {
		if exportOCI == "" && !useInternalRegistry {
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

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	fmt.Printf("To follow this build later: caib logs %s\n", resp.Name)

	if waitForBuild || followLogs || outputDir != "" || flashAfterBuild {
		waitForBuildCompletion(ctx, api, resp.Name)
	}

	displayBuildResults(ctx, api, resp.Name)
}

func pullOCIArtifact(ociRef, destPath, username, password string, insecureSkipTLS bool) error {
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

	// Configure TLS verification
	if insecureSkipTLS {
		systemCtx.OCIInsecureSkipTLSVerify = insecureSkipTLS
		systemCtx.DockerInsecureSkipTLSVerify = types.OptionalBoolTrue
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

	// Extract the artifact blob(s) to the destination
	if err := extractOCIArtifactBlob(tempDir, destPath); err != nil {
		return fmt.Errorf("extract artifact: %w", err)
	}

	// Check if destPath is a directory (multi-layer) or file (single-layer)
	info, err := os.Stat(destPath)
	if err != nil {
		return fmt.Errorf("stat destination: %w", err)
	}

	if info.IsDir() {
		// Multi-layer: files already extracted with correct names
		fmt.Printf("Downloaded multi-layer artifact to %s/\n", destPath)
	} else {
		// Single-layer: check if file is compressed and add appropriate extension if needed
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
	}

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

	// Check if this is a multi-layer artifact
	isMultiLayer := manifest.Annotations["automotive.sdv.cloud.redhat.com/multi-layer"] == "true"

	if isMultiLayer {
		// Multi-layer: extract all layers to destPath directory
		fmt.Printf("Multi-layer artifact detected (%d layers)\n", len(manifest.Layers))

		// Create destination directory
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("create destination directory: %w", err)
		}

		// Track sanitized filenames to prevent silent overwrites
		seenFilenames := make(map[string]struct {
			layerIndex int
			digest     string
			title      string
		})

		for i, layer := range manifest.Layers {
			layerDigest := strings.TrimPrefix(layer.Digest, "sha256:")
			layerPath := filepath.Join(ociLayoutPath, "blobs", "sha256", layerDigest)

			// Get filename from annotation, fallback to layer index
			originalTitle := layer.Annotations["org.opencontainers.image.title"]

			// Sanitize filename to prevent path traversal attacks
			filename := sanitizeFilename(originalTitle, i)

			// Check for duplicate sanitized filenames
			if prev, exists := seenFilenames[filename]; exists {
				return fmt.Errorf("duplicate sanitized filename '%s' for layer %d (digest: %s, title: %s) conflicts with layer %d (digest: %s, title: %s)",
					filename, i, layer.Digest, originalTitle, prev.layerIndex, prev.digest, prev.title)
			}

			// Record this filename as seen
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

	// Single-layer: extract to destPath file (original behavior)
	layerDigest := strings.TrimPrefix(manifest.Layers[0].Digest, "sha256:")
	layerPath := filepath.Join(ociLayoutPath, "blobs", "sha256", layerDigest)

	return copyFile(layerPath, destPath)
}

// sanitizeBuildName converts a string into a valid RFC 1123 subdomain name
// suitable for use as a Kubernetes resource name. It lowercases the input,
// replaces invalid characters (underscores, dots, etc.) with hyphens,
// collapses consecutive hyphens, and trims leading/trailing hyphens.
func sanitizeBuildName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	// Collapse consecutive hyphens
	result := multiHyphenRe.ReplaceAllString(b.String(), "-")
	return strings.Trim(result, "-")
}

// validateBuildName checks a user-provided build name and exits if it
// contains only invalid characters after sanitization.
var validManifestSuffixes = []string{".aib.yml", ".mpp.yml"}

func validateManifestSuffix(filename string) {
	for _, suffix := range validManifestSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return
		}
	}
	handleError(fmt.Errorf("manifest file %q must have one of the following extensions: %s",
		filepath.Base(filename), strings.Join(validManifestSuffixes, ", ")))
}

func validateBuildName(name string) {
	if sanitizeBuildName(name) == "" {
		fmt.Printf("Error: build name '%s' contains only invalid characters\n", name)
		fmt.Println("Build names must contain at least one letter or number")
		os.Exit(1)
	}
}

// sanitizeFilename validates and sanitizes a filename from OCI layer annotations.
// Returns a safe filename, falling back to "layer-N.bin" if the input is invalid.
// This prevents path traversal attacks by rejecting:
// - Empty filenames
// - Absolute paths
// - Paths containing ".." components
// - Paths containing null bytes
// - Filenames that differ from their base name (contain path separators)
func sanitizeFilename(filename string, layerIndex int) string {
	fallback := fmt.Sprintf("layer-%d.bin", layerIndex)

	// Reject empty filenames
	if filename == "" {
		return fallback
	}

	// Reject filenames containing null bytes
	if strings.ContainsRune(filename, 0) {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename contains null bytes, using fallback\n", layerIndex)
		return fallback
	}

	// Reject absolute paths
	if filepath.IsAbs(filename) {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename is absolute path, using fallback\n", layerIndex)
		return fallback
	}

	// Reject paths containing ".."
	if strings.Contains(filename, "..") {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename contains '..', using fallback\n", layerIndex)
		return fallback
	}

	// Extract base name and reject if it differs (contains path separators)
	base := filepath.Base(filename)
	if base != filename {
		fmt.Fprintf(os.Stderr, "Warning: layer %d filename contains path separators, using basename: %s\n", layerIndex, base)
		filename = base
	}

	// Final safety check: base should not be empty, ".", or ".."
	if filename == "" || filename == "." || filename == ".." {
		return fallback
	}

	return filename
}

// copyFile copies a file from src to dst
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

// runBuildDev handles the 'build-dev' command (traditional ostree/package builds)
func runBuildDev(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	manifest = args[0]

	validateManifestSuffix(manifest)

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}

	if useInternalRegistry {
		if exportOCI != "" {
			handleError(fmt.Errorf("--internal-registry cannot be used with --push"))
		}
	} else {
		validateOutputRequiresPush(outputDir, exportOCI, "--push")
	}

	// Auto-generate build name if not provided
	if buildName == "" {
		base := filepath.Base(manifest)
		for _, suffix := range validManifestSuffixes {
			base = strings.TrimSuffix(base, suffix)
		}
		buildName = fmt.Sprintf("%s-%s", sanitizeBuildName(base), time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	} else {
		validateBuildName(buildName)
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

	applyRegistryCredentialsToRequest(&req)

	// Fetch target defaults and apply them to the request
	operatorConfig := fetchTargetDefaults(ctx, api, target, flashAfterBuild)
	applyTargetDefaults(cmd, operatorConfig, &req)

	// Add flash configuration if enabled
	if flashAfterBuild {
		if exportOCI == "" && !useInternalRegistry {
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

	resp, err := api.CreateBuild(ctx, req)
	if err != nil {
		handleError(err)
	}
	fmt.Printf("Build %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	fmt.Printf("To follow this build later: caib logs %s\n", resp.Name)

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

	displayBuildResults(ctx, api, resp.Name)
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

	logTransport := &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       2 * time.Minute,
	}
	if insecureSkipTLS {
		logTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// No hard Timeout on the client: log streams can run for the entire
	// build duration (often >10 min). The build's context timeout
	// (timeoutCtx) already governs cancellation via the request context.
	logClient := &http.Client{
		Transport: logTransport,
	}
	streamState := &logStreamState{}
	pb := ui.NewProgressBar()

	for {
		select {
		case <-timeoutCtx.Done():
			pb.Clear()
			handleError(fmt.Errorf("timed out waiting for build"))
		case <-ticker.C:
			reqCtx, cancelReq := context.WithTimeout(ctx, 2*time.Minute)
			st, err := api.GetBuild(reqCtx, name)
			cancelReq()
			if err != nil {
				fmt.Printf("status check failed: %v\n", err)
				continue
			}

			// Progress bar mode: when not following logs, poll progress endpoint
			if !followLogs && !streamState.active {
				progressCtx, progressCancel := context.WithTimeout(ctx, 10*time.Second)
				progress, _ := api.GetBuildProgress(progressCtx, name)
				progressCancel()
				// Use phase from progress response (fresher than GetBuild)
				displayPhase := st.Phase
				var step *buildapitypes.BuildStep
				if progress != nil {
					step = progress.Step
					if progress.Phase != "" {
						displayPhase = progress.Phase
					}
				}
				pb.Render(displayPhase, step)
			} else if !streamState.active && (!userFollowRequested || !streamState.canRetry()) {
				// Fallback: text status when streaming is not active
				if st.Phase != lastPhase || st.Message != lastMessage {
					fmt.Printf("status: %s - %s\n", st.Phase, st.Message)
					lastPhase = st.Phase
					lastMessage = st.Message
				}
			}

			// Handle terminal build states
			if st.Phase == phaseCompleted {
				pb.Clear()
				flashWasExecuted := strings.Contains(st.Message, "flash")
				if flashWasExecuted {
					bannerColor := func(a ...any) string { return fmt.Sprint(a...) }
					infoColor := func(a ...any) string { return fmt.Sprint(a...) }
					commandColor := func(a ...any) string { return fmt.Sprint(a...) }
					if supportsColorOutput() {
						bannerColor = color.New(color.FgHiGreen, color.Bold).SprintFunc()
						infoColor = color.New(color.FgHiWhite).SprintFunc()
						commandColor = color.New(color.FgHiYellow, color.Bold).SprintFunc()
					}

					divider := strings.Repeat("=", 50)
					fmt.Println("\n" + bannerColor(divider))
					fmt.Println(bannerColor("Build and flash completed successfully!"))
					fmt.Println(bannerColor(divider))
					fmt.Println("\n" + infoColor("The device has been flashed and a lease has been acquired."))
					// Get lease ID from API response (preferred) or fall back to log parsing
					leaseID := ""
					if st.Jumpstarter != nil && st.Jumpstarter.LeaseID != "" {
						leaseID = st.Jumpstarter.LeaseID
					} else if streamState.leaseID != "" {
						leaseID = streamState.leaseID
					}
					if leaseID != "" {
						fmt.Printf("\n%s %s\n", infoColor("Lease ID:"), commandColor(leaseID))
						fmt.Printf("\n%s\n", infoColor("To access the device:"))
						fmt.Printf("  %s\n", commandColor(fmt.Sprintf("jmp shell --lease %s", leaseID)))
						fmt.Printf("\n%s\n", infoColor("To release the lease when done:"))
						fmt.Printf("  %s\n", commandColor(fmt.Sprintf("jmp delete leases %s", leaseID)))
					} else {
						fmt.Println(infoColor("Check the logs above for lease details, or use:"))
						fmt.Printf("  %s\n", commandColor("jmp list leases"))
						fmt.Printf("\n%s\n", infoColor("To access the device:"))
						fmt.Printf("  %s\n", commandColor("jmp shell --lease <lease-id>"))
						fmt.Printf("\n%s\n", infoColor("To release the lease when done:"))
						fmt.Printf("  %s\n", commandColor("jmp delete leases <lease-id>"))
					}
				} else {
					fmt.Println("Build completed successfully!")
					if flashAfterBuild {
						fmt.Println("\nWarning: --flash was requested but flash was not executed.")
						fmt.Println("This may be because no Jumpstarter target mapping exists for this target.")
						fmt.Println("Check OperatorConfig for JumpstarterTargetMappings configuration.")
					}
					// Show flash instructions with colors
					displayFlashInstructions(st, false)
				}
				return
			}
			if st.Phase == phaseFailed {
				pb.Clear()
				// Provide phase-specific error messages
				errPrefix := errPrefixBuild
				isFlashFailure := false

				if strings.Contains(strings.ToLower(st.Message), errPrefixFlash) {
					errPrefix = errPrefixFlash
					isFlashFailure = true
				} else if strings.Contains(strings.ToLower(st.Message), errPrefixPush) {
					errPrefix = errPrefixPush
				} else if lastPhase == phaseFlashing {
					errPrefix = errPrefixFlash
					isFlashFailure = true
				} else if lastPhase == "Pushing" {
					errPrefix = errPrefixPush
				} else if flashAfterBuild && (lastPhase == phaseFlashing || strings.Contains(strings.ToLower(st.Message), errPrefixFlash)) {
					// Only treat as flash failure if we actually reached a flash-related phase
					// or the error message explicitly indicates a flash error
					errPrefix = errPrefixFlash
					isFlashFailure = true
				}

				err := fmt.Errorf("%s failed: %s", errPrefix, st.Message)
				if isFlashFailure {
					handleFlashError(err, st)
				} else {
					handleError(err)
				}
			}

			// Attempt log streaming for active builds
			if !followLogs || streamState.active {
				continue
			}

			// If the stream ended cleanly but the build is still active
			// (e.g. stream covered build tasks but flash pod hadn't appeared yet),
			// allow reconnection so we pick up remaining task logs.
			if streamState.completed && isBuildActive(st.Phase) {
				streamState.completed = false
				streamState.retryCount = 0
			}

			if !streamState.canRetry() {
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
	return phase == "Building" || phase == "Running" || phase == "Uploading" || phase == phaseFlashing
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
	firstStream := state.startTime.IsZero()
	if firstStream {
		state.startTime = time.Now()
	}

	if firstStream {
		fmt.Println("Streaming logs...")
	}
	state.active = true
	state.reset()

	// Use line-by-line streaming for real-time output
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // Handle long lines
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		// Advance startTime so reconnections only fetch new logs
		state.startTime = time.Now()

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

// displayFlashInstructions shows colorful flashing instructions when flash is not executed or fails
func displayFlashInstructions(st *buildapitypes.BuildResponse, isFailure bool) {
	if st.Jumpstarter == nil || !st.Jumpstarter.Available {
		return
	}

	// Only show instructions if this target actually has a mapping
	// (i.e., there's a selector or flash command configured for it)
	if st.Jumpstarter.ExporterSelector == "" && st.Jumpstarter.FlashCmd == "" {
		return
	}

	// Don't show jumpstarter instructions if user requested a download - they have the artifact locally
	if outputDir != "" {
		return
	}

	colorsSupported := supportsColorOutput()

	var headerColor, commandColor, infoColor func(...any) string
	var headerPrefix, commandPrefix string

	if isFailure {
		if colorsSupported {
			headerColor = color.New(color.FgHiRed, color.Bold).SprintFunc()
			commandColor = color.New(color.FgHiYellow, color.Bold).SprintFunc()
			infoColor = color.New(color.FgHiWhite).SprintFunc()
		} else {
			headerColor = func(a ...any) string { return fmt.Sprint(a...) }
			commandColor = func(a ...any) string { return fmt.Sprint(a...) }
			infoColor = func(a ...any) string { return fmt.Sprint(a...) }
			headerPrefix = "[!] "
			commandPrefix = ">> "
		}
	} else {
		if colorsSupported {
			// Success mode: use high-contrast, readable colors
			headerColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
			commandColor = color.New(color.FgHiGreen, color.Bold).SprintFunc()
			infoColor = color.New(color.FgHiYellow).SprintFunc()
		} else {
			// Fallback with symbols for no-color terminals
			headerColor = func(a ...any) string { return fmt.Sprint(a...) }
			commandColor = func(a ...any) string { return fmt.Sprint(a...) }
			infoColor = func(a ...any) string { return fmt.Sprint(a...) }
			headerPrefix = "[*] "
			commandPrefix = ">> "
		}
	}

	if isFailure {
		fmt.Printf("\n%s%s\n", headerPrefix, headerColor("Manual Flash Required"))
		fmt.Printf("%s\n", infoColor("Flash failed, but you can flash manually using Jumpstarter:"))
	} else {
		fmt.Printf("%s\n", infoColor("Jumpstarter is available for flashing:"))
	}

	if st.Jumpstarter.ExporterSelector != "" {
		fmt.Printf("  %s %s\n", infoColor("Exporter selector:"), st.Jumpstarter.ExporterSelector)
	}

	if st.Jumpstarter.FlashCmd != "" {
		fmt.Printf("  %s\n", infoColor("Flash command:"))
		fmt.Printf("    %s%s\n", commandPrefix, commandColor(st.Jumpstarter.FlashCmd))
	}
}

func handleFlashError(err error, st *buildapitypes.BuildResponse) {
	fmt.Printf("Error: %v\n", err)

	// Show flash instructions to help user flash manually after failure
	if flashAfterBuild && st != nil {
		displayFlashInstructions(st, true)
	}

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
		fmt.Println("Error: --server is required (or set CAIB_SERVER, or run 'caib login <server-url>')")
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

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to flush output: %v\n", err)
		}
	}()

	if _, err := fmt.Fprintln(w, "NAME\tSTATUS\tAGE\tREQUESTED BY\tARTIFACT"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write header: %v\n", err)
		return
	}
	for _, it := range items {
		artifact := it.DiskImage
		if artifact == "" {
			artifact = it.ContainerImage
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", it.Name, it.Phase, formatAge(it.CreatedAt), it.RequestedBy, artifact); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write row: %v\n", err)
		}
	}
}

func runShow(_ *cobra.Command, args []string) {
	ctx := context.Background()
	showBuildName := args[0]

	if strings.TrimSpace(serverURL) == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}

	var st *buildapitypes.BuildResponse
	err := executeWithReauth(serverURL, &authToken, func(api *buildapiclient.Client) error {
		var err error
		st, err = api.GetBuild(ctx, showBuildName)
		return err
	})
	if err != nil {
		handleError(fmt.Errorf("error getting ImageBuild %s: %w", showBuildName, err))
	}

	// Backward-compatible fallback for older API servers that do not yet include response parameters.
	if st.Parameters == nil {
		_ = executeWithReauth(serverURL, &authToken, func(api *buildapiclient.Client) error {
			tpl, err := api.GetBuildTemplate(ctx, showBuildName)
			if err != nil {
				return err
			}
			st.Parameters = buildParametersFromTemplate(tpl)
			return nil
		})
	}

	switch strings.ToLower(showOutputFormat) {
	case "json":
		out, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("error rendering JSON output: %w", err))
		}
		fmt.Println(string(out))
	case "yaml", "yml":
		out, err := yaml.Marshal(st)
		if err != nil {
			handleError(fmt.Errorf("error rendering YAML output: %w", err))
		}
		fmt.Print(string(out))
	case "table":
		printBuildDetails(st)
	default:
		handleError(fmt.Errorf("invalid output format %q (supported: table, json, yaml)", showOutputFormat))
	}
}

func buildParametersFromTemplate(tpl *buildapitypes.BuildTemplateResponse) *buildapitypes.BuildParameters {
	if tpl == nil {
		return nil
	}

	params := &buildapitypes.BuildParameters{
		Architecture:           string(tpl.Architecture),
		Distro:                 string(tpl.Distro),
		Target:                 string(tpl.Target),
		Mode:                   string(tpl.Mode),
		ExportFormat:           string(tpl.ExportFormat),
		Compression:            tpl.Compression,
		StorageClass:           tpl.StorageClass,
		AutomotiveImageBuilder: tpl.AutomotiveImageBuilder,
		BuilderImage:           tpl.BuilderImage,
		ContainerRef:           tpl.ContainerRef,
		BuildDiskImage:         tpl.BuildDiskImage,
		FlashEnabled:           tpl.FlashEnabled,
		FlashLeaseDuration:     tpl.FlashLeaseDuration,
		UseServiceAccountAuth:  tpl.UseInternalRegistry,
	}

	if strings.TrimSpace(params.Architecture) == "" &&
		strings.TrimSpace(params.Distro) == "" &&
		strings.TrimSpace(params.Target) == "" &&
		strings.TrimSpace(params.Mode) == "" &&
		strings.TrimSpace(params.ExportFormat) == "" &&
		strings.TrimSpace(params.Compression) == "" &&
		strings.TrimSpace(params.StorageClass) == "" &&
		strings.TrimSpace(params.AutomotiveImageBuilder) == "" &&
		strings.TrimSpace(params.BuilderImage) == "" &&
		strings.TrimSpace(params.ContainerRef) == "" &&
		strings.TrimSpace(params.FlashLeaseDuration) == "" &&
		!params.BuildDiskImage &&
		!params.FlashEnabled &&
		!params.UseServiceAccountAuth {
		return nil
	}

	return params
}

func printBuildDetails(st *buildapitypes.BuildResponse) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to flush output: %v\n", err)
		}
	}()

	rows := [][2]string{
		{"Name", st.Name},
		{"Phase", st.Phase},
		{"Message", st.Message},
		{"Requested By", valueOrDash(st.RequestedBy)},
		{"Start Time", valueOrDash(st.StartTime)},
		{"Completion Time", valueOrDash(st.CompletionTime)},
		{"Container Image", valueOrDash(st.ContainerImage)},
		{"Disk Image", valueOrDash(st.DiskImage)},
		{"Warning", valueOrDash(st.Warning)},
	}

	if st.Parameters != nil {
		rows = append(rows,
			[2]string{"Architecture", valueOrDash(st.Parameters.Architecture)},
			[2]string{"Distro", valueOrDash(st.Parameters.Distro)},
			[2]string{"Target", valueOrDash(st.Parameters.Target)},
			[2]string{"Mode", valueOrDash(st.Parameters.Mode)},
			[2]string{"Export Format", valueOrDash(st.Parameters.ExportFormat)},
			[2]string{"Compression", valueOrDash(st.Parameters.Compression)},
			[2]string{"Storage Class", valueOrDash(st.Parameters.StorageClass)},
			[2]string{"AIB Image", valueOrDash(st.Parameters.AutomotiveImageBuilder)},
			[2]string{"Builder Image", valueOrDash(st.Parameters.BuilderImage)},
		)
	}

	if st.Jumpstarter != nil {
		rows = append(rows,
			[2]string{"Jumpstarter Available", fmt.Sprintf("%t", st.Jumpstarter.Available)},
			[2]string{"Jumpstarter Exporter", valueOrDash(st.Jumpstarter.ExporterSelector)},
			[2]string{"Jumpstarter Flash Cmd", valueOrDash(st.Jumpstarter.FlashCmd)},
			[2]string{"Jumpstarter Lease ID", valueOrDash(st.Jumpstarter.LeaseID)},
		)
	}

	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", row[0], row[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write output row: %v\n", err)
			return
		}
	}
}

func runLogs(_ *cobra.Command, args []string) {
	ctx := context.Background()
	name := args[0]

	if strings.TrimSpace(serverURL) == "" {
		fmt.Println("Error: --server is required (or set CAIB_SERVER, or run 'caib login <server-url>')")
		os.Exit(1)
	}

	api, err := createBuildAPIClient(serverURL, &authToken)
	if err != nil {
		handleError(err)
	}

	// Verify the build exists and show current status
	st, err := api.GetBuild(ctx, name)
	if err != nil {
		handleError(fmt.Errorf("failed to get build: %w", err))
	}
	fmt.Printf("Build %s: %s - %s\n", name, st.Phase, st.Message)

	if st.Phase == phaseCompleted || st.Phase == phaseFailed {
		// Build is finished — attempt to fetch logs once (pods may have been GC'd)
		logTransport := &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
		}
		if insecureSkipTLS {
			logTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		logClient := &http.Client{
			Timeout:   2 * time.Minute,
			Transport: logTransport,
		}
		streamState := &logStreamState{}
		if err := tryLogStreaming(ctx, logClient, name, streamState); err != nil {
			fmt.Printf("Could not retrieve logs (pods may have been cleaned up). Use 'caib show %s' for details.\n", name)
		}
		return
	}

	followLogs = true
	waitForBuildCompletion(ctx, api, name)
	displayBuildResults(ctx, api, name)
}

func valueOrDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func formatAge(rfcTime string) string {
	t, err := time.Parse(time.RFC3339, rfcTime)
	if err != nil {
		return rfcTime
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func runDownload(_ *cobra.Command, args []string) {
	ctx := context.Background()
	downloadBuildName := args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}

	if outputDir == "" {
		handleError(fmt.Errorf("--output / -o is required"))
	}

	var st *buildapitypes.BuildResponse
	err := executeWithReauth(serverURL, &authToken, func(api *buildapiclient.Client) error {
		var err error
		st, err = api.GetBuild(ctx, downloadBuildName)
		return err
	})
	if err != nil {
		handleError(fmt.Errorf("error getting build %s: %w", downloadBuildName, err))
	}

	if st.Phase != phaseCompleted {
		handleError(fmt.Errorf("build %s is not completed (phase: %s), cannot download artifacts", downloadBuildName, st.Phase))
	}

	ociRef := st.DiskImage
	if ociRef == "" {
		handleError(fmt.Errorf("build %s has no disk image artifact to download (no OCI export was configured)", downloadBuildName))
	}

	// Use API-minted token if available (internal registry builds),
	// otherwise fall back to environment credentials.
	registryUsername := ""
	registryPassword := ""
	if st.RegistryToken != "" {
		registryUsername = "serviceaccount"
		registryPassword = st.RegistryToken
	} else {
		var effectiveRegistryURL string
		effectiveRegistryURL, registryUsername, registryPassword = extractRegistryCredentials(ociRef, "")
		if err := validateRegistryCredentials(effectiveRegistryURL, registryUsername, registryPassword); err != nil {
			handleError(err)
		}
	}

	fmt.Printf("Downloading disk image from %s\n", ociRef)
	if err := pullOCIArtifact(ociRef, outputDir, registryUsername, registryPassword, insecureSkipTLS); err != nil {
		handleError(fmt.Errorf("download failed: %w", err))
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

	// Validate each part can be parsed as an integer
	if n, err := fmt.Sscanf(parts[0], "%d", &hours); n != 1 || err != nil {
		return time.Hour // Default 1 hour if hours is invalid
	}
	if n, err := fmt.Sscanf(parts[1], "%d", &mins); n != 1 || err != nil {
		return time.Hour // Default 1 hour if minutes is invalid
	}
	if n, err := fmt.Sscanf(parts[2], "%d", &secs); n != 1 || err != nil {
		return time.Hour // Default 1 hour if seconds is invalid
	}

	// Validate ranges to prevent negative or extremely large values
	if hours < 0 || hours > 8760 || mins < 0 || mins >= 60 || secs < 0 || secs >= 60 {
		return time.Hour // Default 1 hour if values are out of reasonable range
	}

	return time.Duration(hours)*time.Hour + time.Duration(mins)*time.Minute + time.Duration(secs)*time.Second
}

// runFlash handles the standalone 'flash' command
func runFlash(_ *cobra.Command, args []string) {
	ctx := context.Background()
	imageRef := args[0]

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
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

	flashLogTransport := &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       2 * time.Minute,
	}
	if insecureSkipTLS {
		flashLogTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// No hard Timeout on the client: flash operations can stream logs for
	// the entire lease duration (default 3 hours, user-configurable). The
	// flash's context timeout (timeoutCtx) already governs cancellation.
	logClient := &http.Client{
		Transport: flashLogTransport,
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
			if st.Phase == phaseCompleted {
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
