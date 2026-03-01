/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package container implements CLI commands for container image building.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	containersarchive "github.com/containers/storage/pkg/archive"
	"github.com/spf13/cobra"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/ui"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

// Container build command flags
var (
	serverURL              string
	authToken              string
	buildName              string
	containerBuildPush     string
	containerBuildFile     string
	containerBuildStrategy string
	containerBuildArgs     []string
	containerBuildTimeout  int
	architecture           string
	useInternalRegistry    bool
	registryAuthFile       string
	insecureSkipTLS        bool
)

const (
	containerBuildTotalSteps = 3
	archAMD64                = "amd64"
	archARM64                = "arm64"
	phaseCompleted           = "Completed"
	phaseFailed              = "Failed"
	phasePending             = "Pending"
	phaseUploading           = "Uploading"
)

// newBuildCmd creates the container build subcommand with required -f flag
func newBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build [context-dir]",
		Short: "Build a container image from a Containerfile using Shipwright",
		Long: `Build a container image from a Containerfile/Dockerfile using Shipwright (OpenShift Builds)
on the cluster. The build context directory is uploaded to the cluster and the image
is built and pushed to the specified registry.

Examples:
  # Build from current directory with explicit Containerfile
  caib container build -f Containerfile --push quay.io/myorg/myimage:latest

  # Build from a specific directory with custom Containerfile
  caib container build ./my-app -f Dockerfile.prod --push quay.io/myorg/myimage:v1

  # Build with build args
  caib container build -f Containerfile --push quay.io/myorg/myimage:latest --build-arg VERSION=1.0 --build-arg ENV=prod

  # Build and push to OpenShift internal registry
  caib container build -f Containerfile --internal-registry`,
		Args: cobra.MaximumNArgs(1),
		Run:  runBuildContainer,
	}

	cmd.Flags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
	cmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	cmd.Flags().StringVarP(&buildName, "name", "n", "", "name for the build (auto-generated if omitted)")
	cmd.Flags().StringVar(&containerBuildPush, "push", "", "push built image to registry (required unless --internal-registry)")
	cmd.Flags().StringVarP(&containerBuildFile, "containerfile", "f", "", "path to Containerfile (required)")
	cmd.Flags().StringVar(&containerBuildStrategy, "strategy", "buildah", "Shipwright build strategy name")
	cmd.Flags().StringArrayVar(&containerBuildArgs, "build-arg", []string{}, "build argument KEY=VALUE (can be repeated)")
	cmd.Flags().StringVarP(&architecture, "arch", "a", getDefaultArch(), "target architecture (amd64, arm64)")
	cmd.Flags().IntVar(&containerBuildTimeout, "timeout", 30, "build timeout in minutes")
	cmd.Flags().StringVar(
		&registryAuthFile,
		"registry-auth-file",
		"",
		"path to Docker/Podman auth file for push authentication (takes precedence over env vars and auto-discovery)",
	)
	cmd.Flags().BoolVar(&useInternalRegistry, "internal-registry", false, "push to OpenShift internal registry")

	_ = cmd.MarkFlagRequired("containerfile")

	return cmd
}

// getDefaultArch returns the default architecture for builds based on the host runtime
func getDefaultArch() string {
	switch runtime.GOARCH {
	case archARM64:
		return archARM64
	default:
		return archAMD64
	}
}

// runBuildContainer handles the container build command
func runBuildContainer(_ *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	contextDir := "."
	if len(args) > 0 {
		contextDir = args[0]
	}

	absContextDir, containerfile := resolveContainerBuildContext(contextDir)
	fmt.Printf("Context: %s\n", absContextDir)
	fmt.Printf("Containerfile: %s\n", filepath.Join(absContextDir, containerfile))

	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}

	if containerBuildPush != "" && useInternalRegistry {
		handleError(fmt.Errorf("--push and --internal-registry are mutually exclusive"))
	}
	if containerBuildPush == "" && !useInternalRegistry {
		handleError(fmt.Errorf("either --push or --internal-registry is required"))
	}

	if buildName == "" {
		dirName := filepath.Base(absContextDir)
		buildName = fmt.Sprintf("cb-%s-%s", sanitizeBuildName(dirName), time.Now().Format("20060102-150405"))
		fmt.Printf("Auto-generated build name: %s\n", buildName)
	} else {
		validateBuildName(buildName)
	}

	buildArgs := parseContainerBuildArgs(containerBuildArgs)

	var registryCreds *buildapitypes.RegistryCredentials
	if !useInternalRegistry {
		effectiveRegistryURL, registryUsername, registryPassword := registryauth.ExtractRegistryCredentials(containerBuildPush, "")
		var err error
		registryCreds, err = registryauth.ResolveRegistryCredentials(
			effectiveRegistryURL,
			registryUsername,
			registryPassword,
			registryAuthFile,
		)
		if err != nil {
			handleError(err)
		}
	}

	// Create the container build
	if useInternalRegistry {
		fmt.Println("Using OpenShift internal registry")
	}
	fmt.Println("Creating container build...")
	var createResp *buildapitypes.ContainerBuildResponse
	err := executeWithReauth(serverURL, &authToken, func(client *buildapiclient.Client) error {
		resp, cerr := client.CreateContainerBuild(ctx, buildapitypes.ContainerBuildRequest{
			Name:                buildName,
			Output:              containerBuildPush,
			Containerfile:       containerfile,
			Strategy:            containerBuildStrategy,
			BuildArgs:           buildArgs,
			Architecture:        architecture,
			Timeout:             int32(containerBuildTimeout),
			RegistryCredentials: registryCreds,
			UseInternalRegistry: useInternalRegistry,
		})
		if cerr != nil {
			return cerr
		}
		createResp = resp
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("failed to create container build: %w", err))
	}

	colorFormatter := NewColorFormatter()
	fmt.Printf("%s %s - %s\n", colorFormatter.LabelColor("Build "+createResp.Name+" accepted:"), createResp.Phase, createResp.Message)
	if createResp.OutputImage != "" {
		fmt.Printf("%s %s\n", colorFormatter.LabelColor("Output image:"), colorFormatter.ValueColor(createResp.OutputImage))
	}
	fmt.Printf("\n%s\n  %s\n\n", colorFormatter.LabelColor("View build logs:"), colorFormatter.CommandColor("caib container logs "+createResp.Name))

	// Create tarball and upload
	fmt.Printf("Packaging context directory: %s\n", absContextDir)
	tarball, err := createContextTarball(absContextDir)
	if err != nil {
		handleError(fmt.Errorf("failed to create context tarball: %w", err))
	}
	tarballPath := tarball.Name()
	if info, err := tarball.Stat(); err == nil {
		fmt.Printf("Context tarball: %s (%.1f MB)\n", tarballPath, float64(info.Size())/(1024*1024))
	}
	defer func() {
		if err := tarball.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close tarball: %v\n", err)
		}
		if err := os.Remove(tarballPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp tarball: %v\n", err)
		}
	}()

	pb := ui.NewProgressBar()
	pb.Render(phasePending, &buildapitypes.BuildStep{Done: 0, Total: 3, Stage: "Waiting for build pod"})

	waitForContainerBuildUploadReady(ctx, createResp.Name)

	pb.Render(phaseUploading, &buildapitypes.BuildStep{Done: 1, Total: 3, Stage: "Uploading build context"})

	uploadContainerBuildContext(ctx, createResp.Name, tarballPath)

	pb.Render("Building", &buildapitypes.BuildStep{Done: 2, Total: 3, Stage: "Building image"})

	// Poll until terminal
	finalStatus := waitForContainerBuildCompletion(ctx, createResp.Name, pb)

	pb.Clear()
	displayContainerBuildResult(finalStatus)
}

// resolveContainerBuildContext validates and resolves the context directory and Containerfile.
// Now requires explicit -f flag instead of auto-detection.
func resolveContainerBuildContext(contextDir string) (string, string) {
	absContextDir, err := filepath.Abs(contextDir)
	if err != nil {
		handleError(fmt.Errorf("invalid context directory: %w", err))
	}
	info, err := os.Stat(absContextDir)
	if err != nil || !info.IsDir() {
		handleError(fmt.Errorf("context directory does not exist or is not a directory: %s", absContextDir))
	}

	// Require explicit containerfile - no auto-detection
	containerfile := containerBuildFile
	if containerfile == "" {
		handleError(fmt.Errorf("--containerfile (-f) is required. Specify path to Containerfile or Dockerfile"))
	}

	cfPath := containerfile
	if !filepath.IsAbs(cfPath) {
		cfPath = filepath.Join(absContextDir, cfPath)
	}
	if _, err := os.Stat(cfPath); err != nil {
		handleError(fmt.Errorf("containerfile not found: %s", cfPath))
	}

	return absContextDir, containerfile
}

// parseContainerBuildArgs parses KEY=VALUE build arguments.
func parseContainerBuildArgs(rawArgs []string) map[string]string {
	buildArgs := make(map[string]string, len(rawArgs))
	for _, arg := range rawArgs {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			handleError(fmt.Errorf("invalid --build-arg format: %q (expected KEY=VALUE)", arg))
		}
		buildArgs[parts[0]] = parts[1]
	}
	return buildArgs
}

// waitForContainerBuildUploadReady polls until the build is ready to accept source upload.
func waitForContainerBuildUploadReady(ctx context.Context, name string) {
	uploadTimeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			handleError(fmt.Errorf("operation canceled"))
		case <-uploadTimeout:
			handleError(fmt.Errorf("timed out waiting for build to reach Uploading phase"))
		case <-ticker.C:
			var status *buildapitypes.ContainerBuildResponse
			err := executeWithReauth(serverURL, &authToken, func(client *buildapiclient.Client) error {
				s, serr := client.GetContainerBuild(ctx, name)
				if serr != nil {
					return serr
				}
				status = s
				return nil
			})
			if err != nil {
				handleError(fmt.Errorf("failed to get build status: %w", err))
			}
			if status.Phase == phaseUploading {
				return
			}
			if isContainerBuildTerminal(status.Phase) {
				handleError(fmt.Errorf("build terminated before uploading: %s - %s", status.Phase, status.Message))
			}
		}
	}
}

// isRetryableUploadError checks if an error represents a temporary condition that should be retried.
func isRetryableUploadError(err error) bool {
	errMsg := err.Error()
	return strings.Contains(errMsg, "upload context failed: 503 Service Unavailable")
}

// uploadContainerBuildContext uploads the tarball to the build API, retrying on 503 (waiter not ready).
func uploadContainerBuildContext(ctx context.Context, name string, tarballPath string) {
	uploadDeadline := time.Now().Add(10 * time.Minute)
	for {
		if ctx.Err() != nil {
			handleError(fmt.Errorf("operation canceled"))
		}

		tarball, err := os.Open(tarballPath)
		if err != nil {
			handleError(fmt.Errorf("failed to open tarball: %w", err))
		}

		err = executeWithReauth(serverURL, &authToken, func(client *buildapiclient.Client) error {
			// Seek to beginning in case of auth retries
			_, seekErr := tarball.Seek(0, io.SeekStart)
			if seekErr != nil {
				return fmt.Errorf("failed to seek to beginning of tarball: %w", seekErr)
			}
			return client.UploadContainerBuildContext(ctx, name, tarball)
		})

		_ = tarball.Close()

		if err == nil {
			break
		}

		if time.Now().After(uploadDeadline) {
			handleError(fmt.Errorf("upload timed out after 10 minutes: %w", err))
		}
		if isRetryableUploadError(err) {
			time.Sleep(5 * time.Second)
			continue
		}
		handleError(fmt.Errorf("failed to upload build context: %w", err))
	}
}

// isContainerBuildTerminal returns true if the build phase is terminal.
func isContainerBuildTerminal(phase string) bool {
	return phase == phaseCompleted || phase == phaseFailed
}

// getContainerBuildStatus retrieves the current build status.
func getContainerBuildStatus(ctx context.Context, name string) (*buildapitypes.ContainerBuildResponse, error) {
	var status *buildapitypes.ContainerBuildResponse
	err := executeWithReauth(serverURL, &authToken, func(client *buildapiclient.Client) error {
		s, serr := client.GetContainerBuild(ctx, name)
		if serr != nil {
			return serr
		}
		status = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return status, nil
}

// waitForContainerBuildCompletion polls until the build reaches a terminal state.
func waitForContainerBuildCompletion(ctx context.Context, name string, pb *ui.ProgressBar) *buildapitypes.ContainerBuildResponse {
	// Add extra headroom for queueing and status propagation beyond task timeout.
	waitTimeout := time.Duration(containerBuildTimeout+10) * time.Minute
	if waitTimeout < 15*time.Minute {
		waitTimeout = 15 * time.Minute
	}

	timeout := time.After(waitTimeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			handleError(fmt.Errorf("operation canceled"))
		case <-timeout:
			handleError(fmt.Errorf("build timed out after %v", waitTimeout))
		case <-ticker.C:
			status, err := getContainerBuildStatus(ctx, name)
			if err != nil {
				pb.Render("Building", &buildapitypes.BuildStep{
					Done:  2,
					Total: containerBuildTotalSteps,
					Stage: fmt.Sprintf("Status check failed: %v", err),
				})
				continue
			}

			done := containerBuildPhaseStep(status.Phase)
			pb.Render(status.Phase, &buildapitypes.BuildStep{
				Done:  done,
				Total: containerBuildTotalSteps,
				Stage: status.Message,
			})

			if isContainerBuildTerminal(status.Phase) {
				return status
			}
		}
	}
}

// displayContainerBuildResult shows the final build result.
func displayContainerBuildResult(finalStatus *buildapitypes.ContainerBuildResponse) {
	colorFormatter := NewColorFormatter()

	fmt.Printf("\n%s %s\n", colorFormatter.LabelColor("Build "+finalStatus.Name+":"), finalStatus.Phase)
	if finalStatus.Message != "" {
		fmt.Printf("%s %s\n", colorFormatter.LabelColor("Message:"), finalStatus.Message)
	}
	if finalStatus.OutputImage != "" {
		fmt.Printf("%s %s\n", colorFormatter.LabelColor("Output image:"), colorFormatter.ValueColor(finalStatus.OutputImage))
	}
	if finalStatus.RegistryToken != "" {
		credsFile, err := writeRegistryCredentialsFile(finalStatus.RegistryToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write registry credentials file: %v\n", err)
			fmt.Printf("\n%s\n", colorFormatter.LabelColor("Registry credentials (valid ~4 hours):"))
			fmt.Printf("  %s %s\n", colorFormatter.LabelColor("Username:"), colorFormatter.ValueColor("serviceaccount"))
			fmt.Printf("  %s %s\n", colorFormatter.LabelColor("Token:"), colorFormatter.ValueColor(finalStatus.RegistryToken))
			fmt.Printf("\n%s\n", colorFormatter.LabelColor("To pull this image:"))
			fmt.Printf("  %s\n", colorFormatter.CommandColor(
				fmt.Sprintf("podman pull --creds serviceaccount:<token> %s", finalStatus.OutputImage)))
		} else {
			fmt.Printf("\n%s %s (valid ~4 hours)\n",
				colorFormatter.LabelColor("Registry credentials written to:"),
				colorFormatter.ValueColor(credsFile))
			fmt.Printf("\n%s\n", colorFormatter.LabelColor("To pull this image:"))
			fmt.Printf("  %s\n", colorFormatter.CommandColor(
				fmt.Sprintf("podman pull --creds serviceaccount:$(jq -r .token %s) %s", credsFile, finalStatus.OutputImage)))
		}
	}
	switch finalStatus.Phase {
	case phaseFailed:
		fmt.Printf("\n%s\n  %s\n", colorFormatter.LabelColor("View build logs:"), colorFormatter.CommandColor("caib container logs "+finalStatus.Name))
		handleError(fmt.Errorf("build failed"))
	case phaseCompleted:
		fmt.Printf("\n%s %s\n", colorFormatter.ValueColor("✓"), colorFormatter.ValueColor("Build completed successfully!"))
	default:
	}
}

// writeRegistryCredentialsFile writes registry credentials to a temporary file.
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

// containerBuildPhaseStep maps container build phases to progress step numbers.
func containerBuildPhaseStep(phase string) int {
	switch phase {
	case phasePending:
		return 0
	case phaseUploading:
		return 1
	case "Building":
		return 2
	case phaseCompleted, phaseFailed:
		return containerBuildTotalSteps
	default:
		return 1
	}
}

// createContextTarball creates a tar archive of a directory and returns a reader.
func createContextTarball(contextDir string) (*os.File, error) {
	tmpFile, err := os.CreateTemp("", "caib-context-*.tar")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Load ignore patterns with gitignore support
	ignorePatterns, err := LoadIgnorePatterns(contextDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load ignore patterns: %v\n", err)
		ignorePatterns = []string{".git", ".svn", "node_modules"}
	}

	tarOpts := &containersarchive.TarOptions{
		IncludeFiles:    []string{"."},
		ExcludePatterns: ignorePatterns,
		Compression:     containersarchive.Uncompressed,
	}

	tarReader, err := containersarchive.TarWithOptions(contextDir, tarOpts)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to create tar stream: %w", err)
	}
	defer func() { _ = tarReader.Close() }()

	_, err = io.Copy(tmpFile, tarReader)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to create tar archive: %w", err)
	}

	if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to seek to beginning of file: %w", err)
	}

	return tmpFile, nil
}
