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

// Package sealed implements CLI commands for sealed image operations.
package sealed

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
)

const defaultAIBImage = "quay.io/centos-sig-automotive/automotive-image-builder:latest"

var (
	sealedAIBImage          string
	sealedBuilderImage      string
	sealedArchitecture      string
	sealedVerbose           bool
	sealedExtraArgs         []string
	sealedServerURL         string
	sealedAuthToken         string
	sealedWait              bool
	sealedFollowLogs        bool
	sealedKeySecret         string
	sealedKeyPasswordSecret string
	sealedKeyFile           string
	sealedKeyPassword       string
)

func containerTool() string {
	if t := os.Getenv("CONTAINER_TOOL"); t != "" {
		return t
	}
	return "podman"
}

// addSealedCommonFlags adds flags common to all sealed subcommands
func addSealedCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sealedAIBImage, "aib-image", defaultAIBImage, "AIB container image")
	cmd.Flags().StringVar(&sealedBuilderImage, "builder-image", "", "Builder container image for reseal operations (overrides --arch default)")
	cmd.Flags().StringVar(&sealedArchitecture, "arch", "", "Target architecture for default builder image (e.g., amd64, arm64); auto-detected if not set")
	cmd.Flags().BoolVar(&sealedVerbose, "verbose", false, "Verbose AIB output")
	cmd.Flags().StringArrayVar(&sealedExtraArgs, "extra-args", nil, "Extra arguments to pass to AIB (repeatable)")
}

// addSealedServerFlags adds flags for running sealed operations on the cluster via Build API
func addSealedServerFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sealedServerURL, "server", config.DefaultServer(), "Build API server URL (if set, run on cluster instead of locally)")
	cmd.Flags().StringVar(&sealedAuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for API authentication")
	cmd.Flags().BoolVarP(&sealedWait, "wait", "w", false, "Wait for sealed job to complete (when using --server)")
	cmd.Flags().BoolVarP(&sealedFollowLogs, "follow", "f", false, "Stream logs (when using --server)")
	cmd.Flags().StringVar(&sealedKeySecret, "key-secret", "", "Name of existing secret containing sealing key (data key 'private-key')")
	cmd.Flags().StringVar(&sealedKeyPasswordSecret, "key-password-secret", "", "Name of existing secret containing key password (data key 'password')")
	cmd.Flags().StringVar(&sealedKeyFile, "key-file", "", "Path to local PEM key file (uploaded to cluster automatically)")
	cmd.Flags().StringVar(&sealedKeyPassword, "key-password", "", "Password for encrypted key file (used with --key-file)")
}

// runAIB runs the AIB container with the given subcommand and args. workDir is a host path
// mounted at /workspace in the container; input paths in args should be under /workspace.
func runAIB(subcommand string, workDir string, args ...string) error {
	tool := containerTool()
	if _, err := exec.LookPath(tool); err != nil {
		return fmt.Errorf("%s not found: %w (set CONTAINER_TOOL for docker)", tool, err)
	}

	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("resolve work dir: %w", err)
	}
	if err := os.MkdirAll(absWork, 0755); err != nil {
		return fmt.Errorf("create work dir: %w", err)
	}

	aibArgs := []string{"run", "--rm"}
	aibArgs = append(aibArgs, "-v", absWork+":/workspace:rw")
	aibArgs = append(aibArgs, "--privileged")
	aibArgs = append(aibArgs, sealedAIBImage, "aib")
	if sealedVerbose {
		aibArgs = append(aibArgs, "--verbose")
	}
	aibArgs = append(aibArgs, subcommand)
	aibArgs = append(aibArgs, sealedExtraArgs...)
	aibArgs = append(aibArgs, args...)

	cmd := exec.Command(tool, aibArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("aib %s: %w", subcommand, err)
	}
	return nil
}

// toContainerPath returns a path suitable for use inside the container (forward slashes).
func toContainerPath(rel string) string {
	return "/workspace/" + strings.ReplaceAll(rel, "\\", "/")
}

// ensurePathInWorkspace returns an absolute path and ensures the path is under workDir (for safety).
// If path is already absolute and under workDir, it is returned as-is after cleaning.
// If path is relative, it is joined with workDir and returned.
func ensurePathInWorkspace(workDir, path string) (string, error) {
	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return "", err
	}
	var absPath string
	if filepath.IsAbs(path) {
		absPath = filepath.Clean(path)
		rel, err := filepath.Rel(absWork, absPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("path must be under work dir: %s", path)
		}
	} else {
		absPath = filepath.Join(absWork, path)
	}
	return absPath, nil
}

// runLocalTwoArgOp is a shared helper for local sealed operations that take an input and output path
// (e.g. prepare-reseal, reseal, extract-for-signing).
func runLocalTwoArgOp(subcommand, workDir, input, output string) error {
	if workDir == "" {
		workDir = "."
	}
	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	inPath, err := ensurePathInWorkspace(absWork, input)
	if err != nil {
		return err
	}
	if _, err := os.Stat(inPath); err != nil {
		return fmt.Errorf("input disk: %w", err)
	}
	outPath, err := ensurePathInWorkspace(absWork, output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	relIn, err := filepath.Rel(absWork, inPath)
	if err != nil {
		return fmt.Errorf("resolve relative input path: %w", err)
	}
	relOut, err := filepath.Rel(absWork, outPath)
	if err != nil {
		return fmt.Errorf("resolve relative output path: %w", err)
	}
	return runAIB(subcommand, absWork, toContainerPath(relIn), toContainerPath(relOut))
}

// registryFromRef extracts the registry host from an OCI reference (e.g. quay.io/org/img:tag -> quay.io).
func registryFromRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) < 2 {
		return "docker.io"
	}
	first := parts[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first
	}
	return "docker.io"
}

// sealedRegistryCredentials returns registry URL, username, password from env and refs for the API.
func sealedRegistryCredentials(inputRef, outputRef, signedRef string) (registryURL, username, password string) {
	username = strings.TrimSpace(os.Getenv("REGISTRY_USERNAME"))
	password = strings.TrimSpace(os.Getenv("REGISTRY_PASSWORD"))
	if username == "" || password == "" {
		return "", "", ""
	}
	for _, ref := range []string{inputRef, outputRef, signedRef} {
		if r := registryFromRef(ref); r != "" {
			return r, username, password
		}
	}
	return "", "", ""
}

// runSealedViaAPI creates a sealed job via the Build API and optionally waits and streams logs
func runSealedViaAPI(op buildapitypes.SealedOperation, inputRef, outputRef, signedRef string) error {
	if strings.TrimSpace(sealedServerURL) == "" {
		return fmt.Errorf("--server is required for cluster execution")
	}
	api, err := buildapiclient.New(sealedServerURL, buildapiclient.WithAuthToken(strings.TrimSpace(sealedAuthToken)))
	if err != nil {
		return err
	}
	ctx := context.Background()
	req := buildapitypes.SealedRequest{
		Operation:    op,
		InputRef:     inputRef,
		OutputRef:    outputRef,
		SignedRef:    signedRef,
		AIBImage:     sealedAIBImage,
		BuilderImage: sealedBuilderImage,
		Architecture: sealedArchitecture,
		AIBExtraArgs: sealedExtraArgs,
	}
	if regURL, user, pass := sealedRegistryCredentials(inputRef, outputRef, signedRef); regURL != "" && user != "" && pass != "" {
		req.RegistryCredentials = &buildapitypes.RegistryCredentials{
			Enabled:     true,
			AuthType:    "username-password",
			RegistryURL: regURL,
			Username:    user,
			Password:    pass,
		}
	}
	// --key-file: read local PEM file and send content via API (server creates the secret)
	if strings.TrimSpace(sealedKeyFile) != "" {
		keyData, err := os.ReadFile(strings.TrimSpace(sealedKeyFile))
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", sealedKeyFile, err)
		}
		req.KeyContent = string(keyData)
		if strings.TrimSpace(sealedKeyPassword) != "" {
			req.KeyPassword = strings.TrimSpace(sealedKeyPassword)
		}
	} else if strings.TrimSpace(sealedKeySecret) != "" {
		// --key-secret: reference an existing secret on the cluster
		req.KeySecretRef = strings.TrimSpace(sealedKeySecret)
		if strings.TrimSpace(sealedKeyPasswordSecret) != "" {
			req.KeyPasswordSecretRef = strings.TrimSpace(sealedKeyPasswordSecret)
		}
	}
	resp, err := api.CreateSealed(ctx, req)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed job %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)
	if sealedWait || sealedFollowLogs {
		waitForSealedCompletion(ctx, api, resp.Name)
	}
	return nil
}

const maxSealedLogRetries = 24 // ~2 minutes at 5s intervals

func waitForSealedCompletion(ctx context.Context, api *buildapiclient.Client, name string) {
	fmt.Println("Waiting for sealed job to complete...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeout := 2 * time.Hour
	deadline := time.Now().Add(timeout)
	var lastPhase string
	logRetries := 0
	logStreaming := false
	logRetryWarningShown := false
	for time.Now().Before(deadline) {
		st, err := api.GetSealed(ctx, name)
		if err != nil {
			fmt.Printf("status check failed: %v\n", err)
			<-ticker.C
			continue
		}
		if st.Phase != lastPhase {
			fmt.Printf("status: %s - %s\n", st.Phase, st.Message)
			lastPhase = st.Phase
		}
		if st.Phase == "Completed" {
			fmt.Println("Sealed job completed successfully.")
			if st.OutputRef != "" {
				fmt.Printf("Output: %s\n", st.OutputRef)
			}
			return
		}
		if st.Phase == "Failed" {
			fmt.Printf("Error: sealed job failed: %s\n", st.Message)
			os.Exit(1)
		}
		if sealedFollowLogs && !logStreaming && (st.Phase == "Running" || st.Phase == "Pending") {
			if logRetries < maxSealedLogRetries {
				err := streamSealedLogs(sealedServerURL, sealedAuthToken, name)
				if err != nil {
					logRetries++
					if !logRetryWarningShown {
						fmt.Printf("Waiting for logs... (attempt %d/%d)\n", logRetries, maxSealedLogRetries)
						logRetryWarningShown = true
					}
				} else {
					// Stream completed normally, don't retry
					logStreaming = true
				}
			} else if !logRetryWarningShown {
				fmt.Printf("Log streaming failed after %d attempts. Falling back to status updates.\n", maxSealedLogRetries)
				logRetryWarningShown = true
				sealedFollowLogs = false
			}
		}
		<-ticker.C
	}
	fmt.Printf("Error: timed out after %v\n", timeout)
	os.Exit(1)
}

// streamSealedLogs attempts to stream logs; returns nil on success, error if not ready yet
func streamSealedLogs(serverURL, token, name string) error {
	logURL := strings.TrimRight(serverURL, "/") + "/v1/sealed/" + url.PathEscape(name) + "/logs?follow=1"
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, logURL, nil)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("log stream failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		return fmt.Errorf("log endpoint not ready (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("log stream error: HTTP %d", resp.StatusCode)
	}
	fmt.Println("Streaming logs...")
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	_ = scanner.Err()
	return nil
}

func handleSealedError(err error) {
	fmt.Printf("Error: %v\n", err)
	os.Exit(1)
}

// NewSealedCmd creates the sealed parent command with subcommands
func NewSealedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sealed",
		Short: "Sealed image operations (prepare-reseal, reseal, extract-for-signing, inject-signed)",
		Long:  `Run AIB sealed-image workflow steps. With --server, runs on the cluster via Build API; otherwise runs locally using the AIB container. When using --server, input/output must be OCI references.`,
	}
	cmd.AddCommand(newPrepareResealCmd())
	cmd.AddCommand(newResealCmd())
	cmd.AddCommand(newExtractForSigningCmd())
	cmd.AddCommand(newInjectSignedCmd())
	return cmd
}
