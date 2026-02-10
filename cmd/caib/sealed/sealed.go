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
	sealedAIBImage   string
	sealedVerbose    bool
	sealedExtraArgs  []string
	sealedServerURL  string
	sealedAuthToken  string
	sealedWait       bool
	sealedFollowLogs bool
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
	cmd.Flags().BoolVar(&sealedVerbose, "verbose", false, "Verbose AIB output")
	cmd.Flags().StringArrayVar(&sealedExtraArgs, "extra-args", nil, "Extra arguments to pass to AIB (repeatable)")
}

// addSealedServerFlags adds flags for running sealed operations on the cluster via Build API
func addSealedServerFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sealedServerURL, "server", config.DefaultServer(), "Build API server URL (if set, run on cluster instead of locally)")
	cmd.Flags().StringVar(&sealedAuthToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for API authentication")
	cmd.Flags().BoolVarP(&sealedWait, "wait", "w", false, "Wait for sealed job to complete (when using --server)")
	cmd.Flags().BoolVarP(&sealedFollowLogs, "follow", "f", false, "Stream logs (when using --server)")
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
		AIBExtraArgs: sealedExtraArgs,
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

func waitForSealedCompletion(ctx context.Context, api *buildapiclient.Client, name string) {
	fmt.Println("Waiting for sealed job to complete...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeout := 2 * time.Hour
	deadline := time.Now().Add(timeout)
	var lastPhase string
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
		if sealedFollowLogs && (st.Phase == "Running" || st.Phase == "Pending") {
			streamSealedLogs(sealedServerURL, sealedAuthToken, name)
			sealedFollowLogs = false
		}
		<-ticker.C
	}
	fmt.Printf("Error: timed out after %v\n", timeout)
	os.Exit(1)
}

func streamSealedLogs(serverURL, token, name string) {
	logURL := strings.TrimRight(serverURL, "/") + "/v1/sealed/" + url.PathEscape(name) + "/logs?follow=1"
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, logURL, nil)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("log stream failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("log stream error: HTTP %d\n", resp.StatusCode)
		return
	}
	fmt.Println("Streaming logs...")
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	_ = scanner.Err()
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
