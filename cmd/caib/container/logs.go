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

package container

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// logStreamState encapsulates state for log streaming with automatic reconnection
type logStreamState struct {
	retryCount   int
	warningShown bool
	startTime    time.Time
	completed    bool // Set when stream ends normally, prevents reconnection
}

const maxLogRetries = 24 // ~2 minutes at 5s intervals

// newLogsCmd creates the container logs subcommand
func newLogsCmd(defaultServer string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs <build-name>",
		Short: "Follow logs of a container build",
		Long: `Follow the log output of an active or completed container build.

Examples:
  # Follow logs of an active container build
  caib container logs my-build-20250101-120000

  # List container builds first, then follow one
  caib container list
  caib container logs <build-name>`,
		Args: cobra.ExactArgs(1),
		Run:  runContainerLogs,
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServer, "REST API server base URL")
	cmd.Flags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")

	return cmd
}

// runContainerLogs handles the container logs command
func runContainerLogs(_ *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	name := args[0]

	if strings.TrimSpace(serverURL) == "" {
		fmt.Println("Error: --server is required (or set CAIB_SERVER, or run 'caib login <server-url>')")
		os.Exit(1)
	}

	// Verify the build exists and show current status
	status, err := getContainerBuildStatus(ctx, name)
	if err != nil {
		handleError(fmt.Errorf("failed to get container build: %w", err))
	}
	fmt.Printf("Build %s: %s - %s\n", name, status.Phase, status.Message)

	logTransport := &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if insecureSkipTLS {
		logTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	logClient := &http.Client{
		Transport: logTransport,
	}

	if isContainerBuildTerminal(status.Phase) {
		// Build is finished — fetch logs once without follow mode (pods may have been GC'd)
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		streamState := &logStreamState{}
		if err := tryContainerLogStreaming(fetchCtx, logClient, name, streamState, false); err != nil {
			fmt.Printf("Could not retrieve logs (pods may have been cleaned up): %v\n", err)
		}
		return
	}

	// Build is still active — wait for logs to become available, then stream
	if status.Phase == phasePending || status.Phase == phaseUploading {
		fmt.Println("Waiting for build to start...")
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for status.Phase == phasePending || status.Phase == phaseUploading {
			<-ticker.C
			status, err = getContainerBuildStatus(ctx, name)
			if err != nil {
				continue
			}
			if isContainerBuildTerminal(status.Phase) {
				fmt.Printf("Build %s: %s - %s\n", name, status.Phase, status.Message)
				return
			}
		}
		fmt.Printf("Build %s: %s - %s\n", name, status.Phase, status.Message)
	}

	// Stream logs
	streamState := &logStreamState{}
	for {
		err := tryContainerLogStreaming(ctx, logClient, name, streamState, true)
		if streamState.completed {
			break
		}
		if ctx.Err() != nil {
			break
		}
		if err != nil && isNonRetryableLogError(err) {
			handleError(err)
		}
		// Stream ended (nil error with incomplete stream, or transient error) — retry
		streamState.retryCount++
		if streamState.retryCount > maxLogRetries {
			handleError(fmt.Errorf("log stream unavailable after %d retries", maxLogRetries))
		}
		time.Sleep(5 * time.Second)
	}
}

// isNonRetryableLogError returns true for errors that should not be retried.
func isNonRetryableLogError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "HTTP 401") ||
		strings.Contains(msg, "HTTP 403") ||
		strings.Contains(msg, "HTTP 404")
}

// tryContainerLogStreaming attempts to stream logs and returns error if it fails.
// When follow is true, the server keeps the connection open for live streaming.
func tryContainerLogStreaming(ctx context.Context, logClient *http.Client, name string, state *logStreamState, follow bool) error {
	logURL := buildContainerBuildLogURL(name, state.startTime, follow)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return fmt.Errorf("creating log request: %w", err)
	}
	if token := strings.TrimSpace(authToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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

// buildContainerBuildLogURL builds the log streaming URL for container builds
func buildContainerBuildLogURL(buildName string, startTime time.Time, follow bool) string {
	logURL := strings.TrimRight(serverURL, "/") + "/v1/container-builds/" + url.PathEscape(buildName) + "/logs"
	if follow {
		logURL += "?follow=1"
	}
	if !startTime.IsZero() {
		sep := "?"
		if follow {
			sep = "&"
		}
		logURL += sep + "since=" + url.QueryEscape(startTime.Format(time.RFC3339))
	}
	return logURL
}

// streamLogsToStdout streams logs from the response body to stdout
func streamLogsToStdout(body io.Reader, state *logStreamState) error {
	if state.startTime.IsZero() {
		state.startTime = time.Now()
	}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)

		// Advance the cursor so reconnections resume from here
		state.startTime = time.Now()

		// Check for completion markers
		if strings.Contains(line, "Build completed") || strings.Contains(line, "Build failed") {
			state.completed = true
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading log stream: %w", err)
	}

	return nil
}

const maxLogErrorBodyBytes = 64 * 1024 // 64KB limit for error response bodies

// handleLogStreamError handles HTTP errors from log streaming
func handleLogStreamError(resp *http.Response, state *logStreamState) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxLogErrorBodyBytes))
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
		return fmt.Errorf("log stream failed: HTTP %d - %s", resp.StatusCode, msg)
	}
	return fmt.Errorf("log stream failed: HTTP %d", resp.StatusCode)
}
