// Package flashcmd provides the `caib image flash` command handler.
package flashcmd

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/logstream"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
)

const (
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
	phasePending   = "Pending"
	phaseRunning   = "Running"
	maxLogRetries  = 24
)

// Options wires flash command handlers to caller-owned state and dependencies.
type Options struct {
	ServerURL         *string
	AuthToken         *string
	JumpstarterClient *string
	FlashName         *string
	Target            *string
	ExporterSelector  *string
	LeaseDuration     *string
	FlashCmd          *string
	WaitForBuild      *bool
	FollowLogs        *bool
	InsecureSkipTLS   *bool
	RegistryAuthFile  *string

	HandleError func(error)
}

// Handler implements flash-related Cobra run functions.
type Handler struct {
	opts Options
}

// NewHandler creates a flash command handler.
func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts}
}

func (h *Handler) handleError(err error) {
	if h != nil && h.opts.HandleError != nil {
		h.opts.HandleError(err)
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func (h *Handler) applyWaitFollowDefaults(cmd *cobra.Command, defaultWait, defaultFollow bool) {
	if !cmd.Flags().Changed("wait") {
		*h.opts.WaitForBuild = defaultWait
	}
	if !cmd.Flags().Changed("follow") {
		*h.opts.FollowLogs = defaultFollow
	}
}

// RunFlash handles the standalone `caib image flash` command.
func (h *Handler) RunFlash(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd, true, false)

	ctx := context.Background()
	imageRef := args[0]
	server := strings.TrimSpace(*h.opts.ServerURL)

	if server == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}

	if strings.TrimSpace(*h.opts.JumpstarterClient) == "" {
		h.handleError(fmt.Errorf("--client is required"))
		return
	}

	// Validate that either target or exporter is specified.
	if strings.TrimSpace(*h.opts.Target) == "" && strings.TrimSpace(*h.opts.ExporterSelector) == "" {
		h.handleError(fmt.Errorf("either --target or --exporter is required"))
		return
	}

	api, err := common.CreateBuildAPIClient(server, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	clientConfigBytes, err := os.ReadFile(*h.opts.JumpstarterClient)
	if err != nil {
		h.handleError(fmt.Errorf("failed to read client config file: %w", err))
		return
	}
	clientConfigB64 := base64.StdEncoding.EncodeToString(clientConfigBytes)

	req := buildapitypes.FlashRequest{
		Name:             *h.opts.FlashName,
		ImageRef:         imageRef,
		Target:           *h.opts.Target,
		ExporterSelector: *h.opts.ExporterSelector,
		ClientConfig:     clientConfigB64,
		LeaseDuration:    *h.opts.LeaseDuration,
		FlashCmd:         *h.opts.FlashCmd,
	}

	// Resolve OCI registry credentials for the flash image
	authFile := ""
	if h.opts.RegistryAuthFile != nil {
		authFile = *h.opts.RegistryAuthFile
	}
	registryURL, registryUsername, registryPassword := registryauth.ExtractRegistryCredentials(imageRef, "")
	registryCreds, credErr := registryauth.ResolveRegistryCredentials(
		registryURL, registryUsername, registryPassword, authFile,
	)
	if credErr != nil {
		h.handleError(fmt.Errorf("failed to resolve registry credentials: %w", credErr))
		return
	}
	req.RegistryCredentials = registryCreds

	resp, err := api.CreateFlash(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	fmt.Printf("Flash job %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)

	if *h.opts.WaitForBuild || *h.opts.FollowLogs {
		h.waitForFlashCompletion(ctx, api, resp.Name)
	}
}

// parseLeaseDuration converts HH:MM:SS format to time.Duration.
func parseLeaseDuration(duration string) (time.Duration, error) {
	parts := strings.Split(duration, ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid lease duration %q: expected HH:MM:SS", duration)
	}

	hours, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid lease duration hours %q", parts[0])
	}
	mins, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid lease duration minutes %q", parts[1])
	}
	secs, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, fmt.Errorf("invalid lease duration seconds %q", parts[2])
	}
	if hours < 0 || hours > 8760 || mins < 0 || mins >= 60 || secs < 0 || secs >= 60 {
		return 0, fmt.Errorf("invalid lease duration values %q", duration)
	}

	return time.Duration(hours)*time.Hour + time.Duration(mins)*time.Minute + time.Duration(secs)*time.Second, nil
}

// waitForFlashCompletion waits for a flash job to complete, optionally streaming logs.
func (h *Handler) waitForFlashCompletion(ctx context.Context, _ *buildapiclient.Client, name string) {
	fmt.Println("Waiting for flash to complete...")

	leaseDuration, err := parseLeaseDuration(*h.opts.LeaseDuration)
	if err != nil {
		h.handleError(fmt.Errorf("invalid lease duration: %w", err))
		return
	}

	timeoutDuration := leaseDuration + 10*time.Minute
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
	if *h.opts.InsecureSkipTLS {
		flashLogTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}
	logClient := &http.Client{Transport: flashLogTransport}
	streamState := &logstream.State{}

	for {
		select {
		case <-timeoutCtx.Done():
			h.handleError(fmt.Errorf("timed out waiting for flash"))
			return
		case <-ticker.C:
			reqCtx, cancelReq := context.WithTimeout(timeoutCtx, 2*time.Minute)
			var st *buildapitypes.FlashResponse
			err := common.ExecuteWithReauth(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS, func(api *buildapiclient.Client) error {
				var getErr error
				st, getErr = api.GetFlash(reqCtx, name)
				return getErr
			})
			cancelReq()
			if err != nil {
				fmt.Printf("status check failed: %v\n", err)
				continue
			}

			if !streamState.Active && (st.Phase != lastPhase || st.Message != lastMessage) {
				fmt.Printf("status: %s - %s\n", st.Phase, st.Message)
				lastPhase = st.Phase
				lastMessage = st.Message
			}

			if st.Phase == phaseCompleted {
				fmt.Println("Flash completed successfully!")
				return
			}
			if st.Phase == phaseFailed {
				h.handleError(fmt.Errorf("flash failed: %s", st.Message))
				return
			}

			if !*h.opts.FollowLogs || streamState.Active || !streamState.CanRetry(maxLogRetries) {
				continue
			}

			if st.Phase == phasePending {
				streamState.Reset()
				if !pendingWarningShown {
					fmt.Println("Waiting for flash to start before streaming logs...")
					pendingWarningShown = true
				}
				continue
			}

			if st.Phase == phaseRunning {
				if streamState.RetryCount == 0 {
					fmt.Println("Flash is running. Attempting to stream logs...")
					pendingWarningShown = false
				}
				if err := h.tryFlashLogStreaming(timeoutCtx, logClient, name, streamState); err != nil {
					streamState.RetryCount++
				}
			}
		}
	}
}

func (h *Handler) tryFlashLogStreaming(ctx context.Context, logClient *http.Client, name string, state *logstream.State) error {
	logURL := strings.TrimRight(strings.TrimSpace(*h.opts.ServerURL), "/") + "/v1/flash/" + url.PathEscape(name) + "/logs?follow=1"
	if !state.StartTime.IsZero() {
		logURL += "&since=" + url.QueryEscape(state.StartTime.Format(time.RFC3339))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create log request: %w", err)
	}
	if t := strings.TrimSpace(*h.opts.AuthToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}

	resp, err := logClient.Do(req)
	if err != nil {
		return fmt.Errorf("log request failed: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", closeErr)
			}
		}()
		return logstream.StreamLogsToStdout(resp.Body, state, false)
	}
	return logstream.HandleLogStreamError(resp, state, maxLogRetries)
}
