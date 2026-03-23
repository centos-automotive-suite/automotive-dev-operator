package buildcmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/logstream"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/ui"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

//nolint:gocyclo // Complex state machine for build progress tracking with log streaming.
func (h *Handler) waitForBuildCompletion(ctx context.Context, api *buildapiclient.Client, name string) error {
	fmt.Println("Waiting for build to complete...")
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(*h.opts.Timeout)*time.Minute)
	defer cancel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	userFollowRequested := *h.opts.FollowLogs
	var lastPhase, lastMessage string
	pendingWarningShown := false
	retryLimitWarningShown := false

	logTransport := &http.Transport{
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       2 * time.Minute,
	}
	if *h.opts.InsecureSkipTLS {
		logTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}
	// No hard Timeout on the client: log streams can run for the entire
	// build duration (often >10 min). The build's context timeout (timeoutCtx)
	// already governs cancellation via the request context.
	logClient := &http.Client{
		Transport: logTransport,
	}
	streamState := &logstream.State{}
	pb := ui.NewProgressBar()

	for {
		select {
		case <-timeoutCtx.Done():
			pb.Clear()
			timeoutErr := fmt.Errorf("timed out waiting for build")
			h.handleError(timeoutErr)
			return timeoutErr
		case <-ticker.C:
			reqCtx, cancelReq := context.WithTimeout(timeoutCtx, 2*time.Minute)
			st, err := api.GetBuild(reqCtx, name)
			cancelReq()
			if err != nil {
				fmt.Printf("status check failed: %v\n", err)
				continue
			}

			if !*h.opts.FollowLogs && !streamState.Active {
				progressCtx, progressCancel := context.WithTimeout(timeoutCtx, 10*time.Second)
				progress, _ := api.GetBuildProgress(progressCtx, name)
				progressCancel()

				displayPhase := st.Phase
				var step *buildapitypes.BuildStep
				if progress != nil {
					step = progress.Step
					if progress.Phase != "" {
						displayPhase = progress.Phase
					}
				}
				pb.Render(displayPhase, step)
			} else if !streamState.Active && (!userFollowRequested || !streamState.CanRetry(maxLogRetries)) {
				if st.Phase != lastPhase || st.Message != lastMessage {
					fmt.Printf("status: %s - %s\n", st.Phase, st.Message)
					lastPhase = st.Phase
					lastMessage = st.Message
				}
			}

			if st.Phase == phaseCompleted {
				pb.Complete()
				flashWasExecuted := strings.Contains(strings.ToLower(st.Message), "flash")
				if flashWasExecuted {
					bannerColor := func(a ...any) string { return fmt.Sprint(a...) }
					infoColor := func(a ...any) string { return fmt.Sprint(a...) }
					commandColor := func(a ...any) string { return fmt.Sprint(a...) }
					if h.supportsColorOutput() {
						bannerColor = color.New(color.FgHiGreen, color.Bold).SprintFunc()
						infoColor = color.New(color.FgHiWhite).SprintFunc()
						commandColor = color.New(color.FgHiYellow, color.Bold).SprintFunc()
					}

					divider := strings.Repeat("=", 50)
					fmt.Println("\n" + bannerColor(divider))
					fmt.Println(bannerColor("Build and flash completed successfully!"))
					fmt.Println(bannerColor(divider))
					fmt.Println("\n" + infoColor("The device has been flashed and a lease has been acquired."))

					leaseID := ""
					if st.Jumpstarter != nil && st.Jumpstarter.LeaseID != "" {
						leaseID = st.Jumpstarter.LeaseID
					} else if streamState.LeaseID != "" {
						leaseID = streamState.LeaseID
					}
					if leaseID != "" {
						// Update workspace lease if --workspace was specified
						if h.opts.Workspace != nil && *h.opts.Workspace != "" {
							leaseCtx, cancelLease := context.WithTimeout(ctx, 10*time.Second)
							leaseErr := api.SetWorkspaceLease(leaseCtx, *h.opts.Workspace, leaseID)
							cancelLease()
							if leaseErr != nil {
								fmt.Printf("\nWarning: failed to update workspace lease: %v\n", leaseErr)
							}
						}
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
					if *h.opts.FlashAfterBuild {
						fmt.Println("\nWarning: --flash was requested but flash was not executed.")
						fmt.Println("This may be because no Jumpstarter target mapping exists for this target.")
						fmt.Println("Check OperatorConfig for JumpstarterTargetMappings configuration.")
					}
					h.displayFlashInstructions(st, false)
				}
				return nil
			}
			if st.Phase == phaseFailed {
				pb.Clear()
				isFlashFailure := strings.Contains(strings.ToLower(st.Message), errPrefixFlash) ||
					lastPhase == phaseFlashing

				handleErr := fmt.Errorf("%s", st.Message)
				// Only show push/flash results when an image was actually produced.
				hasImage := st.DiskImage != "" || st.ContainerImage != ""
				if hasImage && (isFlashFailure || *h.opts.FlashAfterBuild) {
					h.displayBuildResults(ctx, api, name)
					h.handleFlashError(handleErr, st)
				} else {
					h.handleError(handleErr)
				}
				return handleErr
			}

			if !*h.opts.FollowLogs || streamState.Active {
				continue
			}

			if streamState.Completed && isBuildActive(st.Phase) {
				streamState.Completed = false
				streamState.RetryCount = 0
			}

			if !streamState.CanRetry(maxLogRetries) {
				continue
			}

			if st.Phase == phasePending {
				streamState.Reset()
				if userFollowRequested && !pendingWarningShown {
					fmt.Println("Waiting for build to start before streaming logs...")
					pendingWarningShown = true
				}
				continue
			}

			if isBuildActive(st.Phase) {
				if streamState.RetryCount == 0 {
					fmt.Println("Build is active. Attempting to stream logs...")
					pendingWarningShown = false
				}

				if err := h.tryLogStreaming(timeoutCtx, logClient, name, streamState); err != nil {
					streamState.RetryCount++
					if !streamState.CanRetry(maxLogRetries) && !retryLimitWarningShown {
						msg := "Log streaming failed after %d attempts (~2 minutes). Falling back to status updates only.\n"
						fmt.Printf(msg, maxLogRetries)
						retryLimitWarningShown = true
					}
				} else {
					*h.opts.FollowLogs = userFollowRequested
				}
			}
		}
	}
}

const maxLogRetries = 24

func isBuildActive(phase string) bool {
	return phase == "Building" || phase == phaseRunning || phase == phaseUploading || phase == phaseFlashing
}

func (h *Handler) tryLogStreaming(ctx context.Context, logClient *http.Client, name string, state *logstream.State) error {
	logURL := h.buildLogURL(name, state.StartTime)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create log request: %w", err)
	}
	if authToken := strings.TrimSpace(*h.opts.AuthToken); authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
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
		return logstream.StreamLogsToStdout(resp.Body, state, true)
	}

	return logstream.HandleLogStreamError(resp, state, maxLogRetries)
}

func (h *Handler) buildLogURL(buildName string, startTime time.Time) string {
	logURL := strings.TrimRight(*h.opts.ServerURL, "/") + "/v1/builds/" + url.PathEscape(buildName) + "/logs?follow=1"
	if !startTime.IsZero() {
		logURL += "&since=" + url.QueryEscape(startTime.Format(time.RFC3339))
	}
	return logURL
}

// RunLogs handles `caib image logs`.
func (h *Handler) RunLogs(_ *cobra.Command, args []string) {
	ctx := context.Background()
	name := args[0]

	if strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}

	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	st, err := api.GetBuild(ctx, name)
	if err != nil {
		h.handleError(fmt.Errorf("failed to get build: %w", err))
		return
	}
	fmt.Printf("Build %s: %s - %s\n", name, st.Phase, st.Message)

	if st.Phase == phaseCompleted || st.Phase == phaseFailed {
		logTransport := &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
		}
		if *h.opts.InsecureSkipTLS {
			logTransport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			}
		}
		logClient := &http.Client{
			Timeout:   2 * time.Minute,
			Transport: logTransport,
		}
		streamState := &logstream.State{}
		if err := h.tryLogStreaming(ctx, logClient, name, streamState); err != nil {
			fmt.Printf("Could not retrieve logs (pods may have been cleaned up). Use 'caib image show %s' for details.\n", name)
		}
		return
	}

	*h.opts.FollowLogs = true
	if err := h.waitForBuildCompletion(ctx, api, name); err != nil {
		return
	}
	h.displayBuildResults(ctx, api, name)
}
