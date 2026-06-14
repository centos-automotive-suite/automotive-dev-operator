// Package sealedcmd provides sealed image operation handlers.
package sealedcmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
)

const (
	phaseCompleted      = "Completed"
	phaseFailed         = "Failed"
	phasePending        = "Pending"
	phaseRunning        = "Running"
	maxSealedLogRetries = 24
)

// Options wires sealed command handlers to caller-owned state and dependencies.
type Options struct {
	ServerURL              *string
	AuthToken              *string
	AutomotiveImageBuilder *string
	SealedBuilderImage     *string
	SealedArchitecture     *string
	AIBExtraArgs           *[]string
	WaitForBuild           *bool
	FollowLogs             *bool
	Timeout                *int

	SealedKeySecret         *string
	SealedKeyPasswordSecret *string
	SealedKeyFile           *string
	SealedKeyPassword       *string
	SealedInputRef          *string
	SealedOutputRef         *string
	SealedSignedRef         *string

	RegistryAuthFile *string
	InsecureSkipTLS  *bool
	HandleError      func(error)
}

// Handler implements sealed command run functions.
type Handler struct {
	opts Options
}

// NewHandler creates a sealed operations handler.
func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts}
}

func (h *Handler) handleError(err error) {
	if h != nil && h.opts.HandleError != nil {
		h.opts.HandleError(err)
		return
	}
	fmt.Fprintln(os.Stderr, common.FormatError(err))
	os.Exit(1)
}

func (h *Handler) applyWaitFollowDefaults(cmd *cobra.Command) {
	if !cmd.Flags().Changed("wait") {
		*h.opts.WaitForBuild = false
	}
	if !cmd.Flags().Changed("follow") {
		*h.opts.FollowLogs = true
	}
}

// RunPrepareReseal handles `caib image prepare-reseal`.
func (h *Handler) RunPrepareReseal(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd)
	inputRef, outputRef, err := h.resolveSealedTwoRefs(args)
	if err != nil {
		h.handleError(err)
		return
	}
	h.sealedRunViaAPI(buildapitypes.SealedPrepareReseal, inputRef, outputRef, "")
}

// RunReseal handles `caib image reseal`.
func (h *Handler) RunReseal(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd)
	inputRef, outputRef, err := h.resolveSealedTwoRefs(args)
	if err != nil {
		h.handleError(err)
		return
	}
	h.sealedRunViaAPI(buildapitypes.SealedReseal, inputRef, outputRef, "")
}

// RunExtractForSigning handles `caib image extract-for-signing`.
func (h *Handler) RunExtractForSigning(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd)
	inputRef, outputRef, err := h.resolveSealedTwoRefs(args)
	if err != nil {
		h.handleError(err)
		return
	}
	h.sealedRunViaAPI(buildapitypes.SealedExtractForSigning, inputRef, outputRef, "")
}

// RunInjectSigned handles `caib image inject-signed`.
func (h *Handler) RunInjectSigned(cmd *cobra.Command, args []string) {
	h.applyWaitFollowDefaults(cmd)
	inputRef, signedRef, outputRef, err := h.resolveSealedThreeRefs(args)
	if err != nil {
		h.handleError(err)
		return
	}
	h.sealedRunViaAPI(buildapitypes.SealedInjectSigned, inputRef, outputRef, signedRef)
}

func (h *Handler) sealedBuildRequest(
	op buildapitypes.SealedOperation,
	inputRef, outputRef, signedRef string,
) (buildapitypes.SealedRequest, error) {
	req := buildapitypes.SealedRequest{
		Operation:    op,
		InputRef:     inputRef,
		OutputRef:    outputRef,
		SignedRef:    signedRef,
		AIBImage:     *h.opts.AutomotiveImageBuilder,
		BuilderImage: *h.opts.SealedBuilderImage,
		Architecture: *h.opts.SealedArchitecture,
		AIBExtraArgs: *h.opts.AIBExtraArgs,
	}

	registryURL, username, password := registryauth.ExtractRegistryCredentials(inputRef, outputRef)
	registryCreds, err := registryauth.ResolveRegistryCredentials(
		registryURL,
		username,
		password,
		*h.opts.RegistryAuthFile,
	)
	if err != nil {
		return req, err
	}
	req.RegistryCredentials = registryCreds

	if keyFile := strings.TrimSpace(*h.opts.SealedKeyFile); keyFile != "" {
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return req, fmt.Errorf("failed to read key file %s: %w", keyFile, err)
		}
		req.KeyContent = string(keyData)
		if keyPassword := strings.TrimSpace(*h.opts.SealedKeyPassword); keyPassword != "" {
			req.KeyPassword = keyPassword
		}
	} else if keySecret := strings.TrimSpace(*h.opts.SealedKeySecret); keySecret != "" {
		req.KeySecretRef = keySecret
		if keyPassSecret := strings.TrimSpace(*h.opts.SealedKeyPasswordSecret); keyPassSecret != "" {
			req.KeyPasswordSecretRef = keyPassSecret
		}
	}

	return req, nil
}

func (h *Handler) sealedRunViaAPI(op buildapitypes.SealedOperation, inputRef, outputRef, signedRef string) {
	api, err := common.CreateBuildAPIClient(*h.opts.ServerURL, h.opts.AuthToken, *h.opts.InsecureSkipTLS)
	if err != nil {
		h.handleError(err)
		return
	}

	ctx := context.Background()
	req, err := h.sealedBuildRequest(op, inputRef, outputRef, signedRef)
	if err != nil {
		h.handleError(err)
		return
	}

	resp, err := api.CreateSealed(ctx, req)
	if err != nil {
		h.handleError(err)
		return
	}
	clilog.Infof("Job %s accepted: %s - %s\n", resp.Name, resp.Phase, resp.Message)

	if *h.opts.WaitForBuild || *h.opts.FollowLogs {
		h.sealedWaitForCompletion(ctx, api, op, resp.Name)
	}
}

func (h *Handler) sealedWaitForCompletion(
	ctx context.Context,
	api *buildapiclient.Client,
	op buildapitypes.SealedOperation,
	name string,
) {
	clilog.Infoln("Waiting for job to complete...")
	sealedTimeout := time.Duration(*h.opts.Timeout) * time.Minute
	waitCtx, cancel := context.WithTimeout(ctx, sealedTimeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastPhase string
	logRetries := 0
	logStreaming := false
	logRetryWarningShown := false
	const requestTimeout = 2 * time.Minute

	for {
		select {
		case <-waitCtx.Done():
			h.handleError(fmt.Errorf("timed out after %v", sealedTimeout))
			return
		case <-ticker.C:
			reqCtx, reqCancel := context.WithTimeout(waitCtx, requestTimeout)
			st, err := api.GetSealed(reqCtx, op, name)
			reqCancel()
			if err != nil {
				if waitCtx.Err() != nil {
					h.handleError(fmt.Errorf("timed out after %v", sealedTimeout))
					return
				}
				fmt.Fprintf(os.Stderr, "status check failed: %v\n", err)
				continue
			}

			if st.Phase != lastPhase {
				clilog.Infof("status: %s - %s\n", st.Phase, st.Message)
				lastPhase = st.Phase
			}

			if st.Phase == phaseCompleted {
				clilog.Infoln("Job completed successfully.")
				if st.OutputRef != "" {
					clilog.Infof("Output: %s\n", st.OutputRef)
				}
				return
			}
			if st.Phase == phaseFailed {
				h.handleError(fmt.Errorf("job failed: %s", st.Message))
				return
			}

			if *h.opts.FollowLogs && !logStreaming && (st.Phase == phaseRunning || st.Phase == phasePending) {
				if logRetries < maxSealedLogRetries {
					logCtx, logCancel := context.WithTimeout(waitCtx, requestTimeout)
					streamErr := h.sealedStreamLogs(logCtx, op, name)
					logCancel()
					if streamErr != nil {
						logRetries++
						if logRetries == 1 {
							clilog.Infof("Waiting for logs... (attempt %d/%d)\n", logRetries, maxSealedLogRetries)
						}
					} else {
						logStreaming = true
					}
				} else if !logRetryWarningShown {
					clilog.Infof("Log streaming failed after %d attempts. Falling back to status updates.\n", maxSealedLogRetries)
					logRetryWarningShown = true
					logStreaming = false
					*h.opts.FollowLogs = false
				}
			}
		}
	}
}

func (h *Handler) sealedStreamLogs(ctx context.Context, op buildapitypes.SealedOperation, name string) error {
	logURL := strings.TrimRight(*h.opts.ServerURL, "/") +
		buildapitypes.SealedOperationAPIPath(op) + "/" + url.PathEscape(name) + "/logs?follow=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create log request: %w", err)
	}
	if t := strings.TrimSpace(*h.opts.AuthToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}

	transport := &http.Transport{}
	if *h.opts.InsecureSkipTLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}
	httpClient := &http.Client{
		Timeout:   10 * time.Minute,
		Transport: transport,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("log stream failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		return fmt.Errorf("log endpoint not ready (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("log stream error: HTTP %d", resp.StatusCode)
	}

	clilog.Infoln("Streaming logs...")
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("log stream interrupted: %w", err)
	}
	return nil
}

// resolveSealedTwoRefs returns input and output refs from --input/--output flags or positionals (any order).
func (h *Handler) resolveSealedTwoRefs(args []string) (inputRef, outputRef string, err error) {
	in := strings.TrimSpace(*h.opts.SealedInputRef)
	out := strings.TrimSpace(*h.opts.SealedOutputRef)
	if in != "" && out != "" {
		return in, out, nil
	}
	if in != "" && len(args) >= 1 {
		return in, strings.TrimSpace(args[0]), nil
	}
	if out != "" && len(args) >= 1 {
		return strings.TrimSpace(args[0]), out, nil
	}
	if len(args) >= 2 {
		return strings.TrimSpace(args[0]), strings.TrimSpace(args[1]), nil
	}
	return "", "", fmt.Errorf("need two refs: use positionals (source output) or --input and --output in any order")
}

// resolveSealedThreeRefs returns input, signed, and output refs from --input/--signed/--output flags or positionals (any order).
func (h *Handler) resolveSealedThreeRefs(args []string) (inputRef, signedRef, outputRef string, err error) {
	in := strings.TrimSpace(*h.opts.SealedInputRef)
	signed := strings.TrimSpace(*h.opts.SealedSignedRef)
	out := strings.TrimSpace(*h.opts.SealedOutputRef)
	if in != "" && signed != "" && out != "" {
		return in, signed, out, nil
	}

	fromFlags := 0
	if in != "" {
		fromFlags++
	}
	if signed != "" {
		fromFlags++
	}
	if out != "" {
		fromFlags++
	}

	need := 3 - fromFlags
	if len(args) < need {
		return "", "", "", fmt.Errorf(
			"need three refs (source, signed-artifact, output): use positionals or --input, --signed, --output in any order")
	}

	idx := 0
	if in == "" {
		in = strings.TrimSpace(args[idx])
		idx++
	}
	if signed == "" {
		signed = strings.TrimSpace(args[idx])
		idx++
	}
	if out == "" {
		out = strings.TrimSpace(args[idx])
	}
	return in, signed, out, nil
}
