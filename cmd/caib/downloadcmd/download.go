// Package downloadcmd provides the image artifact download handler.
package downloadcmd

import (
	"context"
	"fmt"
	"strings"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
)

const phaseCompleted = "Completed"

// Options wires download handler dependencies.
type Options struct {
	ServerURL       *string
	AuthToken       *string
	OutputDir       *string
	InsecureSkipTLS *bool

	HandleError func(error)
}

// Handler implements the download command run function.
type Handler struct {
	opts Options
}

// NewHandler creates a download handler.
func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts}
}

func (h *Handler) handleError(err error) {
	if h.opts.HandleError != nil {
		h.opts.HandleError(err)
		return
	}
	panic(err)
}

// RunDownload handles `caib image download`.
func (h *Handler) RunDownload(_ *cobra.Command, args []string) {
	ctx := context.Background()
	downloadBuildName := args[0]

	if h.opts.ServerURL == nil || strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}
	if h.opts.OutputDir == nil || strings.TrimSpace(*h.opts.OutputDir) == "" {
		h.handleError(fmt.Errorf("--output / -o is required"))
		return
	}
	if h.opts.InsecureSkipTLS == nil {
		h.handleError(fmt.Errorf("internal error: --insecure option is not configured"))
		return
	}

	serverURL := strings.TrimSpace(*h.opts.ServerURL)
	outputDir := strings.TrimSpace(*h.opts.OutputDir)
	insecureSkipTLS := *h.opts.InsecureSkipTLS

	var st *buildapitypes.BuildResponse
	err := common.ExecuteWithReauth(serverURL, h.opts.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
		var getErr error
		st, getErr = api.GetBuild(ctx, downloadBuildName)
		return getErr
	})
	if err != nil {
		h.handleError(fmt.Errorf("error getting build %s: %w", downloadBuildName, err))
		return
	}

	if st.Phase != phaseCompleted {
		h.handleError(fmt.Errorf("build %s is not completed (phase: %s), cannot download artifacts", downloadBuildName, st.Phase))
		return
	}

	ociRef := st.DiskImage
	if ociRef == "" {
		h.handleError(fmt.Errorf(
			"build %s has no disk image artifact to download (no OCI export was configured)",
			downloadBuildName,
		))
		return
	}

	registryUsername := ""
	registryPassword := ""
	if st.RegistryToken != "" {
		registryUsername = "serviceaccount"
		registryPassword = st.RegistryToken
	} else {
		effectiveRegistryURL, extractedUser, extractedPassword := registryauth.ExtractRegistryCredentials(ociRef, "")
		registryUsername = extractedUser
		registryPassword = extractedPassword
		if err := registryauth.ValidateRegistryCredentials(effectiveRegistryURL, registryUsername, registryPassword); err != nil {
			h.handleError(err)
			return
		}
	}

	fmt.Printf("Downloading disk image from %s\n", ociRef)
	if err := common.PullOCIArtifact(ociRef, outputDir, registryUsername, registryPassword, insecureSkipTLS); err != nil {
		h.handleError(fmt.Errorf("download failed: %w", err))
		return
	}
}
