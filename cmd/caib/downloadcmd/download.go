// Package downloadcmd provides the image artifact download handler.
package downloadcmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	buildcontract "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

const phaseCompleted = "Completed"

// Options wires download handler dependencies.
type Options struct {
	Connection  *commandopts.Connection
	Output      *commandopts.Output
	HandleError func(error)
}

// Handler implements the download command run function.
type Handler struct {
	opts Options
}

// NewHandler creates a download handler.
func (o Options) withDefaults() Options {
	if o.Connection == nil {
		o.Connection = &commandopts.Connection{}
	}
	if o.Output == nil {
		o.Output = &commandopts.Output{}
	}
	return o
}

func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts.withDefaults()}
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

	if strings.TrimSpace(h.opts.Connection.ServerURL) == "" {
		h.handleError(common.ServerURLRequiredError(fmt.Sprintf("caib image download --server <server-url> -o <dir> %s", downloadBuildName)))
		return
	}
	if strings.TrimSpace(h.opts.Output.Dir) == "" {
		h.handleError(common.NewActionableError(
			fmt.Errorf("--output / -o is required"),
			fmt.Sprintf("caib image download -o <output-dir> %s", downloadBuildName),
		))
		return
	}

	serverURL := strings.TrimSpace(h.opts.Connection.ServerURL)
	outputDir := strings.TrimSpace(h.opts.Output.Dir)
	insecureSkipTLS := h.opts.Connection.InsecureSkipTLS

	var st *buildcontract.BuildResponse
	err := common.ExecuteWithReauth(serverURL, &h.opts.Connection.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
		var getErr error
		st, getErr = api.GetBuild(ctx, downloadBuildName)
		return getErr
	})
	if err != nil {
		h.handleError(fmt.Errorf("error getting build %s: %w", downloadBuildName, err))
		return
	}

	if st.Phase != phaseCompleted {
		h.handleError(common.NewActionableError(
			fmt.Errorf("build %s is not completed (phase: %s), cannot download artifacts", downloadBuildName, st.Phase),
			"caib image logs "+downloadBuildName,
		))
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

	clilog.Infof("Downloading disk image from %s\n", ociRef)
	if err := common.PullOCIArtifact(ociRef, outputDir, registryUsername, registryPassword, insecureSkipTLS); err != nil {
		h.handleError(fmt.Errorf("download failed: %w", err))
		return
	}
}
