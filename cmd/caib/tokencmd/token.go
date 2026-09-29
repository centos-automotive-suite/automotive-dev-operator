// Package tokencmd provides the image registry token request handler.
package tokencmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	buildcontract "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

// Options wires token handler dependencies.
type Options struct {
	Connection  *commandopts.Connection
	Output      *commandopts.Output
	HandleError func(error)
}

// Handler implements the token command run function.
type Handler struct {
	opts Options
}

// NewHandler creates a token handler.
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

// RunToken handles `caib image token`.
func (h *Handler) RunToken(_ *cobra.Command, args []string) {
	ctx := context.Background()
	buildName := args[0]

	if strings.TrimSpace(h.opts.Connection.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}

	serverURL := strings.TrimSpace(h.opts.Connection.ServerURL)
	insecureSkipTLS := h.opts.Connection.InsecureSkipTLS

	format, fmtErr := common.ResolveOutputFormat(&h.opts.Output.Format)
	if fmtErr != nil {
		h.handleError(fmtErr)
		return
	}

	var tok *buildcontract.TokenResponse
	err := common.ExecuteWithReauth(serverURL, &h.opts.Connection.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
		var tokenErr error
		tok, tokenErr = api.CreateBuildToken(ctx, buildName)
		return tokenErr
	})
	if err != nil {
		h.handleError(fmt.Errorf("error requesting token for build %s: %w", buildName, err))
		return
	}

	common.RenderFormatted(format, tok, func() error {
		fmt.Printf("Registry:  %s\n", tok.Registry)
		fmt.Printf("Image:     %s\n", tok.Image)
		fmt.Printf("Username:  %s\n", tok.Username)
		fmt.Printf("Token:     %s\n", tok.Token)
		fmt.Printf("Expires:   %s\n", tok.ExpiresAt)
		fmt.Println()
		fmt.Println("To authenticate:")
		fmt.Printf("  echo '%s' | podman login %s --username %s --password-stdin\n", tok.Token, tok.Registry, tok.Username)
		return nil
	}, h.handleError)
}
