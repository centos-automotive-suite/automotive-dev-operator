// Package tokencmd provides the image registry token request handler.
package tokencmd

import (
	"context"
	"fmt"
	"strings"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
)

// Options wires token handler dependencies.
type Options struct {
	ServerURL       *string
	AuthToken       *string
	InsecureSkipTLS *bool

	HandleError func(error)
}

// Handler implements the token command run function.
type Handler struct {
	opts Options
}

// NewHandler creates a token handler.
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

// RunToken handles `caib image token`.
func (h *Handler) RunToken(_ *cobra.Command, args []string) {
	ctx := context.Background()
	buildName := args[0]

	if h.opts.ServerURL == nil || strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}
	if h.opts.InsecureSkipTLS == nil {
		h.handleError(fmt.Errorf("internal error: --insecure option is not configured"))
		return
	}

	serverURL := strings.TrimSpace(*h.opts.ServerURL)
	insecureSkipTLS := *h.opts.InsecureSkipTLS

	var tok *buildapitypes.TokenResponse
	err := common.ExecuteWithReauth(serverURL, h.opts.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
		var tokenErr error
		tok, tokenErr = api.CreateBuildToken(ctx, buildName)
		return tokenErr
	})
	if err != nil {
		h.handleError(fmt.Errorf("error requesting token for build %s: %w", buildName, err))
		return
	}

	fmt.Printf("Registry:  %s\n", tok.Registry)
	fmt.Printf("Image:     %s\n", tok.Image)
	fmt.Printf("Username:  %s\n", tok.Username)
	fmt.Printf("Token:     %s\n", tok.Token)
	fmt.Printf("Expires:   %s\n", tok.ExpiresAt)
	fmt.Println()
	fmt.Println("To authenticate:")
	fmt.Printf("  echo '%s' | podman login %s --username %s --password-stdin\n", tok.Token, tok.Registry, tok.Username)
}
