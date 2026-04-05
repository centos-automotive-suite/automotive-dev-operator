package main

import (
	"fmt"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/authcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/catalog"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/container"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/image"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/workspace"
	"github.com/spf13/cobra"
)

var validOutputFormats = map[string]bool{
	"table": true,
	"json":  true,
	"yaml":  true,
	"yml":   true,
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "caib",
		Short:   "Cloud Automotive Image Builder",
		Version: version,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			f := strings.ToLower(strings.TrimSpace(outputFormat))
			if !validOutputFormats[f] {
				return fmt.Errorf("invalid output format %q (supported: table, json, yaml)", outputFormat)
			}
			return nil
		},
	}

	rootCmd.InitDefaultVersionFlag()
	rootCmd.SetVersionTemplate("caib version: {{.Version}}\n")

	rootCmd.PersistentFlags().BoolVar(
		&insecureSkipTLS,
		"insecure",
		envBool("CAIB_INSECURE"),
		"skip TLS certificate verification (insecure, for testing only; env: CAIB_INSECURE)",
	)
	rootCmd.PersistentFlags().StringVar(
		&outputFormat,
		"output-format",
		"table",
		"output format: table, json, yaml",
	)
	state := newRuntimeState()
	handlers := state.newHandlers()

	rootCmd.AddCommand(
		image.NewImageCmd(state.imageOptions(handlers)),
		newLoginCmd(),
		container.NewContainerCmd(),
		catalog.NewCatalogCmd(),
		authcmd.NewAuthCmd(),
		workspace.NewWorkspaceCmd(),
	)

	return rootCmd
}

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login [server-url]",
		Short: "Save server endpoint and authenticate for subsequent commands",
		Long: `Login saves the Build API server URL in XDG config (typically ~/.config/caib/cli.json) so you do not need
to pass --server or set CAIB_SERVER for later commands. If the server uses OIDC,
this command also performs authentication and caches the token.

If no URL is provided, the server endpoint is attempted to be derived from the current Jumpstarter
client config (~/.config/jumpstarter/clients/<alias>.yaml).

Examples:
  caib login https://build-api.my-cluster.example.com
  caib login # attempt to derive endpoint from Jumpstarter config (if available)`,
		Args: cobra.MaximumNArgs(1),
		Run:  runLogin,
	}
}
