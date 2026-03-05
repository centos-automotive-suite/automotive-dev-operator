package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

// runLogin saves the server URL and optionally performs OIDC authentication.
func runLogin(_ *cobra.Command, args []string) {
	var server string

	if len(args) == 0 {
		server = config.DeriveServerFromJumpstarter()
		if server == "" {
			handleError(fmt.Errorf("no Jumpstarter config found or derived endpoint unreachable; provide a server URL explicitly"))
		}
	} else {
		server = strings.TrimSpace(args[0])
		if server == "" {
			handleError(fmt.Errorf("server URL is required"))
		}
		if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
			server = "https://" + server
		}

		parsedURL, err := url.Parse(server)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			handleError(fmt.Errorf("invalid server URL %q", server))
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			handleError(fmt.Errorf("invalid server URL %q: scheme must be http or https", server))
		}
		if parsedURL.User != nil {
			handleError(fmt.Errorf("server URL must not include credentials"))
		}
		if parsedURL.RawQuery != "" {
			handleError(fmt.Errorf("server URL must not include query parameters"))
		}
		if parsedURL.Fragment != "" {
			handleError(fmt.Errorf("server URL must not include fragments"))
		}
		if parsedURL.Path != "" && parsedURL.Path != "/" {
			handleError(fmt.Errorf("server URL must not include a non-root path"))
		}
		server = parsedURL.Scheme + "://" + parsedURL.Host
	}

	if err := config.SaveServerURL(server); err != nil {
		handleError(fmt.Errorf("failed to save server URL: %w", err))
	}
	fmt.Printf("Server saved: %s\n", server)

	ctx := context.Background()
	token, didAuth, err := auth.GetTokenWithReauth(ctx, server, "", insecureSkipTLS)
	if err != nil {
		fmt.Printf("Warning: authentication failed (you may need --token or kubeconfig for API calls): %v\n", err)
		return
	}
	if token != "" && didAuth {
		fmt.Println("OIDC authentication successful. Token cached for subsequent commands.")
	} else if token != "" {
		fmt.Println("Using existing or kubeconfig token. You can run build/list/disk commands without --server.")
	}
}
