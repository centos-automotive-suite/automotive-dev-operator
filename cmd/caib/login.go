package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

// normalizeServerURL parses and normalizes a raw server URL argument.
// It prepends "https://" if no scheme is present, and rejects URLs with
// invalid schemes, credentials, query parameters, fragments, or non-root paths.
func normalizeServerURL(raw string) (string, error) {
	server := strings.TrimSpace(raw)
	if server == "" {
		return "", fmt.Errorf("server URL is required")
	}
	if strings.Contains(server, "://") {
		if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
			return "", fmt.Errorf("invalid server URL %q: scheme must be http or https", raw)
		}
	} else {
		server = "https://" + server
	}
	parsedURL, err := url.Parse(server)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	if parsedURL.User != nil {
		return "", fmt.Errorf("server URL must not include credentials")
	}
	if parsedURL.RawQuery != "" {
		return "", fmt.Errorf("server URL must not include query parameters")
	}
	if parsedURL.Fragment != "" {
		return "", fmt.Errorf("server URL must not include fragments")
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		return "", fmt.Errorf("server URL must not include a non-root path")
	}
	return parsedURL.Scheme + "://" + parsedURL.Host, nil
}

// checkServerReachable performs a lightweight GET against /v1/healthz to confirm
// the server exists and is reachable before the URL is persisted to config.
// Any HTTP response (even an error status) is accepted — only a connection
// failure causes an error.
func checkServerReachable(serverURL string, insecureSkipTLS bool) error {
	transport := &http.Transport{}
	if insecureSkipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get(strings.TrimSuffix(serverURL, "/") + "/v1/healthz")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// runLogin saves the server URL and optionally performs OIDC authentication.
func runLogin(_ *cobra.Command, args []string) {
	var server string

	if len(args) == 0 {
		server = config.DeriveServerFromJumpstarter()
		if server == "" {
			handleError(fmt.Errorf("no Jumpstarter config found or derived endpoint unreachable; provide a server URL explicitly"))
		}
	} else {
		var err error
		server, err = normalizeServerURL(args[0])
		if err != nil {
			handleError(err)
		}
	}

	if err := checkServerReachable(server, insecureSkipTLS); err != nil {
		handleError(fmt.Errorf("cannot connect to server %q: %w", server, err))
	}

	if err := config.SaveServerURL(server); err != nil {
		handleError(fmt.Errorf("failed to save server URL: %w", err))
	}
	clilog.Infof("Server saved: %s\n", server)

	ctx := context.Background()

	// An existing `jmp login` session may already hold a token this server accepts;
	// offering it here avoids a second browser round trip.
	jmpToken := config.JumpstarterToken()
	token, didAuth, err := auth.GetTokenWithReauth(ctx, server, jmpToken, insecureSkipTLS)
	if err != nil {
		clilog.Warnf("authentication failed (you may need --token or kubeconfig for API calls): %v\n", err)
		return
	}
	if msg := loginResultMessage(token, jmpToken, didAuth); msg != "" {
		clilog.Infoln(msg)
	}
}

// loginResultMessage describes where the token came from. jmpToken is the token
// found in the Jumpstarter client config, if any.
func loginResultMessage(token, jmpToken string, didAuth bool) string {
	switch {
	case token == "":
		return ""
	case didAuth:
		return "OIDC authentication successful. Token cached for subsequent commands."
	case jmpToken != "" && token == jmpToken:
		return "Reusing the token from your Jumpstarter client config. You can run build/list/disk commands without --server."
	default:
		return "Using existing or kubeconfig token. You can run build/list/disk commands without --server."
	}
}
