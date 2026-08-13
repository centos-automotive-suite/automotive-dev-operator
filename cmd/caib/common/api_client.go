// Package caibcommon provides shared caib helpers.
package caibcommon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"k8s.io/client-go/tools/clientcmd"
)

// CreateBuildAPIClient creates a build API client with auth token from flags/env/kubeconfig.
func CreateBuildAPIClient(serverURL string, authToken *string, insecureSkipTLS bool) (*buildapiclient.Client, error) {
	ctx := context.Background()

	tokenValue := ""
	if authToken != nil {
		tokenValue = strings.TrimSpace(*authToken)
	}
	setToken := func(token string) {
		tokenValue = strings.TrimSpace(token)
		if authToken != nil {
			*authToken = tokenValue
		}
	}

	envToken := strings.TrimSpace(os.Getenv("CAIB_TOKEN"))
	explicitToken := tokenValue != "" || envToken != ""

	if !explicitToken {
		token, didAuth, err := auth.GetTokenWithReauth(ctx, serverURL, "", insecureSkipTLS)
		if err != nil {
			clilog.Statusf("Error: OIDC authentication failed: %v\n", err)
			clilog.Statusln("Attempting kubeconfig fallback (this may use a different identity)")
			if tok, loadErr := LoadTokenFromKubeconfig(); loadErr == nil && strings.TrimSpace(tok) != "" {
				setToken(tok)
			} else {
				return nil, fmt.Errorf("OIDC authentication failed and no kubeconfig token available: %w", err)
			}
		} else if token != "" {
			setToken(token)
			if didAuth {
				clilog.Statusln("OIDC authentication successful")
			}
		} else if tok, loadErr := LoadTokenFromKubeconfig(); loadErr == nil && strings.TrimSpace(tok) != "" {
			setToken(tok)
		}
	} else if tokenValue == "" {
		if envToken != "" {
			setToken(envToken)
		} else if tok, loadErr := LoadTokenFromKubeconfig(); loadErr == nil && strings.TrimSpace(tok) != "" {
			setToken(tok)
		}
	}

	var opts []buildapiclient.Option
	if tokenValue != "" {
		opts = append(opts, buildapiclient.WithAuthToken(tokenValue))
	}

	if insecureSkipTLS {
		opts = append(opts, buildapiclient.WithInsecureTLS())
	}
	if caCertFile := os.Getenv("SSL_CERT_FILE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	} else if caCertFile := os.Getenv("REQUESTS_CA_BUNDLE"); caCertFile != "" {
		opts = append(opts, buildapiclient.WithCACertificate(caCertFile))
	}

	return buildapiclient.New(serverURL, opts...)
}

// ExecuteWithReauth executes an API call and retries once after re-auth on auth errors.
func ExecuteWithReauth(
	serverURL string,
	authToken *string,
	insecureSkipTLS bool,
	fn func(*buildapiclient.Client) error,
) error {
	ctx := context.Background()
	currentToken := ""
	if authToken != nil {
		currentToken = strings.TrimSpace(*authToken)
	}
	setToken := func(token string) {
		currentToken = strings.TrimSpace(token)
		if authToken != nil {
			*authToken = currentToken
		}
	}

	runWithFreshClient := func() error {
		client, err := CreateBuildAPIClient(serverURL, authToken, insecureSkipTLS)
		if err != nil {
			return err
		}
		if authToken != nil {
			currentToken = strings.TrimSpace(*authToken)
		}
		return fn(client)
	}

	err := runWithFreshClient()
	if err == nil {
		return nil
	}
	if !auth.IsAuthError(err) {
		return err
	}

	clilog.Statusln("Authentication failed (401), re-authenticating...")
	newToken, _, err := auth.GetTokenWithReauth(ctx, serverURL, currentToken, insecureSkipTLS)
	if err != nil {
		return fmt.Errorf("re-authentication failed: %w", err)
	}
	setToken(newToken)

	clilog.Statusln("Retrying request...")
	err = runWithFreshClient()
	if err == nil {
		return nil
	}
	if !auth.IsAuthError(err) {
		return err
	}

	if tok, loadErr := LoadTokenFromKubeconfig(); loadErr == nil && strings.TrimSpace(tok) != "" {
		setToken(tok)
		clilog.Statusln("Attempting kubeconfig fallback...")
		return runWithFreshClient()
	}

	return err
}

// LoadTokenFromKubeconfig loads a bearer token from kubeconfig.
func LoadTokenFromKubeconfig() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	deferred := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	if restCfg, err := deferred.ClientConfig(); err == nil && restCfg != nil {
		if t := strings.TrimSpace(restCfg.BearerToken); t != "" {
			return t, nil
		}
		if f := strings.TrimSpace(restCfg.BearerTokenFile); f != "" {
			if b, readErr := os.ReadFile(f); readErr == nil {
				if t := strings.TrimSpace(string(b)); t != "" {
					return t, nil
				}
			}
		}
	}

	rawCfg, err := loadingRules.Load()
	if err != nil || rawCfg == nil {
		return "", fmt.Errorf("cannot load kubeconfig: %w", err)
	}
	ctxName := rawCfg.CurrentContext
	if strings.TrimSpace(ctxName) == "" {
		return "", fmt.Errorf("no current kube context")
	}
	ctx := rawCfg.Contexts[ctxName]
	if ctx == nil {
		return "", fmt.Errorf("missing context %s", ctxName)
	}
	ai := rawCfg.AuthInfos[ctx.AuthInfo]
	if ai == nil {
		return "", fmt.Errorf("missing auth info for context %s", ctxName)
	}
	if strings.TrimSpace(ai.Token) != "" {
		return strings.TrimSpace(ai.Token), nil
	}
	if ai.AuthProvider != nil && ai.AuthProvider.Config != nil {
		if t := strings.TrimSpace(ai.AuthProvider.Config["access-token"]); t != "" {
			return t, nil
		}
		if t := strings.TrimSpace(ai.AuthProvider.Config["id-token"]); t != "" {
			return t, nil
		}
		if t := strings.TrimSpace(ai.AuthProvider.Config["token"]); t != "" {
			return t, nil
		}
	}
	if path, lookErr := exec.LookPath("oc"); lookErr == nil && path != "" {
		cmdCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, cmdErr := exec.CommandContext(cmdCtx, path, "whoami", "-t").Output()
		if cmdErr == nil {
			if t := strings.TrimSpace(string(out)); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("no bearer token found in kubeconfig")
}
