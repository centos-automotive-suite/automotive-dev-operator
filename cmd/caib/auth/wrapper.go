package auth

import (
	"context"
	"fmt"
	"strings"

	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

// IsAuthError checks if an error is an authentication error (401/403)
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "forbidden")
}

// GetTokenWithReauth gets a token, triggering OIDC re-auth if needed.
// Returns empty string if no OIDC config is available (auth is optional).
// The boolean return indicates whether a fresh auth flow was performed.
// Returns an error if OIDC is configured but config fetch fails (network/server errors).
func GetTokenWithReauth(ctx context.Context, serverURL string, currentToken string, insecureSkipTLS bool) (string, bool, error) {
	// Prefer API config over local: server is source of truth (OperatorConfig).
	// When server has OIDC disabled or init failed, API returns empty JWT and we should not use local OIDC.
	config, err := GetOIDCConfigFromAPI(serverURL, insecureSkipTLS)
	if err != nil {
		// Error fetching config - this is a real error, not "not configured"
		return "", false, fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	if config == nil {
		// API says no OIDC - do not use local config; caller will use kubeconfig
		return "", false, nil
	}

	oidcAuth := NewOIDCAuth(config.IssuerURL, config.ClientID, config.Scopes, insecureSkipTLS)
	if oidcAuth == nil {
		return "", false, fmt.Errorf("failed to initialize OIDC authenticator")
	}

	// If we have a current token, check if it's valid
	if currentToken != "" {
		if oidcAuth.IsTokenValid(currentToken) {
			return currentToken, false, nil
		}
	}

	// Get new token via OIDC flow
	token, fromCache, err := oidcAuth.GetTokenWithStatus(ctx)
	if err != nil {
		return "", false, err
	}
	return token, !fromCache, nil
}

// RefreshCachedToken attempts to refresh the cached token using the stored refresh token.
// Returns the new access token or an error if refresh is not possible.
func RefreshCachedToken(ctx context.Context, serverURL string, insecureSkipTLS bool) (string, error) {
	config, err := GetOIDCConfigFromAPI(serverURL, insecureSkipTLS)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	if config == nil {
		return "", fmt.Errorf("OIDC is not configured on the server")
	}

	oidcAuth := NewOIDCAuth(config.IssuerURL, config.ClientID, config.Scopes, insecureSkipTLS)
	if oidcAuth == nil {
		return "", fmt.Errorf("failed to initialize OIDC authenticator")
	}

	if err := oidcAuth.loadTokenCache(); err != nil {
		return "", fmt.Errorf("no cached token found: %w", err)
	}

	if oidcAuth.tokenCache == nil || oidcAuth.tokenCache.RefreshToken == "" {
		return "", fmt.Errorf("no refresh token stored; run 'caib login <server-url>' first")
	}

	token, err := oidcAuth.tryRefreshToken(ctx)
	if err != nil {
		return "", fmt.Errorf("refresh failed: %w", err)
	}
	return token, nil
}

// CreateClientWithReauth creates a client and handles re-authentication on auth errors.
// If authToken is nil, it will be treated as empty and OIDC will be attempted.
// OIDC errors are logged but do not prevent client creation (auth is optional).
func CreateClientWithReauth(ctx context.Context, serverURL string, authToken *string, insecureSkipTLS bool) (*buildapiclient.Client, error) {
	// Guard against nil pointer
	tokenValue := ""
	if authToken != nil {
		tokenValue = strings.TrimSpace(*authToken)
	}

	// Try to get token from OIDC if needed
	if tokenValue == "" {
		// Try OIDC auth
		token, _, err := GetTokenWithReauth(ctx, serverURL, "", insecureSkipTLS)
		if err != nil {
			// OIDC fetch failed - log but continue (auth is optional, kubeconfig may work)
			fmt.Printf("Warning: OIDC authentication failed: %v\n", err)
		} else if token != "" {
			tokenValue = token
			if authToken != nil {
				*authToken = token
			}
		}
	}

	// Configure TLS options
	var opts []buildapiclient.Option
	opts = append(opts, buildapiclient.WithAuthToken(tokenValue))
	if insecureSkipTLS {
		opts = append(opts, buildapiclient.WithInsecureTLS())
	}

	return buildapiclient.New(serverURL, opts...)
}
