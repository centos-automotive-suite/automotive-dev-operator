// Package auth provides OIDC authentication functionality for the caib CLI.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenCacheDir  = ".caib"
	tokenCacheFile = "token.json"
)

// TokenCache stores cached OIDC token information.
type TokenCache struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Issuer       string    `json:"issuer"`
}

// OIDCConfig holds OIDC provider configuration.
type OIDCConfig struct {
	IssuerURL string
	ClientID  string
	Scopes    []string
}

// OIDCAuth handles OIDC authentication flow and token management.
type OIDCAuth struct {
	config          OIDCConfig
	tokenCache      *TokenCache
	cachePath       string
	insecureSkipTLS bool
}

// NewOIDCAuth creates a new OIDC authenticator instance.
func NewOIDCAuth(issuerURL, clientID string, scopes []string, insecureSkipTLS bool) *OIDCAuth {
	if issuerURL == "" || clientID == "" {
		return nil
	}

	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	cachePath := filepath.Join(homeDir, tokenCacheDir, tokenCacheFile)

	return &OIDCAuth{
		config: OIDCConfig{
			IssuerURL: issuerURL,
			ClientID:  clientID,
			Scopes:    scopes,
		},
		cachePath:       cachePath,
		insecureSkipTLS: insecureSkipTLS,
	}
}

// GetToken retrieves a valid OIDC token, using cache if available.
func (a *OIDCAuth) GetToken(ctx context.Context) (string, error) {
	token, _, err := a.GetTokenWithStatus(ctx)
	return token, err
}

// GetTokenWithStatus returns the token and whether it came from cache.
func (a *OIDCAuth) GetTokenWithStatus(ctx context.Context) (string, bool, error) {
	if err := a.loadTokenCache(); err == nil {
		if a.tokenCache != nil && a.tokenCache.Token != "" {
			if time.Now().Before(a.tokenCache.ExpiresAt.Add(-5*time.Minute)) && a.IsTokenValid(a.tokenCache.Token) {
				return a.tokenCache.Token, true, nil
			}

			// Access token expired — try silent refresh if we have a refresh token
			if a.tokenCache.RefreshToken != "" {
				token, err := a.tryRefreshToken(ctx)
				if err == nil {
					return token, true, nil
				}
			}
		}
	}

	// No cache, no refresh token, or refresh failed — full browser login
	token, err := a.authenticate(ctx)
	if err != nil {
		return "", false, err
	}
	return token, false, nil
}

// tryRefreshToken attempts to silently get a new access token using the cached refresh token.
func (a *OIDCAuth) tryRefreshToken(ctx context.Context) (string, error) {
	discoveryURL := strings.TrimSuffix(a.config.IssuerURL, "/") + "/.well-known/openid-configuration"
	discovery, err := a.getDiscovery(discoveryURL)
	if err != nil {
		return "", err
	}

	tokenResp, err := a.refreshAccessToken(ctx, discovery.TokenEndpoint, a.tokenCache.RefreshToken)
	if err != nil {
		return "", err
	}

	token := tokenResp.AccessToken
	if token == "" {
		token = tokenResp.IDToken
	}

	// Use the new refresh token if provided, otherwise keep the old one
	refreshToken := tokenResp.RefreshToken
	if refreshToken == "" {
		refreshToken = a.tokenCache.RefreshToken
	}

	if err := a.saveTokenCache(token, refreshToken, tokenResp.ExpiresIn); err != nil {
		fmt.Printf("Warning: Failed to save token cache: %v\n", err)
	}

	return token, nil
}

// IsTokenValid checks if a token is valid and not expired.
func (a *OIDCAuth) IsTokenValid(token string) bool {
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return false
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return false
		}
	}

	return true
}

func (a *OIDCAuth) authenticate(ctx context.Context) (string, error) {
	if a.config.IssuerURL == "" {
		return "", fmt.Errorf("issuer URL is required")
	}

	// Get OIDC discovery document
	discoveryURL := strings.TrimSuffix(a.config.IssuerURL, "/") + "/.well-known/openid-configuration"
	discovery, err := a.getDiscovery(discoveryURL)
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC discovery: %w", err)
	}

	// Generate state and PKCE code verifier
	state, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	codeVerifier, err := generateRandomString(43)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeChallenge := base64URLEncode(sha256Hash(codeVerifier))

	// Bind callback server to a port and keep the listener so no other process can claim it
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to find available port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	// Build authorization URL
	authURL, err := url.Parse(discovery.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", a.config.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(a.config.Scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	// Create callback server
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}

			code := r.URL.Query().Get("code")
			returnedState := r.URL.Query().Get("state")
			errorParam := r.URL.Query().Get("error")

			if errorParam != "" {
				errChan <- fmt.Errorf("OIDC error: %s", errorParam)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, "Authentication failed: %s", errorParam)
				return
			}

			if code == "" {
				errChan <- fmt.Errorf("no authorization code received")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, "No authorization code received")
				return
			}

			if returnedState != state {
				errChan <- fmt.Errorf("state mismatch")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, "State mismatch")
				return
			}

			codeChan <- code
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "Authentication successful! You can close this window.")
		}),
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("callback server error: %w", err)
		}
	}()

	browserFailed := false
	if err := openBrowser(authURL.String()); err != nil {
		browserFailed = true
	}

	// If the browser opened, give the SSO session a moment to auto-complete.
	// Only show the URL if it doesn't come back quickly (user needs to interact).
	if !browserFailed {
		select {
		case code := <-codeChan:
			return a.handleAuthCode(ctx, server, discovery.TokenEndpoint, code, redirectURI, codeVerifier)
		case err := <-errChan:
			return a.shutdownAndReturn(server, err)
		case <-time.After(3 * time.Second):
			fmt.Printf("\nPlease complete login in your browser or open the URL manually:\n%s\n\n", authURL.String())
		}
	} else {
		fmt.Printf("\nCould not open browser automatically. Please open this URL:\n%s\n\n", authURL.String())
	}

	select {
	case code := <-codeChan:
		return a.handleAuthCode(ctx, server, discovery.TokenEndpoint, code, redirectURI, codeVerifier)
	case err := <-errChan:
		return a.shutdownAndReturn(server, err)
	case <-ctx.Done():
		return a.shutdownAndReturn(server, ctx.Err())
	case <-time.After(5 * time.Minute):
		return a.shutdownAndReturn(server, fmt.Errorf("authentication timeout"))
	}
}

func (a *OIDCAuth) handleAuthCode(ctx context.Context, server *http.Server, tokenEndpoint, code, redirectURI, codeVerifier string) (string, error) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(shutdownCtx)
	cancel()

	tokenResp, err := a.exchangeCodeForToken(ctx, tokenEndpoint, code, redirectURI, codeVerifier)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code for token: %w", err)
	}

	token := tokenResp.AccessToken
	if token == "" {
		token = tokenResp.IDToken
	}

	if err := a.saveTokenCache(token, tokenResp.RefreshToken, tokenResp.ExpiresIn); err != nil {
		fmt.Printf("Warning: Failed to save token cache: %v\n", err)
	}

	return token, nil
}

func (a *OIDCAuth) shutdownAndReturn(server *http.Server, err error) (string, error) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(shutdownCtx)
	cancel()
	return "", err
}

type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (a *OIDCAuth) doTokenRequest(ctx context.Context, tokenEndpoint string, data url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	transport := &http.Transport{}
	if a.insecureSkipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: %s: %s", resp.Status, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

func (a *OIDCAuth) exchangeCodeForToken(ctx context.Context, tokenEndpoint, code, redirectURI, codeVerifier string) (*tokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", a.config.ClientID)
	data.Set("code_verifier", codeVerifier)

	tokenResp, err := a.doTokenRequest(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	if tokenResp.AccessToken == "" && tokenResp.IDToken == "" {
		return nil, fmt.Errorf("token endpoint returned neither id_token nor access_token")
	}
	return tokenResp, nil
}

func (a *OIDCAuth) refreshAccessToken(ctx context.Context, tokenEndpoint, refreshToken string) (*tokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", a.config.ClientID)

	tokenResp, err := a.doTokenRequest(ctx, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	if tokenResp.AccessToken == "" && tokenResp.IDToken == "" {
		return nil, fmt.Errorf("refresh response returned neither id_token nor access_token")
	}
	return tokenResp, nil
}

// DiscoveryDocument represents the OIDC discovery document structure.
type DiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (a *OIDCAuth) getDiscovery(discoveryURL string) (*DiscoveryDocument, error) {
	transport := &http.Transport{}
	if a.insecureSkipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery request failed: %s", resp.Status)
	}

	var discovery DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, err
	}

	return &discovery, nil
}

// LoadTokenCache reads the token cache from disk. Returns (nil, nil) if no cache file exists.
func LoadTokenCache() (*TokenCache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cachePath := filepath.Join(homeDir, tokenCacheDir, tokenCacheFile)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cache TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	return &cache, nil
}

func (a *OIDCAuth) loadTokenCache() error {
	data, err := os.ReadFile(a.cachePath)
	if err != nil {
		return err
	}

	var cache TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return err
	}
	// Reject cache if issuer changed (e.g. different OIDC provider) so we fetch a new token
	if cache.Issuer != a.config.IssuerURL {
		return fmt.Errorf("cached token issuer %q does not match current config %q", cache.Issuer, a.config.IssuerURL)
	}
	a.tokenCache = &cache
	return nil
}

func (a *OIDCAuth) saveTokenCache(token, refreshToken string, expiresIn int) error {
	var expiresAt time.Time
	if expiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	} else {
		// Fall back to JWT exp claim for providers that don't set expires_in
		parser := jwt.NewParser()
		claims := jwt.MapClaims{}
		if _, _, err := parser.ParseUnverified(token, claims); err == nil {
			if exp, ok := claims["exp"].(float64); ok {
				expiresAt = time.Unix(int64(exp), 0)
			}
		}
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(1 * time.Hour)
		}
	}

	cache := TokenCache{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Issuer:       a.config.IssuerURL,
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(a.cachePath), 0700); err != nil {
		return err
	}

	return os.WriteFile(a.cachePath, data, 0600)
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func sha256Hash(data string) []byte {
	h := sha256.Sum256([]byte(data))
	return h[:]
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", "", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	return exec.Command(cmd, args...).Start()
}
