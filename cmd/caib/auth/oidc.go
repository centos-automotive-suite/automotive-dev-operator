// Package auth provides OIDC authentication functionality for the caib CLI.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Issuer    string    `json:"issuer"`
}

// OIDCConfig holds OIDC provider configuration.
type OIDCConfig struct {
	IssuerURL string
	ClientID  string
	Scopes    []string
}

// OIDCAuth handles OIDC authentication flow and token management.
type OIDCAuth struct {
	config     OIDCConfig
	tokenCache *TokenCache
	cachePath  string
}

// NewOIDCAuth creates a new OIDC authenticator instance.
func NewOIDCAuth(issuerURL, clientID string, scopes []string) *OIDCAuth {
	if issuerURL == "" || clientID == "" {
		return nil
	}

	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
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
		cachePath: cachePath,
	}
}

// GetToken retrieves a valid OIDC token, using cache if available.
func (a *OIDCAuth) GetToken(ctx context.Context) (string, error) {
	token, _, err := a.GetTokenWithStatus(ctx)
	return token, err
}

// GetTokenWithStatus returns the token and whether it came from cache.
func (a *OIDCAuth) GetTokenWithStatus(ctx context.Context) (string, bool, error) {
	// Try to load from cache first
	if err := a.loadTokenCache(); err == nil {
		if a.tokenCache != nil && a.tokenCache.Token != "" {
			// Check if token expires more than 5 minutes from now
			if time.Now().Before(a.tokenCache.ExpiresAt.Add(-5 * time.Minute)) {
				// Verify token is not expired by parsing it
				if a.IsTokenValid(a.tokenCache.Token) {
					return a.tokenCache.Token, true, nil
				}
			}
		}
	}

	// Token expired or not found, trigger re-authentication
	token, err := a.authenticate(ctx)
	if err != nil {
		return "", false, err
	}
	return token, false, nil
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

	// Find available port for callback
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to find available port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return "", fmt.Errorf("failed to close listener: %w", err)
	}

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
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
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
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("callback server error: %w", err)
		}
	}()

	fmt.Println("Token is expired, triggering re-authentication")
	fmt.Printf("\nPlease open the URL in browser: %s\n\n", authURL.String())
	if err := openBrowser(authURL.String()); err != nil {
		fmt.Printf("Warning: Could not open browser automatically: %v\n", err)
		fmt.Println("Please open the URL manually")
	}

	// Wait for callback
	select {
	case code := <-codeChan:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
		// Exchange code for token
		token, err := a.exchangeCodeForToken(ctx, discovery.TokenEndpoint, code, redirectURI, codeVerifier)
		if err != nil {
			return "", fmt.Errorf("failed to exchange code for token: %w", err)
		}

		// Save token to cache
		if err := a.saveTokenCache(token); err != nil {
			fmt.Printf("Warning: Failed to save token cache: %v\n", err)
		}

		return token, nil
	case err := <-errChan:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
		return "", err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
		return "", fmt.Errorf("authentication timeout")
	}
}

func (a *OIDCAuth) exchangeCodeForToken(ctx context.Context, tokenEndpoint, code, redirectURI, codeVerifier string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", a.config.ClientID)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	transport := &http.Transport{}
	// Use default TLS settings

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed: %s: %s", resp.Status, string(body))
	}

	var tokenResp struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	// Prefer id_token, fallback to access_token
	token := tokenResp.IDToken
	if token == "" {
		token = tokenResp.AccessToken
	}

	return token, nil
}

// DiscoveryDocument represents the OIDC discovery document structure.
type DiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (a *OIDCAuth) getDiscovery(discoveryURL string) (*DiscoveryDocument, error) {
	transport := &http.Transport{}
	// Use default TLS settings

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

func (a *OIDCAuth) loadTokenCache() error {
	data, err := os.ReadFile(a.cachePath)
	if err != nil {
		return err
	}

	var cache TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return err
	}

	a.tokenCache = &cache
	return nil
}

func (a *OIDCAuth) saveTokenCache(token string) error {
	// Parse token to get expiration
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	var expiresAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		// Default to 1 hour if no expiration
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	cache := TokenCache{
		Token:     token,
		ExpiresAt: expiresAt,
		Issuer:    a.config.IssuerURL,
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	// Ensure cache directory exists
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
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default:
		cmd = "xdg-open"
	}

	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
