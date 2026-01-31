// Package auth provides OIDC authentication functionality for the caib CLI.
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GetOIDCConfigFromAPI fetches OIDC configuration from the Build API server.
func GetOIDCConfigFromAPI(serverURL string) (*OIDCConfig, error) {
	transport := &http.Transport{}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	configURL := strings.TrimSuffix(serverURL, "/") + "/v1/auth/config"
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config from API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		// OIDC not configured - this is expected, return nil config without error
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OIDC config: HTTP %d", resp.StatusCode)
	}

	var apiResponse struct {
		ClientID string `json:"clientId"`
		JWT      []struct {
			Issuer struct {
				URL       string   `json:"url"`
				Audiences []string `json:"audiences,omitempty"`
			} `json:"issuer"`
			ClaimMappings struct {
				Username struct {
					Claim  string `json:"claim"`
					Prefix string `json:"prefix,omitempty"`
				} `json:"username"`
			} `json:"claimMappings"`
		} `json:"jwt"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC config response: %w", err)
	}

	if len(apiResponse.JWT) == 0 {
		// OIDC not configured - this is expected, return nil config without error
		return nil, nil
	}

	jwtConfig := apiResponse.JWT[0]

	clientID := apiResponse.ClientID
	if clientID == "" {
		return nil, fmt.Errorf("OIDC client ID is required but not provided by the server")
	}

	issuerURL := jwtConfig.Issuer.URL
	if issuerURL == "" {
		return nil, fmt.Errorf("OIDC issuer URL is required but not provided by the server")
	}

	return &OIDCConfig{
		IssuerURL: issuerURL,
		ClientID:  clientID,
		Scopes:    []string{"openid", "profile", "email"},
	}, nil
}

// GetOIDCConfigFromLocalConfig tries to read from local config file
func GetOIDCConfigFromLocalConfig() (*OIDCConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(homeDir, tokenCacheDir, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config struct {
		IssuerURL string   `json:"issuer_url"`
		ClientID  string   `json:"client_id"`
		Scopes    []string `json:"scopes"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if config.IssuerURL == "" || config.ClientID == "" {
		return nil, fmt.Errorf("invalid config: issuer_url and client_id required")
	}

	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &OIDCConfig{
		IssuerURL: config.IssuerURL,
		ClientID:  config.ClientID,
		Scopes:    scopes,
	}, nil
}

// SaveOIDCConfig saves OIDC config to local file
func SaveOIDCConfig(config *OIDCConfig) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(homeDir, tokenCacheDir, "config.json")

	configData := map[string]interface{}{
		"issuer_url": config.IssuerURL,
		"client_id":  config.ClientID,
		"scopes":     config.Scopes,
	}

	data, err := json.MarshalIndent(configData, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}
