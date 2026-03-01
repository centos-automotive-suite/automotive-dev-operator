// Package config provides local CLI configuration (e.g. default server URL) for caib.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	configDir  = ".caib"
	configFile = "cli.json"

	buildAPIRoutePrefix = "ado-build-api"
	buildAPINamespace   = "automotive-dev-operator-system" // todo: add dynamic namespace discovery
)

// CLIConfig holds saved CLI settings.
type CLIConfig struct {
	ServerURL string `json:"server_url"`
}

// DefaultServer returns the effective default server URL.
// Resolution order: CAIB_SERVER env → saved config → Jumpstarter derivation.
func DefaultServer() string {
	if s := strings.TrimSpace(os.Getenv("CAIB_SERVER")); s != "" {
		return s
	}
	cfg, err := Read()
	if err == nil && cfg != nil {
		if s := strings.TrimSpace(cfg.ServerURL); s != "" {
			return s
		}
	}
	return DeriveServerFromJumpstarter()
}

// JumpstarterEndpoint reads the default Jumpstarter client config files and returns
// the gRPC endpoint, or "" if the config is absent or incomplete.
func JumpstarterEndpoint() string {
	xdgBase := os.Getenv("XDG_CONFIG_HOME")
	if xdgBase == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		xdgBase = filepath.Join(home, ".config")
	}
	jmpDir := filepath.Join(xdgBase, "jumpstarter")

	data, err := os.ReadFile(filepath.Join(jmpDir, "config.yaml"))
	if err != nil {
		return ""
	}
	var userCfg struct {
		Config struct {
			CurrentClient string `yaml:"current-client"`
		} `yaml:"config"`
	}
	if err := yaml.Unmarshal(data, &userCfg); err != nil {
		return ""
	}
	alias := strings.TrimSpace(userCfg.Config.CurrentClient)
	if alias == "" {
		return ""
	}

	data, err = os.ReadFile(filepath.Join(jmpDir, "clients", alias+".yaml"))
	if err != nil {
		return ""
	}
	var clientCfg struct {
		Endpoint string `yaml:"endpoint"`
	}
	if err := yaml.Unmarshal(data, &clientCfg); err != nil {
		return ""
	}
	return strings.TrimSpace(clientCfg.Endpoint)
}

// DeriveServerFromJumpstarter derives the Build API URL from the default Jumpstarter client config,
// checks reachability via /v1/healthz, and if successful saves the URL to ~/.caib/cli.json.
// Returns the derived URL, or "" if the Jumpstarter config is absent, derivation fails, or the server is unreachable.
func DeriveServerFromJumpstarter() string {
	grpcEndpoint := JumpstarterEndpoint()
	if grpcEndpoint == "" {
		return ""
	}

	// Derive Build API URL from gRPC endpoint:
	// grpc.jumpstarter-lab.apps.example.com:443 → https://ado-build-api-<ns>.apps.example.com
	host := grpcEndpoint
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.TrimPrefix(host, "grpc.")
	dotIdx := strings.Index(host, ".")
	if dotIdx == -1 || dotIdx == len(host)-1 {
		return ""
	}
	apiURL := fmt.Sprintf("https://%s-%s.%s", buildAPIRoutePrefix, buildAPINamespace, host[dotIdx+1:])

	// Check reachability via the health endpoint
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(apiURL + "/v1/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Jumpstarter config found, but could not reach derived Build API server %s.\n", apiURL)
		return ""
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Warning: Jumpstarter config found, but derived Build API server %s returned HTTP %d.\n", apiURL, resp.StatusCode)
		return ""
	}

	// Reachable — persist to config so future invocations skip derivation
	fmt.Fprintf(os.Stderr, "Using Build API server derived from Jumpstarter config: %s\n", apiURL)
	if err := SaveServerURL(apiURL); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save derived server URL to config: %v\n", err)
	}
	return apiURL
}

// Read reads the CLI config from the user's home directory.
func Read() (*CLIConfig, error) {
	dir, err := configDirPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg CLIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveServerURL writes the given server URL to the local config file.
func SaveServerURL(serverURL string) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	cfg := &CLIConfig{ServerURL: strings.TrimSpace(serverURL)}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, configFile), data, 0600)
}

func configDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configDir), nil
}
