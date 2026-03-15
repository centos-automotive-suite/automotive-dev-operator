package caibcommon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// JumpstarterClientInfo contains the resolved client config path, endpoint, and raw file data.
type JumpstarterClientInfo struct {
	Path     string
	Endpoint string
	Name     string
	Data     []byte
}

// ResolveJumpstarterClient resolves the Jumpstarter client config.
// If explicitPath is provided, it parses that file for endpoint info.
// If empty, it auto-detects from the Jumpstarter user config.
func ResolveJumpstarterClient(explicitPath string) (*JumpstarterClientInfo, error) {
	if explicitPath != "" {
		return parseClientConfig(explicitPath)
	}
	return detectJumpstarterClient()
}

// detectJumpstarterClient auto-detects the current Jumpstarter client config
// by reading the user config to find current-client, then loading that client config.
func detectJumpstarterClient() (*JumpstarterClientInfo, error) {
	configDir := JumpstarterConfigDir()

	userConfigPath := filepath.Join(configDir, "config.yaml")
	data, err := os.ReadFile(userConfigPath)
	if err != nil {
		return nil, fmt.Errorf("no Jumpstarter config found at %s (use --client to specify manually): %w", userConfigPath, err)
	}

	var userConfig struct {
		Config struct {
			CurrentClient string `yaml:"current-client"`
		} `yaml:"config"`
	}
	if err := yaml.Unmarshal(data, &userConfig); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", userConfigPath, err)
	}

	clientAlias := strings.TrimSpace(userConfig.Config.CurrentClient)
	if clientAlias == "" {
		return nil, fmt.Errorf("no current-client set in %s (use --client to specify manually)", userConfigPath)
	}
	if clientAlias != filepath.Base(clientAlias) {
		return nil, fmt.Errorf("invalid current-client alias %q in %s", clientAlias, userConfigPath)
	}

	clientConfigPath := filepath.Join(configDir, "clients", clientAlias+".yaml")
	return parseClientConfig(clientConfigPath)
}

// parseClientConfig reads a Jumpstarter client config file and extracts metadata.
func parseClientConfig(path string) (*JumpstarterClientInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Jumpstarter client config %s: %w", path, err)
	}

	var cfg struct {
		Endpoint string `yaml:"endpoint"`
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("missing endpoint in %s", path)
	}

	return &JumpstarterClientInfo{
		Path:     path,
		Endpoint: endpoint,
		Name:     cfg.Metadata.Name,
		Data:     data,
	}, nil
}

// JumpstarterConfigDir returns the Jumpstarter config directory,
// respecting JMP_CLIENT_CONFIG_HOME and XDG_CONFIG_HOME env vars.
func JumpstarterConfigDir() string {
	if dir := os.Getenv("JMP_CLIENT_CONFIG_HOME"); dir != "" {
		return dir
	}
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "jumpstarter")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "jumpstarter")
}
