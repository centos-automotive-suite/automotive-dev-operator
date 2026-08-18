// Package config provides local CLI configuration (e.g. default server URL) for caib.
package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"gopkg.in/yaml.v3"
)

const (
	appDirName = "caib"
	configFile = "cli.json"

	buildAPIRoutePrefix = "ado-build-api"
)

// healthHTTPClient is the HTTP client used for the health check in DeriveServerFromJumpstarter.
// nil means use the default (insecure TLS, 5s timeout). Overridden in tests.
var healthHTTPClient *http.Client

// CLIConfig holds saved CLI settings.
type CLIConfig struct {
	ServerURL           string `json:"server_url"`
	DerivedFromEndpoint string `json:"derived_from_endpoint,omitempty"`
}

// DefaultServer returns the effective default server URL: CAIB_SERVER env, then saved config.
// For full resolution including Jumpstarter derivation, use DefaultServerWithDerive.
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
	return ""
}

// DefaultServerWithDerive returns the effective default server URL.
// Resolution order: CAIB_SERVER env → saved config (with staleness check) → Jumpstarter derivation.
// When the saved URL was auto-derived from a Jumpstarter endpoint that no longer matches
// the current Jumpstarter config, the cached value is skipped and re-derived.
func DefaultServerWithDerive() string {
	if s := strings.TrimSpace(os.Getenv("CAIB_SERVER")); s != "" {
		return s
	}

	cfg, err := Read()
	if err == nil && cfg != nil {
		if s := strings.TrimSpace(cfg.ServerURL); s != "" {
			if !IsDerivedAndStale(cfg) {
				return s
			}
		}
	}

	return DeriveServerFromJumpstarter()
}

// IsDerivedAndStale returns true when the saved config was auto-derived from a
// Jumpstarter endpoint that no longer matches the current Jumpstarter client config.
// Manually-set URLs (DerivedFromEndpoint == "") are never considered stale.
func IsDerivedAndStale(cfg *CLIConfig) bool {
	if cfg.DerivedFromEndpoint == "" {
		return false
	}
	return JumpstarterEndpoint() != cfg.DerivedFromEndpoint
}

// JumpstarterEndpoint reads the default Jumpstarter client config files and returns
// the gRPC endpoint, or "" if the config is absent or incomplete.
func JumpstarterEndpoint() string {
	jmpDir := os.Getenv("JMP_CLIENT_CONFIG_HOME")
	if jmpDir == "" {
		xdgBase := os.Getenv("XDG_CONFIG_HOME")
		if xdgBase == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			xdgBase = filepath.Join(home, ".config")
		}
		jmpDir = filepath.Join(xdgBase, "jumpstarter")
	}

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
	if alias == "" || alias != filepath.Base(alias) {
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

// buildAPINamespaceCandidates returns the namespace candidates to probe when
// auto-deriving the Build API URL from Jumpstarter config.
// CAIB_BUILD_API_NAMESPACE env var takes priority; otherwise we fall back to
// the default operator namespace.
func buildAPINamespaceCandidates() []string {
	if ns := strings.TrimSpace(os.Getenv("CAIB_BUILD_API_NAMESPACE")); ns != "" {
		return []string{ns}
	}
	return []string{"automotive-dev-operator-system"}
}

// DeriveServerFromJumpstarter derives the Build API URL from the default Jumpstarter client config,
// checks reachability via /v1/healthz, and if successful saves the URL to ~/.config/caib/cli.json.
// Returns the derived URL, or "" if the Jumpstarter config is absent, derivation fails, or the server is unreachable.
func DeriveServerFromJumpstarter() string {
	grpcEndpoint := JumpstarterEndpoint()
	if grpcEndpoint == "" {
		return ""
	}
	rawEndpoint := grpcEndpoint

	// Derive Build API URL from gRPC endpoint:
	// grpc.jumpstarter-lab.apps.example.com:443 → https://ado-build-api-<ns>.apps.example.com
	if !strings.Contains(grpcEndpoint, "://") {
		grpcEndpoint = "grpc://" + grpcEndpoint // add dummy scheme - required for url.Parse
	}
	u, err := url.Parse(grpcEndpoint)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := u.Hostname()
	var baseDomain string
	if idx := strings.Index(host, ".apps."); idx != -1 {
		baseDomain = host[idx+1:]
	} else {
		parts := strings.SplitN(host, ".", 3)
		if len(parts) < 3 {
			return ""
		}
		baseDomain = parts[2]
	}

	httpClient := healthHTTPClient
	if httpClient == nil {
		httpClient = &http.Client{ //nolint:gosec
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec
			},
		}
	}

	// Probe each candidate namespace until we find a reachable build API
	for _, ns := range buildAPINamespaceCandidates() {
		apiURL := fmt.Sprintf("https://%s-%s.%s", buildAPIRoutePrefix, ns, baseDomain)
		resp, err := httpClient.Get(apiURL + "/v1/healthz")
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}

		clilog.Statusf("Using Build API server derived from Jumpstarter config: %s\n", apiURL)
		if err := saveDerivedServerURL(apiURL, rawEndpoint); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save derived server URL to config: %v\n", err)
		}
		return apiURL
	}

	fmt.Fprintf(os.Stderr, "Warning: Jumpstarter config found, but could not reach Build API server on %s.\n", baseDomain)
	return ""
}

// Read reads the CLI config from XDG config (typically ~/.config/caib).
func Read() (*CLIConfig, error) {
	path, err := configFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
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
// This is the manual-set path (e.g. caib login <url>) — clears DerivedFromEndpoint
// so the URL is never auto-invalidated.
func SaveServerURL(serverURL string) error {
	return saveConfig(&CLIConfig{ServerURL: strings.TrimSpace(serverURL)})
}

// saveDerivedServerURL saves a server URL that was auto-derived from a Jumpstarter endpoint.
// The source endpoint is recorded so the cached URL can be invalidated when the
// Jumpstarter config changes.
func saveDerivedServerURL(serverURL, sourceEndpoint string) error {
	return saveConfig(&CLIConfig{
		ServerURL:           strings.TrimSpace(serverURL),
		DerivedFromEndpoint: strings.TrimSpace(sourceEndpoint),
	})
}

func saveConfig(cfg *CLIConfig) error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// DirPath returns the config directory for caib.
func DirPath() (string, error) {
	if base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); base != "" {
		return filepath.Join(base, appDirName), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", appDirName), nil
}

// CacheDirPath returns the cache directory for caib.
func CacheDirPath() (string, error) {
	if base := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); base != "" {
		return filepath.Join(base, appDirName), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", appDirName), nil
}

func configFilePath() (string, error) {
	dir, err := DirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFile), nil
}
