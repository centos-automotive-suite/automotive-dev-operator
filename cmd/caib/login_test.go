package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
)

func TestNormalizeServerURL(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		// valid inputs
		{input: "https://example.com", want: "https://example.com"},
		{input: "http://example.com", want: "http://example.com"},
		{input: "example.com", want: "https://example.com"},
		{input: "example.com/", want: "https://example.com"},
		{input: "  example.com  ", want: "https://example.com"},
		{input: "https://example.com/", want: "https://example.com"},
		{input: "https://example.com:8443", want: "https://example.com:8443"},
		{input: "http://192.168.1.1:9090", want: "http://192.168.1.1:9090"},

		// empty / whitespace
		{input: "", wantErr: true},
		{input: "   ", wantErr: true},

		// missing host (e.g. bare "https://")
		{input: "https://", wantErr: true},
		{input: "http://", wantErr: true},

		// disallowed components
		{input: "https://user:pass@example.com", wantErr: true},
		{input: "https://example.com?foo=bar", wantErr: true},
		{input: "https://example.com#anchor", wantErr: true},
		{input: "https://example.com/some/path", wantErr: true},

		// invalid schemes — must be caught before https:// prepend
		{input: "ftp://example.com", wantErr: true},
		{input: "grpc://example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeServerURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("normalizeServerURL(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("normalizeServerURL(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeServerURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoginResultMessage(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		jmpToken string
		didAuth  bool
		want     string
	}{
		{name: "no token yields no message"},
		{
			name:    "fresh OIDC login",
			token:   "oidc-token",
			didAuth: true,
			want:    "OIDC authentication successful",
		},
		{
			name:     "reused Jumpstarter token",
			token:    "jmp-token",
			jmpToken: "jmp-token",
			want:     "Jumpstarter client config",
		},
		{
			name:     "cached token wins over an unused Jumpstarter token",
			token:    "cached-token",
			jmpToken: "jmp-token",
			want:     "Using existing or kubeconfig token",
		},
		{
			name:  "cached token with no Jumpstarter config",
			token: "cached-token",
			want:  "Using existing or kubeconfig token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := loginResultMessage(tt.token, tt.jmpToken, tt.didAuth)
			if tt.want == "" {
				if got != "" {
					t.Errorf("loginResultMessage() = %q, want empty", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("loginResultMessage() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// TestCheckServerReachable_Unreachable verifies that an unreachable address
// returns an error, which prevents the URL from being saved to config.
func TestCheckServerReachable_Unreachable(t *testing.T) {
	// Port 1 is never open; any HTTP dial will fail immediately.
	err := checkServerReachable("http://127.0.0.1:1", false)
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

// TestCheckServerReachable_Reachable verifies that a server responding on
// /v1/healthz (any status code) is considered reachable.
func TestCheckServerReachable_Reachable(t *testing.T) {
	// Return 200 OK — healthy server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := checkServerReachable(srv.URL, false); err != nil {
		t.Errorf("unexpected error for reachable server: %v", err)
	}
}

// TestCheckServerReachable_NonOKStatusStillReachable verifies that a non-200
// response (e.g. 404 when the server has no healthz endpoint) is still treated
// as reachable — only connection failures are fatal.
func TestCheckServerReachable_NonOKStatusStillReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if err := checkServerReachable(srv.URL, false); err != nil {
		t.Errorf("unexpected error for server returning 404: %v", err)
	}
}

// TestLoginDoesNotSaveConfigWhenServerUnreachable verifies that an unreachable
// server URL is never written to the config file. This mirrors the runLogin
// guard: checkServerReachable must succeed before SaveServerURL is called.
func TestLoginDoesNotSaveConfigWhenServerUnreachable(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	cfgPath := filepath.Join(tmpDir, "caib", "cli.json")
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("config file should not exist before test")
	}

	// checkServerReachable fails → SaveServerURL must not be called.
	if err := checkServerReachable("http://127.0.0.1:1", false); err == nil {
		t.Fatal("expected reachability error, got nil")
	}

	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Error("config file must not be written when the server is unreachable")
	}
}

// TestLoginSavesConfigWhenServerReachable verifies that a reachable server
// results in the URL being saved to config.
func TestLoginSavesConfigWhenServerReachable(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := checkServerReachable(srv.URL, false); err != nil {
		t.Fatalf("unexpected reachability error: %v", err)
	}

	if err := config.SaveServerURL(srv.URL); err != nil {
		t.Fatalf("SaveServerURL: %v", err)
	}

	cfgPath := filepath.Join(tmpDir, "caib", "cli.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not found after save: %v", err)
	}

	var cfg config.CLIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	if cfg.ServerURL != srv.URL {
		t.Errorf("config server_url = %q, want %q", cfg.ServerURL, srv.URL)
	}
}
