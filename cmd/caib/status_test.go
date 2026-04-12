package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// isolateEnv sets env vars for the test and auto-restores them on cleanup.
func isolateEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

// --- resolveServerWithSource ---

func TestResolveServerWithSource_EnvVar(t *testing.T) {
	tmp := t.TempDir()
	isolateEnv(t, map[string]string{
		"CAIB_SERVER":     "https://from-env.example.com",
		"HOME":            tmp,
		"XDG_CONFIG_HOME": filepath.Join(tmp, "xdg"),
	})

	url, source := resolveServerWithSource()
	if url != "https://from-env.example.com" {
		t.Errorf("expected URL from env, got %q", url)
	}
	if source != sourceCAIBEnv {
		t.Errorf("expected source %q, got %q", sourceCAIBEnv, source)
	}
}

func TestResolveServerWithSource_SavedConfig(t *testing.T) {
	tmp := t.TempDir()
	isolateEnv(t, map[string]string{
		"CAIB_SERVER":     "",
		"HOME":            tmp,
		"XDG_CONFIG_HOME": filepath.Join(tmp, "xdg"),
	})

	configDir := filepath.Join(tmp, "xdg", "caib")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(configDir, "cli.json"),
		[]byte(`{"server_url":"https://from-config.example.com"}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	url, source := resolveServerWithSource()
	if url != "https://from-config.example.com" {
		t.Errorf("expected URL from config, got %q", url)
	}
	if source != "saved config (~/.config/caib/cli.json)" {
		t.Errorf("expected source 'saved config', got %q", source)
	}
}

func TestResolveServerWithSource_NothingConfigured(t *testing.T) {
	tmp := t.TempDir()
	isolateEnv(t, map[string]string{
		"CAIB_SERVER":            "",
		"HOME":                   tmp,
		"XDG_CONFIG_HOME":        filepath.Join(tmp, "xdg"),
		"JMP_CLIENT_CONFIG_HOME": filepath.Join(tmp, "no-jmp"),
	})

	url, source := resolveServerWithSource()
	if url != "" {
		t.Errorf("expected empty URL, got %q", url)
	}
	if source != "" {
		t.Errorf("expected empty source, got %q", source)
	}
}

// --- checkServerHealth ---

func TestCheckServerHealth_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	status := checkServerHealth(srv.URL)
	if status != statusReachable {
		t.Errorf("expected %q, got %q", statusReachable, status)
	}
}

func TestCheckServerHealth_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	status := checkServerHealth(srv.URL)
	expected := "unhealthy (HTTP 503)"
	if status != expected {
		t.Errorf("expected %q, got %q", expected, status)
	}
}

func TestCheckServerHealth_Unreachable(t *testing.T) {
	status := checkServerHealth("http://127.0.0.1:1")
	if len(status) < 12 || status[:11] != "unreachable" {
		t.Errorf("expected 'unreachable (...)', got %q", status)
	}
}

// --- gatherStatus ---

func TestGatherStatus_WithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	isolateEnv(t, map[string]string{
		"CAIB_SERVER":            srv.URL,
		"HOME":                   tmp,
		"XDG_CONFIG_HOME":        filepath.Join(tmp, "xdg"),
		"JMP_CLIENT_CONFIG_HOME": filepath.Join(tmp, "no-jmp"),
	})

	info := gatherStatus()

	if info.Server.URL != srv.URL {
		t.Errorf("expected server URL %q, got %q", srv.URL, info.Server.URL)
	}
	if info.Server.Source != sourceCAIBEnv {
		t.Errorf("expected source %q, got %q", sourceCAIBEnv, info.Server.Source)
	}
	if info.Server.Status != statusReachable {
		t.Errorf("expected status %q, got %q", statusReachable, info.Server.Status)
	}
}

func TestGatherStatus_NoServer(t *testing.T) {
	tmp := t.TempDir()
	isolateEnv(t, map[string]string{
		"CAIB_SERVER":            "",
		"HOME":                   tmp,
		"XDG_CONFIG_HOME":        filepath.Join(tmp, "xdg"),
		"JMP_CLIENT_CONFIG_HOME": filepath.Join(tmp, "no-jmp"),
	})

	info := gatherStatus()

	if info.Server.URL != "" {
		t.Errorf("expected empty server URL, got %q", info.Server.URL)
	}
	if info.Server.Status != statusNotConfigured {
		t.Errorf("expected status %q, got %q", statusNotConfigured, info.Server.Status)
	}
}

// --- JSON / YAML output ---

func TestStatusInfo_JSONRoundTrip(t *testing.T) {
	info := statusInfo{
		Server: serverInfo{
			URL:    "https://api.example.com",
			Source: sourceCAIBEnv,
			Status: statusReachable,
		},
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var decoded statusInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if decoded.Server.URL != info.Server.URL {
		t.Errorf("JSON round-trip: server URL mismatch: %q vs %q", decoded.Server.URL, info.Server.URL)
	}
	if decoded.Server.Source != info.Server.Source {
		t.Errorf("JSON round-trip: source mismatch: %q vs %q", decoded.Server.Source, info.Server.Source)
	}
}

func TestStatusInfo_YAMLRoundTrip(t *testing.T) {
	info := statusInfo{
		Server: serverInfo{
			URL:    "https://api.example.com",
			Source: "saved config",
			Status: "unreachable",
		},
	}

	data, err := yaml.Marshal(info)
	if err != nil {
		t.Fatalf("YAML marshal failed: %v", err)
	}

	var decoded statusInfo
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("YAML unmarshal failed: %v", err)
	}

	if decoded.Server.Status != info.Server.Status {
		t.Errorf("YAML round-trip: status mismatch: %q vs %q", decoded.Server.Status, info.Server.Status)
	}
	if decoded.Server.URL != info.Server.URL {
		t.Errorf("YAML round-trip: URL mismatch: %q vs %q", decoded.Server.URL, info.Server.URL)
	}
}
