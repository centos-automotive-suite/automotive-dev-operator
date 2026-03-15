package caibcommon

import (
	"os"
	"path/filepath"
	"testing"
)

func setupJumpstarterConfig(t *testing.T, baseDir, alias, endpoint, name string) {
	t.Helper()
	jmpDir := filepath.Join(baseDir, "jumpstarter")
	if err := os.MkdirAll(filepath.Join(jmpDir, "clients"), 0700); err != nil {
		t.Fatal(err)
	}
	configYAML := "config:\n  current-client: " + alias + "\n"
	if err := os.WriteFile(filepath.Join(jmpDir, "config.yaml"), []byte(configYAML), 0600); err != nil {
		t.Fatal(err)
	}
	clientYAML := "endpoint: " + endpoint + "\nmetadata:\n  name: " + name + "\n"
	if err := os.WriteFile(filepath.Join(jmpDir, "clients", alias+".yaml"), []byte(clientYAML), 0600); err != nil {
		t.Fatal(err)
	}
}

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func TestResolveJumpstarterClient_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	clientPath := filepath.Join(dir, "my-client.yaml")
	yaml := "endpoint: grpc.lab.example.com:443\nmetadata:\n  name: testclient\n"
	if err := os.WriteFile(clientPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	info, err := ResolveJumpstarterClient(clientPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Path != clientPath {
		t.Errorf("Path = %q, want %q", info.Path, clientPath)
	}
	if info.Endpoint != "grpc.lab.example.com:443" {
		t.Errorf("Endpoint = %q, want %q", info.Endpoint, "grpc.lab.example.com:443")
	}
	if info.Name != "testclient" {
		t.Errorf("Name = %q, want %q", info.Name, "testclient")
	}
	if string(info.Data) != yaml {
		t.Errorf("Data = %q, want %q", string(info.Data), yaml)
	}
}

func TestResolveJumpstarterClient_ExplicitPath_NotFound(t *testing.T) {
	_, err := ResolveJumpstarterClient("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestResolveJumpstarterClient_AutoDetect(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, ".config")
	setupJumpstarterConfig(t, configDir, "myuser", "grpc.remote.example.com:443", "myuser")

	withEnv(t, "JMP_CLIENT_CONFIG_HOME", "")
	withEnv(t, "XDG_CONFIG_HOME", configDir)

	info, err := ResolveJumpstarterClient("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Endpoint != "grpc.remote.example.com:443" {
		t.Errorf("Endpoint = %q, want %q", info.Endpoint, "grpc.remote.example.com:443")
	}
	if info.Name != "myuser" {
		t.Errorf("Name = %q, want %q", info.Name, "myuser")
	}
	if len(info.Data) == 0 {
		t.Error("Data should not be empty")
	}
}

func TestResolveJumpstarterClient_JMPConfigHome(t *testing.T) {
	dir := t.TempDir()
	jmpDir := filepath.Join(dir, "custom-jmp")
	setupJumpstarterConfig(t, jmpDir, "fromenv", "grpc.env.example.com:443", "fromenv")

	withEnv(t, "JMP_CLIENT_CONFIG_HOME", filepath.Join(jmpDir, "jumpstarter"))
	withEnv(t, "XDG_CONFIG_HOME", "")

	info, err := ResolveJumpstarterClient("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Endpoint != "grpc.env.example.com:443" {
		t.Errorf("Endpoint = %q, want %q", info.Endpoint, "grpc.env.example.com:443")
	}
}

func TestResolveJumpstarterClient_NoConfig(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, "JMP_CLIENT_CONFIG_HOME", dir)

	_, err := ResolveJumpstarterClient("")
	if err == nil {
		t.Fatal("expected error when no config exists")
	}
}

func TestResolveJumpstarterClient_EmptyCurrentClient(t *testing.T) {
	dir := t.TempDir()
	jmpDir := filepath.Join(dir, "jumpstarter")
	if err := os.MkdirAll(jmpDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jmpDir, "config.yaml"), []byte("config:\n  current-client: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	withEnv(t, "JMP_CLIENT_CONFIG_HOME", jmpDir)

	_, err := ResolveJumpstarterClient("")
	if err == nil {
		t.Fatal("expected error for empty current-client")
	}
}

func TestResolveJumpstarterClient_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	jmpDir := filepath.Join(dir, "jumpstarter")
	if err := os.MkdirAll(jmpDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jmpDir, "config.yaml"), []byte("config:\n  current-client: ../../../etc/passwd\n"), 0600); err != nil {
		t.Fatal(err)
	}

	withEnv(t, "JMP_CLIENT_CONFIG_HOME", jmpDir)

	_, err := ResolveJumpstarterClient("")
	if err == nil {
		t.Fatal("expected error for path traversal alias")
	}
}

func TestResolveJumpstarterClient_EndpointTrimmed(t *testing.T) {
	dir := t.TempDir()
	clientPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(clientPath, []byte("endpoint: \"  grpc.lab.example.com:443  \"\nmetadata:\n  name: test\n"), 0600); err != nil {
		t.Fatal(err)
	}

	info, err := ResolveJumpstarterClient(clientPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Endpoint != "grpc.lab.example.com:443" {
		t.Errorf("Endpoint = %q, want trimmed value", info.Endpoint)
	}
}
