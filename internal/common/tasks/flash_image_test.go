package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlashUsesRefreshedClientConfig(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "mounted-client.yaml")
	if err := os.WriteFile(source, []byte("expired-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "writable"), 0700); err != nil {
		t.Fatal(err)
	}
	setup := shellFunctions(t, flashImageScript, "export JMP_CLIENT_CONFIG=", "\nFLASH_CMD=")
	setup = strings.ReplaceAll(setup, "/tmp", filepath.Join(dir, "writable"))
	body := `
timeout() { shift; "$@"; }
jmp() {
    local config="${@: -1}"
    case "$1" in
        login)
            mkdir -p "$JMP_CLIENT_CONFIG_HOME/clients"
            printf 'refreshed-token\n' > "$JMP_CLIENT_CONFIG_HOME/clients/$(basename "$config" .yaml).yaml"
            ;;
        get) [[ "$(cat "$config")" == refreshed-token ]] ;;
        *) return 1 ;;
    esac
}
` + setup + `
jmp get leases --client-config "$JMP_CLIENT_CONFIG"
`
	cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", body)
	cmd.Env = append(os.Environ(), "JMP_CLIENT_CONFIG="+source)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subsequent command did not use refreshed credentials: %v\n%s", err, out)
	}
	data, err := os.ReadFile(source)
	if err != nil || string(data) != "expired-token\n" {
		t.Fatalf("mounted credentials changed: %q, %v", data, err)
	}
}
