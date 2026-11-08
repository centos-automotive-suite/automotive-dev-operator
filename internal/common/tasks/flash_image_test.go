package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The lease-id result must name a lease the build still holds: a lease the
// script released after a failed flash is not reported.
func TestFlashLeaseIDResult(t *testing.T) {
	for _, tc := range []struct {
		name, existingLease, flashExit, deleteExit, want string
	}{
		{"flash succeeded", "", "0", "0", "lease-new"},
		{"flash failed, lease released", "", "1", "0", ""},
		{"flash failed, release failed", "", "1", "1", "lease-new"},
		{"flash failed, user lease kept", "lease-user", "1", "0", "lease-user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, "client.yaml")
			if err := os.WriteFile(config, []byte("token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			result := filepath.Join(dir, "lease-id")
			script := strings.ReplaceAll(flashImageScript, "JMP_CLIENT_CONFIG_HOME=/tmp", "JMP_CLIENT_CONFIG_HOME="+dir)
			body := `
emit_progress() { :; }
timeout() { shift; "$@"; }
jmp() {
    case "$1" in
        login) ;;
        create) echo lease-new ;;
        shell) return "$FLASH_EXIT" ;;
        delete) return "$DELETE_EXIT" ;;
        *) return 1 ;;
    esac
}
` + script
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(),
				"JMP_CLIENT_CONFIG="+config,
				"RESULTS_LEASE_ID_PATH="+result,
				"IMAGE_REF=registry/image:tag",
				"EXPORTER_SELECTOR=board=rpi",
				"EXISTING_LEASE="+tc.existingLease,
				"FLASH_EXIT="+tc.flashExit,
				"DELETE_EXIT="+tc.deleteExit,
			)
			out, _ := cmd.CombinedOutput()
			data, err := os.ReadFile(result)
			if err != nil {
				t.Fatalf("reading lease-id result: %v\n%s", err, out)
			}
			if string(data) != tc.want {
				t.Fatalf("lease-id result = %q, want %q\n%s", data, tc.want, out)
			}
		})
	}
}

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
