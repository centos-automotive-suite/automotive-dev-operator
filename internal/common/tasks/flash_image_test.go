package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
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

// The flash task reuses the workspace's lease only while `jmp get leases`
// lists it for the target's selector, and releases only a lease it created.
func TestFlashLeaseSelection(t *testing.T) {
	for _, tc := range []struct {
		name, existingLease, workspaceLease, activeLeases, getExit string
		wantGet, wantCreate                                        bool
		wantFlashLease, wantLog                                    string
		wantDeleted                                                []string
	}{
		{
			name: "explicit lease is used as is", existingLease: "lease-user", workspaceLease: "lease-ws",
			activeLeases: "lease-ws\n", getExit: "0", wantFlashLease: "lease-user",
		},
		{
			name: "fitting workspace lease is reused", workspaceLease: "lease-ws",
			activeLeases: "lease-other\nlease-ws\n", getExit: "0", wantGet: true, wantFlashLease: "lease-ws",
		},
		{
			name: "workspace lease that does not fit is replaced", workspaceLease: "lease-ws",
			activeLeases: "lease-ws-2\n", getExit: "0", wantGet: true, wantCreate: true, wantFlashLease: "lease-new",
			wantLog: "jmp delete leases lease-ws", wantDeleted: []string{"lease-new"},
		},
		{
			name: "lease lookup failure fails the flash", workspaceLease: "lease-ws",
			activeLeases: "lease-ws\n", getExit: "1", wantGet: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, "client.yaml")
			if err := os.WriteFile(config, []byte("token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			callsFile := filepath.Join(dir, "jmp-calls")
			script := strings.ReplaceAll(flashImageScript, "JMP_CLIENT_CONFIG_HOME=/tmp", "JMP_CLIENT_CONFIG_HOME="+dir)
			body := `
emit_progress() { :; }
timeout() { shift; "$@"; }
jmp() {
    printf '%s\n' "$*" >> "$JMP_CALLS"
    case "$1" in
        login) ;;
        get) printf '%s' "$ACTIVE_LEASES"; return "$GET_EXIT" ;;
        create) echo lease-new ;;
        shell) return 1 ;;
        delete) ;;
        *) return 1 ;;
    esac
}
` + script
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(),
				"JMP_CLIENT_CONFIG="+config,
				"JMP_CALLS="+callsFile,
				"IMAGE_REF=registry/image:tag",
				"EXPORTER_SELECTOR=board=rpi",
				"EXISTING_LEASE="+tc.existingLease,
				"WORKSPACE_LEASE="+tc.workspaceLease,
				"ACTIVE_LEASES="+tc.activeLeases,
				"GET_EXIT="+tc.getExit,
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("flash succeeded, want failure\n%s", out)
			}
			data, err := os.ReadFile(callsFile)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Split(strings.TrimSpace(string(data)), "\n")
			callsTo := func(command string) []string {
				var matched []string
				for _, call := range calls {
					if strings.HasPrefix(call, command+" ") {
						matched = append(matched, call)
					}
				}
				return matched
			}

			clientConfig := filepath.Join(dir, "clients", "client.yaml")
			for _, check := range []struct {
				command string
				want    bool
				call    string
			}{
				{"get", tc.wantGet, "get leases --client-config " + clientConfig + " -l board=rpi -o name"},
				{"create", tc.wantCreate, "create lease --client-config " + clientConfig + " -l board=rpi --duration 03:00:00 -o name"},
			} {
				var want []string
				if check.want {
					want = []string{check.call}
				}
				if got := callsTo(check.command); !slices.Equal(got, want) {
					t.Errorf("jmp %s calls = %q, want %q\n%s", check.command, got, want, out)
				}
			}
			shells := callsTo("shell")
			if tc.wantFlashLease == "" {
				if len(shells) != 0 {
					t.Errorf("flash ran: %q\n%s", shells, out)
				}
			} else if len(shells) != 1 || !strings.Contains(shells[0], " --lease "+tc.wantFlashLease+" ") {
				t.Errorf("flash runs = %q, want one on %s\n%s", shells, tc.wantFlashLease, out)
			}
			var deleted []string
			for _, call := range callsTo("delete") {
				fields := strings.Fields(call)
				deleted = append(deleted, fields[len(fields)-1])
			}
			if !slices.Equal(deleted, tc.wantDeleted) {
				t.Errorf("released leases = %q, want %q\n%s", deleted, tc.wantDeleted, out)
			}
			if !strings.Contains(string(out), tc.wantLog) {
				t.Errorf("log does not mention %q\n%s", tc.wantLog, out)
			}
		})
	}
}

// The pipeline hands the workspace's lease to the flash task, and the
// standalone flash TaskRun, which does not set it, gets an empty default.
func TestFlashWorkspaceLeasePlumbing(t *testing.T) {
	pipeline := GenerateTektonPipeline("test", "test-ns", nil)
	if !declaresEmptyDefault(pipeline.Spec.Params, "flash-workspace-lease") {
		t.Error("pipeline must declare flash-workspace-lease with an empty default")
	}
	binding, found := "", false
	for i := range pipeline.Spec.Tasks {
		if pipeline.Spec.Tasks[i].Name == "flash-image" {
			binding, found = taskParamBinding(&pipeline.Spec.Tasks[i], "workspace-lease-name")
		}
	}
	if !found || binding != "$(params.flash-workspace-lease)" {
		t.Errorf("flash-image workspace-lease-name binding = %q, present=%t", binding, found)
	}

	task := GenerateFlashTask("test-ns", nil)
	if !declaresEmptyDefault(task.Spec.Params, "workspace-lease-name") {
		t.Error("flash task must declare workspace-lease-name with an empty default")
	}
	for _, env := range task.Spec.Steps[0].Env {
		if env.Name == "WORKSPACE_LEASE" {
			if env.Value != "$(params.workspace-lease-name)" {
				t.Errorf("WORKSPACE_LEASE = %q", env.Value)
			}
			return
		}
	}
	t.Error("flash step has no WORKSPACE_LEASE")
}

func declaresEmptyDefault(params []tektonv1.ParamSpec, name string) bool {
	for _, param := range params {
		if param.Name == name {
			return param.Default != nil && param.Default.StringVal == ""
		}
	}
	return false
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
