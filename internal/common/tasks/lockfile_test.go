package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockfileBuildCommands(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	_, rest, ok := strings.Cut(script, "declare -a LOCKFILE_ARGS=()")
	if !ok {
		t.Fatal("lockfile argument setup missing")
	}
	setup, _, ok := strings.Cut(rest, "declare -a ROOT_PASSWORD_ARGS=()")
	if !ok {
		t.Fatal("root password setup missing")
	}
	_, rest, ok = strings.Cut(script, "run_bootc() {")
	if !ok {
		t.Fatal("bootc function missing")
	}
	functions, _, ok := strings.Cut(rest, "\ncase ")
	if !ok {
		t.Fatal("build dispatch missing")
	}
	for _, locked := range []bool{false, true} {
		name := "unlocked"
		if locked {
			name = "locked"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "config with spaces")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if locked {
				if err := os.WriteFile(filepath.Join(dir, "aib.lock"), []byte(`{"version":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, mode := range []string{"bootc", "traditional", "disk"} {
				t.Run(mode, func(t *testing.T) {
					body := `
set -e
NEEDS_DISK=true
SPLIT_BUILD=true
DISTRO=autosd
TARGET=qemu
ARCH=aarch64
BOOTC_CONTAINER_NAME=test-image
MANIFEST_FILE=manifest.aib.yml
EXPORT_FILE=output.qcow2
CONTAINER_REF=quay.io/test/image
LOCAL_BUILDER_IMAGE=builder
run_aib_command() { shift; "$@"; }
aib() { printf 'CALL'; printf ' <%s>' "$@"; printf '\n'; }
aib-dev() { aib "$@"; }
start_container_push() { :; }
pull_registry_image() { :; }
log_elapsed() { :; }
`
					cmd := exec.Command("bash", "-c", body+"\ndeclare -a LOCKFILE_ARGS=()"+setup+"\nrun_bootc() {"+functions+"\nrun_"+mode)
					cmd.Env = append(os.Environ(), "MANIFEST_CONFIG_PATH="+dir)
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("script failed: %v\n%s", err, out)
					}
					calls := 0
					for _, line := range strings.Split(string(out), "\n") {
						if !strings.HasPrefix(line, "CALL") {
							continue
						}
						calls++
						want := locked && !strings.Contains(line, "<to-disk-image>")
						has := strings.Contains(line, "<--lockfile> <"+filepath.Join(dir, "aib.lock")+">")
						if has != want {
							t.Fatalf("lockfile argument mismatch: %s", line)
						}
					}
					wantCalls := 1
					if mode == "bootc" {
						wantCalls = 2
					}
					if calls != wantCalls {
						t.Fatalf("got %d AIB calls, want %d: %s", calls, wantCalls, out)
					}
				})
			}
		})
	}
}
