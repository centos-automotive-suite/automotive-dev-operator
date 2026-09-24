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
					cmd.Env = append(os.Environ(), "AIB_LOCKFILE="+filepath.Join(dir, "aib.lock"))
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("script failed: %v\n%s", err, out)
					}
					calls := 0
					for line := range strings.SplitSeq(string(out), "\n") {
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

func TestLockfileReproducibilityArtifacts(t *testing.T) {
	buildScript, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`rm -f "$AIB_LOCKFILE"`,
		`cp "$MANIFEST_CONFIG_PATH/aib.lock" "$AIB_LOCKFILE"`,
	} {
		if !strings.Contains(string(buildScript), want) {
			t.Fatalf("build script missing %q", want)
		}
	}

	pushScript, err := os.ReadFile("scripts/push_artifact.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`if [ "$SECURE_BUILD" = "true" ] || [ "$REPRODUCIBLE" = "true" ]; then`,
		`"$OCI_REFERRER_TYPE_AIB_LOCKFILE" "AIB lockfile"`,
	} {
		if !strings.Contains(string(pushScript), want) {
			t.Fatalf("push script missing %q", want)
		}
	}

	findManifestScript, err := os.ReadFile("scripts/find_manifest.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(findManifestScript), "|aib.lock|") {
		t.Fatal("manifest discovery does not exclude a lockfile left in the shared workspace")
	}
}

func TestPackageReproducibleInputsPreservesBuildLockfile(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "package_reproducible_inputs() {")
	if !ok {
		t.Fatal("reproducible inputs function missing")
	}
	functionBody, _, ok := strings.Cut(rest, "\npackage_reproducible_inputs")
	if !ok {
		t.Fatal("reproducible inputs function call missing")
	}
	script := "package_reproducible_inputs() {" + functionBody + "\npackage_reproducible_inputs\n"

	for _, tt := range []struct {
		name     string
		lockfile string
	}{
		{name: "current lockfile", lockfile: `{"version":1}`},
		{name: "no current lockfile"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			buildDir := filepath.Join(root, "build")
			workspaceDir := filepath.Join(root, "workspace")
			configDir := filepath.Join(root, "config")
			for _, dir := range []string{filepath.Join(buildDir, "osbuild_store", "sources"), workspaceDir, configDir} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(
				filepath.Join(buildDir, "osbuild_store", "hermeto-rpm-bom.json"),
				[]byte(`{"bomFormat":"CycloneDX"}`),
				0600,
			); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(root, "manifest.aib.yml")
			if err := os.WriteFile(manifestPath, []byte("name: test\n"), 0600); err != nil {
				t.Fatal(err)
			}
			lockfilePath := filepath.Join(workspaceDir, "aib.lock")
			if tt.lockfile != "" {
				if err := os.WriteFile(lockfilePath, []byte(tt.lockfile), 0600); err != nil {
					t.Fatal(err)
				}
			}

			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"REPRODUCIBLE=true",
				"BUILD_DIR="+buildDir,
				"WORKSPACE_PATH="+workspaceDir,
				"MANIFEST_FILE="+manifestPath,
				"MANIFEST_CONFIG_PATH="+configDir,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			archive := filepath.Join(workspaceDir, "build-sources.tar.gz")
			list := exec.Command("tar", "-tzf", archive)
			contents, err := list.CombinedOutput()
			if err != nil {
				t.Fatalf("listing sources archive: %v\n%s", err, contents)
			}
			if !strings.Contains(string(contents), "hermeto-rpm-bom.json") {
				t.Fatalf("Hermeto SBOM missing from sources archive:\n%s", contents)
			}

			got, err := os.ReadFile(lockfilePath)
			if tt.lockfile == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("stale lockfile remains: contents=%q err=%v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.lockfile {
				t.Fatalf("lockfile = %q, want %q", got, tt.lockfile)
			}
		})
	}
}

func TestRequiredLockfilePublication(t *testing.T) {
	data, err := os.ReadFile("scripts/push_artifact.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "attach_referrer() {")
	if !ok {
		t.Fatal("attachment helper missing")
	}
	for _, tc := range []struct {
		name, secure, repro    string
		missing, attachFailure bool
	}{
		{name: "ordinary"},
		{name: "secure", secure: "true"},
		{name: "reproducible", repro: "true"},
		{name: "missing lock", secure: "true", missing: true},
		{name: "attachment fails", secure: "true", attachFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range []string{"aib.lock", "aib-manifest.yml", "build-sources.tar.gz"} {
				if f == "aib.lock" && tc.missing {
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, f), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stub := `set -e
cd() { builtin cd "$WORKSPACE"; }
oras() {
 printf 'ATTACH'; printf ' <%s>' "$@"; printf '\n'
 [ "$ATTACH_FAILURE" != true ]
}
ORAS_BIN=oras
ORAS_EXTRA_ARGS=()
`
			cmd := exec.Command("bash", "-c", stub+"attach_referrer() {"+rest+"\necho PUBLISHED")
			cmd.Dir = dir
			fail := "false"
			if tc.attachFailure {
				fail = "true"
			}
			cmd.Env = append(os.Environ(), "SECURE_BUILD="+tc.secure, "REPRODUCIBLE="+tc.repro, "WORKSPACE="+dir, "ATTACH_FAILURE="+fail, "DISK_DIGEST=sha256:abc", "repo_url=registry.example/output", "OCI_REFERRER_TYPE_AIB_LOCKFILE=lock-type", "OCI_REFERRER_TYPE_AIB_MANIFEST=manifest-type", "OCI_REFERRER_TYPE_BUILD_SOURCES=sources-type")
			output, err := cmd.CombinedOutput()
			wantFailure := tc.missing || tc.attachFailure
			if (err != nil) != wantFailure {
				t.Fatalf("err=%v output=%s", err, output)
			}
			if wantFailure && strings.Contains(string(output), "PUBLISHED") {
				t.Fatalf("continued after failed publication: %s", output)
			}
			if !wantFailure && tc.name != "ordinary" && strings.Count(string(output), "<./aib.lock:lock-type>") != 1 {
				t.Fatalf("lock not published exactly once: %s", output)
			}
		})
	}
}

func TestSecureContainerLockfilePublication(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "write_container_results() {")
	if !ok {
		t.Fatal("container results function missing")
	}
	body, _, ok := strings.Cut(rest, "\nwait_for_container_push\n")
	if !ok {
		t.Fatal("container results boundary missing")
	}
	for _, scenario := range []string{"success", "missing lock", "attach failure"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			lock := filepath.Join(dir, "aib.lock")
			if scenario != "missing lock" {
				if err := os.WriteFile(lock, []byte("recorded"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			script := `set -e
fail() { echo "ERROR: $*"; exit 1; }
cat() { echo sha256:example; }
install_oras() { :; }
oras() { printf 'ATTACH'; printf ' <%s>' "$@"; printf '\n'; [ "$SCENARIO" != 'attach failure' ]; }
write_result() { echo "RESULT $1"; }
` + "write_container_results() {" + body + "\nwrite_container_results"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "SCENARIO="+scenario, "NEEDS_PUSH=true", "SECURE_BUILD=true", "REPRODUCIBLE=false", "AIB_LOCKFILE="+lock, "WORKSPACE_PATH="+dir, "CONTAINER_PUSH=registry.example/image:latest", "REGISTRY_AUTH_FILE=", "OCI_REFERRER_TYPE_AIB_LOCKFILE=lock-type")
			out, err := cmd.CombinedOutput()
			if (err == nil) != (scenario == "success") {
				t.Fatalf("err=%v output=%s", err, out)
			}
			if strings.Contains(string(out), "RESULT IMAGE_DIGEST") != (scenario == "success") {
				t.Fatalf("published results before lock attachment: %s", out)
			}
			if scenario == "success" && !strings.Contains(string(out), "<"+lock+":lock-type>") {
				t.Fatalf("lock attachment missing: %s", out)
			}
		})
	}
}
