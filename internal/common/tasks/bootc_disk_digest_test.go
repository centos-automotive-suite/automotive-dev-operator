package tasks

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func shellFunctions(t *testing.T, source string, start, end string) string {
	t.Helper()
	from := strings.Index(source, start)
	if from < 0 {
		t.Fatalf("missing shell function %q", start)
	}
	to := strings.Index(source[from:], end)
	if to < 0 {
		t.Fatalf("missing shell function after %q: %q", start, end)
	}
	return source[from : from+to]
}

// Exercise the production orchestration with transports modeled as digest files.
// The import waits for the registry push to start, and the push waits for disk
// conversion, so serializing either operation fails.
func TestBootcContainerPreparation(t *testing.T) {
	functions := shellFunctions(t, buildImageScript, "cleanup() {", "fail() {") +
		shellFunctions(t, buildImageScript, "copy_to_registry() {", "# SYNC:") +
		shellFunctions(t, buildImageScript, "prepare_container_image() {", "run_traditional() {")
	for _, tc := range []struct {
		name, needsPush, needsDisk, fault, want string
		wantErr                                 bool
	}{
		{"combined", "true", "true", "", "DISK sha256:final", false},
		{"container only", "true", "false", "", "SUCCESS", false},
		{"container only allows conversion", "true", "false", "manifest-conversion", "PUSHED sha256:converted", false},
		{"disk only", "false", "true", "", "SUCCESS", false},
		{"local mismatch", "true", "true", "local-mismatch", "disk source digest differs", true},
		{"registry mismatch", "true", "true", "registry-mismatch", "pushed digest differs", true},
		{"combined rejects conversion", "true", "true", "manifest-conversion", "container push failed", true},
		{"missing registry digest", "true", "true", "missing-digest", "container push completed without a digest", true},
		{"container only requires digest", "true", "false", "missing-digest", "container push completed without a digest", true},
		{"failed registry push", "true", "true", "push-failure", "container push failed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := bootcPreparationHarness + functions + `
run_bootc
wait_for_container_push
if [ "$NEEDS_PUSH" = true ]; then echo "PUSHED $(cat "$CONTAINER_PUSH_DIGEST_FILE")"; fi
echo SUCCESS
`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"TEST_DIR="+t.TempDir(), "NEEDS_PUSH="+tc.needsPush,
				"NEEDS_DISK="+tc.needsDisk, "FAULT="+tc.fault)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected result: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Errorf("output missing %q:\n%s", tc.want, out)
			}
			if tc.wantErr && strings.Contains(string(out), "SUCCESS") {
				t.Errorf("build reported success after %s:\n%s", tc.fault, out)
			}
			if tc.fault == "local-mismatch" && strings.Contains(string(out), "DISK ") {
				t.Errorf("disk conversion ran despite a different local digest:\n%s", out)
			}
		})
	}
}

const bootcPreparationHarness = `
set -e
DISTRO=autosd
TARGET=ride4_sa8650p_sx_r3
ARCH=aarch64
MANIFEST_FILE=manifest.aib.yml
BOOTC_CONTAINER_NAME=quay.io/example/os:base
CONTAINER_PUSH="$BOOTC_CONTAINER_NAME"
BUILDER_IMAGE=quay.io/example/builder:latest
EXPORT_FILE=disk.raw
SPLIT_BUILD=false
if [ "$NEEDS_PUSH" = true ] && [ "$NEEDS_DISK" = true ]; then SPLIT_BUILD=true; fi
COMMON_BUILD_ARGS=()
FORMAT_ARGS=()
BUILD_CONTAINER_ARGS=()
CUSTOM_DEFS_ARGS=()
AIB_EXTRA_ARGS=()
LOCKFILE_ARGS=()
ROOT_PASSWORD_ARGS=()
SKOPEO_COPY_TLS_ARGS=()
REGISTRY_AUTH_FILE=/nonexistent
CLUSTER_REGISTRY_ROUTE=
INTERNAL_REGISTRY=image-registry.openshift-image-registry.svc:5000
CONTAINER_PUSH_PID=
CONTAINER_IMAGE_DIGEST=
CONTAINER_OCI_DIR=
AIB_METADATA_PID=
RESTORE_TMPDIR=
CONTAINER_PUSH_DIGEST_FILE="$TEST_DIR/pushed.digest"
STEP_BUILD=2
PROGRESS_TOTAL=4

fail() { echo "ERROR: $*" >&2; exit 1; }
mktemp() { command mktemp -d "$TEST_DIR/oci.XXXXXX"; }
run_aib_command() { echo sha256:original > "$TEST_DIR/local.digest"; }
prefetch_locked_sources() { :; }
finish_aib_metadata_capture() { :; }
emit_progress() { :; }
log_elapsed() { :; }
annotate_oci_image() { echo sha256:final > "$TEST_DIR/oci.digest"; }
oci_image_bytes() { :; }
stop_workspace_sampler() { :; }
wait_for_test_file() {
  local i
  for ((i=0; i<200; i++)); do
    [ ! -f "$1" ] || return 0
    sleep 0.01
  done
  return 1
}
run_aib_followup_command() {
  local digest
  digest=$(cat "$TEST_DIR/local.digest")
  [ "$digest" = sha256:final ] || fail "disk used unannotated container"
  touch "$TEST_DIR/disk.started"
  echo "DISK $digest"
}
skopeo() {
  local operation="$1" preserve=false digest_file= source destination
  shift
  if [ "$operation" = inspect ]; then
    case "${@: -1}" in
      oci:*) cat "$TEST_DIR/oci.digest" ;;
      containers-storage:*) cat "$TEST_DIR/local.digest" ;;
      *) fail "unexpected inspect: $*" ;;
    esac
    return
  fi
  [ "$operation" = copy ] || fail "unexpected skopeo operation: $operation"
  while [[ "$1" == --* ]]; do
    case "$1" in
      --preserve-digests) preserve=true ;;
      --digestfile) digest_file="$2"; shift ;;
      *) fail "unexpected skopeo option: $1" ;;
    esac
    shift
  done
  source="$1"
  destination="$2"
  case "$source" in
    containers-storage:*)
      cp "$TEST_DIR/local.digest" "$TEST_DIR/oci.digest"
      ;;
    oci:*)
      case "$destination" in
        containers-storage:*)
          [ "$preserve" = true ] || fail "local import did not preserve digests"
          wait_for_test_file "$TEST_DIR/push.started" || fail "local import ran before the push started"
          cp "$TEST_DIR/oci.digest" "$TEST_DIR/local.digest"
          if [ "$FAULT" = local-mismatch ]; then echo sha256:wrong > "$TEST_DIR/local.digest"; fi
          ;;
        docker:*)
          [ "$preserve" = "$SPLIT_BUILD" ] || fail "push digest preservation does not match build mode"
          touch "$TEST_DIR/push.started"
          # A push cannot finish until disk conversion starts in a combined build.
          if [ "$SPLIT_BUILD" = true ]; then
            wait_for_test_file "$TEST_DIR/disk.started" || fail "disk conversion waited for the push"
          fi
          case "$FAULT" in
            push-failure) echo "registry refused push" >&2; return 1 ;;
            missing-digest) return 0 ;;
            registry-mismatch) echo sha256:wrong > "$digest_file" ;;
            manifest-conversion)
              if [ "$preserve" = true ]; then
                echo "registry requires manifest conversion" >&2
                return 1
              fi
              echo sha256:converted > "$digest_file"
              ;;
            *) cp "$TEST_DIR/oci.digest" "$digest_file" ;;
          esac
          ;;
        *) fail "unexpected destination: $destination" ;;
      esac
      ;;
    *) fail "unexpected source (registry pull is forbidden): $source" ;;
  esac
}
`
