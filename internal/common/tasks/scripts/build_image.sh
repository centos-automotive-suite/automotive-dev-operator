# shellcheck shell=bash
# NOTE: common.sh is prepended to this script at embed time.

set -o pipefail

WORKSPACE_PATH="$(workspaces.shared-workspace.path)"
MANIFEST_CONFIG_PATH="$(workspaces.manifest-config-workspace.path)"
BUILD_START_TIME=$(date +%s)

: "${BUILD_MODE:=bootc}"
: "${COMPRESSION:=gzip}"
: "${BUILD_DISK_IMAGE:=false}"
: "${REBUILD_BUILDER:=false}"
: "${USE_PERSISTENT_CACHE:=false}"
: "${REPRODUCIBLE:=false}"
: "${INSECURE_REGISTRY:=false}"
: "${BUILDER_IMAGE:=}"
: "${CLUSTER_REGISTRY_ROUTE:=}"
: "${CONTAINER_PUSH:=}"
: "${CONTAINER_REF:=}"
: "${RESTORE_SOURCES_REF:=}"
: "${EXPORT_FORMAT:=}"

BUILD_DIR=""
LOCAL_BUILDER_IMAGE=""
CONTAINER_PUSH_PID=""
AIB_METADATA_PID=""
AIB_METADATA_FINISHED=false
RESTORE_TMPDIR=""
CONTAINER_OCI_DIR=""
AIB_COMMAND=""
AIB_VERSION=""
AIB_IMAGE_PINNED=""
FINAL_NAME=""

cleanup() {
  local status=$?

  if [ "$status" -ne 0 ] && [ -n "$CONTAINER_PUSH_PID" ] && kill -0 "$CONTAINER_PUSH_PID" 2>/dev/null; then
    kill "$CONTAINER_PUSH_PID" 2>/dev/null || true
    wait "$CONTAINER_PUSH_PID" 2>/dev/null || true
  fi
  if [ -n "$AIB_METADATA_PID" ] && kill -0 "$AIB_METADATA_PID" 2>/dev/null; then
    kill "$AIB_METADATA_PID" 2>/dev/null || true
    wait "$AIB_METADATA_PID" 2>/dev/null || true
  fi
  [ -z "$RESTORE_TMPDIR" ] || rm -rf "$RESTORE_TMPDIR"
  [ -z "$CONTAINER_OCI_DIR" ] || rm -rf "$CONTAINER_OCI_DIR"

  return "$status"
}
trap cleanup EXIT

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

validate_boolean() {
  local name="$1" value="$2"
  case "$value" in
    true|false) ;;
    *) fail "$name must be true or false, got '$value'" ;;
  esac
}

validate_config() {
  [ -n "$DISTRO" ] || fail "distro is required"
  [ -n "$TARGET" ] || fail "target is required"
  [ -n "$TARGET_ARCH" ] || fail "target architecture is required"
  [ -n "$AIB_IMAGE_REF" ] || fail "automotive-image-builder is required"

  case "$BUILD_MODE" in
    bootc|image|package|disk) ;;
    *) fail "unknown build mode '$BUILD_MODE'; expected bootc, image, package, or disk" ;;
  esac
  case "$COMPRESSION" in
    gzip|lz4|xz) ;;
    *) fail "unknown compression '$COMPRESSION'; expected gzip, lz4, or xz" ;;
  esac

  validate_boolean "build-disk-image" "$BUILD_DISK_IMAGE"
  validate_boolean "rebuild-builder" "$REBUILD_BUILDER"
  validate_boolean "use-persistent-cache" "$USE_PERSISTENT_CACHE"
  validate_boolean "reproducible" "$REPRODUCIBLE"
  validate_boolean "insecure-registry" "$INSECURE_REGISTRY"

  validate_container_ref "$AIB_IMAGE_REF"
  [ -z "$BUILDER_IMAGE" ] || validate_container_ref "$BUILDER_IMAGE"
  [ -z "$CONTAINER_PUSH" ] || validate_container_ref "$CONTAINER_PUSH"

  if [ "$BUILD_MODE" = "disk" ]; then
    [ -n "$CONTAINER_REF" ] || fail "container-ref is required for disk mode"
    validate_container_ref "$CONTAINER_REF"
  fi
}

validate_config

NEEDS_DISK=false
case "$BUILD_MODE" in
  image|package|disk) NEEDS_DISK=true ;;
  bootc) [ "$BUILD_DISK_IMAGE" = "true" ] && NEEDS_DISK=true ;;
esac

NEEDS_PUSH=false
if [ "$BUILD_MODE" = "bootc" ] && [ -n "$CONTAINER_PUSH" ]; then
  NEEDS_PUSH=true
fi

PREPARES_BUILDER=false
PULLS_BUILDER=false
if [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; then
  if [ -z "$BUILDER_IMAGE" ] && [ -n "$CLUSTER_REGISTRY_ROUTE" ]; then
    PREPARES_BUILDER=true
    PULLS_BUILDER=true
  elif [ -n "$BUILDER_IMAGE" ]; then
    PULLS_BUILDER=true
  fi
fi

SPLIT_BUILD=false
if [ "$NEEDS_PUSH" = "true" ] && [ "$NEEDS_DISK" = "true" ]; then
  SPLIT_BUILD=true
fi

if [ "$NEEDS_PUSH" = "true" ] && [ -z "$BUILDER_IMAGE" ] && [ "$PREPARES_BUILDER" = "false" ]; then
  fail "container push requires builder-image or cluster-registry-route"
fi

ARCH="$TARGET_ARCH"
case "$ARCH" in
  arm64) ARCH="aarch64" ;;
  amd64) ARCH="x86_64" ;;
esac

SAFE_DISTRO="${DISTRO//[^[:alnum:]_.-]/_}"
SAFE_TARGET="${TARGET//[^[:alnum:]_.-]/_}"
CLEAN_NAME="${SAFE_DISTRO}-${SAFE_TARGET}"

declare -a FORMAT_ARGS=()
case "$EXPORT_FORMAT" in
  "") FILE_EXTENSION=".raw" ;;
  image)
    FILE_EXTENSION=".raw"
    FORMAT_ARGS=(--format raw)
    ;;
  *)
    SAFE_FORMAT="${EXPORT_FORMAT//[^[:alnum:]_.-]/_}"
    FILE_EXTENSION=".${SAFE_FORMAT}"
    FORMAT_ARGS=(--format "$EXPORT_FORMAT")
    ;;
esac
EXPORT_FILE="${CLEAN_NAME}${FILE_EXTENSION}"

detect_stat_command
umask 0077

setup_container_config
setup_var_tmp
setup_cluster_auth

for result in IMAGE_URL IMAGE_DIGEST ARTIFACT_INTEGRITY_DIGEST artifact-filename builder-image aib-version automotive-image-builder aib-command build-timing; do
  write_result "$result" ""
done

rm -rf "$WORKSPACE_PATH/.chains"

read_registry_creds "/workspace/registry-auth"
setup_registry_auth || echo "No custom registry auth found, using cluster auth only"
[ -n "$REGISTRY_AUTH_FILE" ] && export BUILDAH_REGISTRY_AUTH_FILE="$REGISTRY_AUTH_FILE"

MANIFEST_FILE=$(cat /tekton/results/manifest-file-path)
[ -n "$MANIFEST_FILE" ] || fail "no manifest file path provided"
[ -f "$MANIFEST_FILE" ] || fail "manifest file not found at $MANIFEST_FILE"
echo "Using manifest file: $MANIFEST_FILE"

prepare_build_directory() {
  if [ "$USE_PERSISTENT_CACHE" = "true" ]; then
    BUILD_DIR="$WORKSPACE_PATH/build-cache"

    chmod g-s "$WORKSPACE_PATH" 2>/dev/null || true
    mkdir -p "$BUILD_DIR"
    echo "Using persistent build cache at $BUILD_DIR"

    find "$BUILD_DIR" -type d -perm /2000 -exec chmod g-s {} + 2>/dev/null || true
    chown -R :0 "$BUILD_DIR" 2>/dev/null || true

    echo "Cleaning stale artifacts from persistent workspace"
    find "$WORKSPACE_PATH" -mindepth 1 -maxdepth 1 \
      ! -name build-cache \
      ! -name scratch-build \
      ! -name scratch-output \
      ! -name scratch-run \
      -exec rm -rf -- {} +

    find "$BUILD_DIR" -maxdepth 1 -name 'image_output--*' -exec rm -rf -- {} +
  else
    BUILD_DIR="/_build"
    chmod g-s "$BUILD_DIR" 2>/dev/null || true
  fi
}

restore_sources_if_requested() {
  [ -n "$RESTORE_SOURCES_REF" ] || return 0

  echo "Restoring sources from $RESTORE_SOURCES_REF"
  install_oras || fail "failed to install oras"

  local -a auth_flags=()
  if [ -n "$REGISTRY_AUTH_FILE" ] && [ -f "$REGISTRY_AUTH_FILE" ]; then
    auth_flags=(--registry-config "$REGISTRY_AUTH_FILE")
  fi

  local sources_digest sources_repo sources_archive
  sources_digest=$(oras discover "${auth_flags[@]}" "$RESTORE_SOURCES_REF" \
    --artifact-type "$OCI_REFERRER_TYPE_BUILD_SOURCES" --format json \
    | grep -o 'sha256:[a-f0-9]\{64\}' | sed -n '1p' || true)
  [ -n "$sources_digest" ] || fail "no sources referrer found for $RESTORE_SOURCES_REF"

  sources_repo="${RESTORE_SOURCES_REF%%@*}"
  RESTORE_TMPDIR=$(mktemp -d)
  oras pull "${auth_flags[@]}" "${sources_repo}@${sources_digest}" -o "$RESTORE_TMPDIR"
  sources_archive=$(find "$RESTORE_TMPDIR" -name '*.tar.gz' -print -quit)
  [ -n "$sources_archive" ] || fail "no archive found after pulling sources referrer"

  mkdir -p "$BUILD_DIR/osbuild_store"
  tar --no-same-owner --no-same-permissions -xzf "$sources_archive" -C "$BUILD_DIR/osbuild_store"
  rm -rf "$RESTORE_TMPDIR"
  RESTORE_TMPDIR=""
  echo "Sources restored: $(find "$BUILD_DIR/osbuild_store/sources" -type f | wc -l) blobs"
}

prepare_build_directory
restore_sources_if_requested
install_custom_ca_certs
setup_osbuild

cd "$WORKSPACE_PATH" || exit 1

load_args_from_file() {
  local file="$1"
  local description="$2"
  local validator="$3"
  local -n result_array=$4

  [ -f "$file" ] || return 1

  echo "Loading $description from $file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [ -z "$validator" ] || "$validator" "$line" "$description"
    result_array+=("$line")
  done < "$file"
  echo "Loaded ${#result_array[@]} items for $description"
}

load_custom_definitions "$MANIFEST_CONFIG_PATH/custom-definitions.env"

declare -a AIB_EXTRA_ARGS=()
if ! load_args_from_file "$MANIFEST_CONFIG_PATH/aib-extra-args.txt" "AIB extra args" "" AIB_EXTRA_ARGS; then
  echo "No AIB extra args file found"
fi

declare -a ROOT_PASSWORD_ARGS=()
ROOT_PASSWORD_FILE="$MANIFEST_CONFIG_PATH/root-password.txt"
if [ -s "$ROOT_PASSWORD_FILE" ]; then
  ROOT_PASSWORD_ARGS=(--root-password "file:${ROOT_PASSWORD_FILE}")
  echo "Root password override configured"
fi

declare -a SKOPEO_COPY_TLS_ARGS=()
declare -a SKOPEO_INSPECT_TLS_ARGS=()
if [ "$INSECURE_REGISTRY" = "true" ]; then
  SKOPEO_COPY_TLS_ARGS=(--src-tls-verify=false --dest-tls-verify=false)
  SKOPEO_INSPECT_TLS_ARGS=(--tls-verify=false)
fi

copy_from_registry() {
  local ref="$1" destination="$2"

  if skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" "docker://$ref" "$destination" 2>/dev/null; then
    return 0
  fi

  [ -f "$REGISTRY_AUTH_FILE" ] || return 1
  skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" --authfile="$REGISTRY_AUTH_FILE" \
    "docker://$ref" "$destination"
}

copy_cluster_image() {
  local ref="$1" destination="$2"
  local registry_host="${ref%%/*}"
  local auth_file
  auth_file=$(mktemp /tmp/cluster-registry-auth.XXXXXX)
  create_service_account_auth "$registry_host" "$auth_file"
  if ! skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" --authfile="$auth_file" \
    "docker://$ref" "$destination"; then
    rm -f "$auth_file"
    return 1
  fi
  rm -f "$auth_file"
}

pull_registry_image() {
  local ref="$1" destination="$2"
  local registry_host="${ref%%/*}"
  local route_host="${CLUSTER_REGISTRY_ROUTE%%/*}"

  if [ "$registry_host" = "$INTERNAL_REGISTRY" ] || { [ -n "$route_host" ] && [ "$registry_host" = "$route_host" ]; }; then
    copy_cluster_image "$ref" "$destination"
  else
    copy_from_registry "$ref" "$destination"
  fi
}

copy_to_registry() {
  local source="$1" destination="$2" digest_file="${3:-}"
  local -a args=("${SKOPEO_COPY_TLS_ARGS[@]}")
  local registry_host="${destination%%/*}"
  local route_host="${CLUSTER_REGISTRY_ROUTE%%/*}"
  local auth_file=""

  [ -z "$digest_file" ] || args+=(--digestfile "$digest_file")
  if [ "$registry_host" = "$INTERNAL_REGISTRY" ] || { [ -n "$route_host" ] && [ "$registry_host" = "$route_host" ]; }; then
    auth_file=$(mktemp /tmp/registry-push-auth.XXXXXX)
    create_service_account_auth "$registry_host" "$auth_file"
  elif [ -f "$REGISTRY_AUTH_FILE" ]; then
    auth_file="$REGISTRY_AUTH_FILE"
  fi
  [ -z "$auth_file" ] || args+=(--authfile="$auth_file")

  if ! skopeo copy "${args[@]}" "$source" "docker://$destination"; then
    if [ -n "$auth_file" ] && [ "$auth_file" != "$REGISTRY_AUTH_FILE" ]; then
      rm -f "$auth_file"
    fi
    return 1
  fi
  if [ -n "$auth_file" ] && [ "$auth_file" != "$REGISTRY_AUTH_FILE" ]; then
    rm -f "$auth_file"
  fi
}

# SYNC: keep in sync with internal/buildapi/progress.go (estimateBuildSteps).
PROGRESS_TOTAL=3
STEP_BUILD=2
STEP_FINALIZE=3
if [ "$PREPARES_BUILDER" = "true" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_BUILD=$((STEP_BUILD + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi
if [ "$PULLS_BUILDER" = "true" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_BUILD=$((STEP_BUILD + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi
if [ "$NEEDS_PUSH" = "true" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi
if [ "$NEEDS_DISK" = "true" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi

emit_progress "Preparing build" 1 "$PROGRESS_TOTAL"

BOOTC_CONTAINER_NAME="${CONTAINER_PUSH:-localhost/aib-build:${DISTRO}-${TARGET}}"
AIB_HASH=$(printf '%s' "$AIB_IMAGE_REF" | sha256sum | cut -c1-8)
LOCAL_BUILDER_IMAGE="localhost/aib-build:${DISTRO}-${TARGET_ARCH}-${AIB_HASH}"

declare -a BUILD_CONTAINER_ARGS=()

prepare_builder_if_needed() {
  if [ "$PREPARES_BUILDER" = "true" ]; then
    local target_builder_image route_host auth_file builder_cached=false
    target_builder_image="${CLUSTER_REGISTRY_ROUTE}/${NAMESPACE}/aib-build:${DISTRO}-${TARGET_ARCH}-${AIB_HASH}"
    route_host="${CLUSTER_REGISTRY_ROUTE%%/*}"
    auth_file=$(mktemp /tmp/builder-registry-auth.XXXXXX)
    create_service_account_auth "$route_host" "$auth_file"

    emit_progress "Preparing builder" 2 "$PROGRESS_TOTAL"
    if [ "$REBUILD_BUILDER" = "true" ]; then
      echo "Rebuild requested, skipping builder cache check"
    elif skopeo inspect "${SKOPEO_INSPECT_TLS_ARGS[@]}" --authfile="$auth_file" \
      "docker://$target_builder_image" >/dev/null 2>&1; then
      echo "Builder image found in cluster registry: $target_builder_image"
      builder_cached=true
    fi

    if [ "$builder_cached" = "false" ]; then
      echo "Building builder image $LOCAL_BUILDER_IMAGE"
      aib --verbose build-builder --build-dir "$BUILD_DIR" --cache "$BUILD_DIR/dnf-cache" \
        --distro "$DISTRO" "${CUSTOM_DEFS_ARGS[@]}" "$LOCAL_BUILDER_IMAGE"
      copy_to_registry "containers-storage:$LOCAL_BUILDER_IMAGE" "$target_builder_image"
    fi

    rm -f "$auth_file"
    BUILDER_IMAGE="$target_builder_image"
  fi

  write_result builder-image "$BUILDER_IMAGE"

  if [ "$PULLS_BUILDER" = "true" ]; then
    emit_progress "Pulling builder image" $((STEP_BUILD - 1)) "$PROGRESS_TOTAL"
    echo "Pulling builder image: $BUILDER_IMAGE"
    pull_registry_image "$BUILDER_IMAGE" "containers-storage:$LOCAL_BUILDER_IMAGE"
    BUILD_CONTAINER_ARGS=(--build-container "$LOCAL_BUILDER_IMAGE")
  fi
}

prepare_builder_if_needed

configure_compressor() {
  case "$COMPRESSION" in
    gzip)
      if command -v pigz >/dev/null 2>&1; then
        GZIP_COMPRESSOR="pigz"
      elif command -v gzip >/dev/null 2>&1; then
        GZIP_COMPRESSOR="gzip"
      else
        fail "gzip compression requested but neither pigz nor gzip is installed in $AIB_IMAGE_REF"
      fi
      EXT_FILE=".gz"
      EXT_DIR=".tar.gz"
      ;;
    lz4)
      command -v lz4 >/dev/null 2>&1 || fail "lz4 compression requested but lz4 is not installed in $AIB_IMAGE_REF"
      EXT_FILE=".lz4"
      EXT_DIR=".tar.lz4"
      ;;
    xz)
      command -v xz >/dev/null 2>&1 || fail "xz compression requested but xz is not installed in $AIB_IMAGE_REF"
      EXT_FILE=".xz"
      EXT_DIR=".tar.xz"
      ;;
  esac
}

if [ "$NEEDS_DISK" = "true" ]; then
  configure_compressor
fi

start_aib_metadata_capture() {
  rm -f /tmp/aib-version.txt /tmp/aib-pinned.txt
  (
    aib --version 2>&1 | head -1 | tr -d '\r\n' | sed 's/^aib //' > /tmp/aib-version.txt 2>/dev/null || true

    local -a inspect_args=("${SKOPEO_INSPECT_TLS_ARGS[@]}")
    [ ! -f "$REGISTRY_AUTH_FILE" ] || inspect_args+=(--authfile="$REGISTRY_AUTH_FILE")
    local digest
    digest=$(skopeo inspect "${inspect_args[@]}" --format '{{.Digest}}' "docker://${AIB_IMAGE_REF}" 2>/dev/null || true)
    if [ -n "$digest" ]; then
      case "$AIB_IMAGE_REF" in
        *@*) printf '%s' "$AIB_IMAGE_REF" > /tmp/aib-pinned.txt ;;
        *)
          local base
          base=$(printf '%s' "$AIB_IMAGE_REF" | sed 's/:[^/]*$//')
          printf '%s@%s' "$base" "$digest" > /tmp/aib-pinned.txt
          ;;
      esac
    else
      printf '%s' "$AIB_IMAGE_REF" > /tmp/aib-pinned.txt
    fi
  ) &
  AIB_METADATA_PID=$!
}

finish_aib_metadata_capture() {
  [ "$AIB_METADATA_FINISHED" = "false" ] || return 0

  wait "$AIB_METADATA_PID" 2>/dev/null || true
  AIB_METADATA_PID=""
  AIB_VERSION=$(cat /tmp/aib-version.txt 2>/dev/null || true)
  AIB_IMAGE_PINNED=$(cat /tmp/aib-pinned.txt 2>/dev/null || printf '%s' "$AIB_IMAGE_REF")
  write_result aib-version "$AIB_VERSION"
  write_result automotive-image-builder "$AIB_IMAGE_PINNED"
  AIB_METADATA_FINISHED=true
  echo "AIB image reference: $AIB_IMAGE_PINNED"
}

start_aib_metadata_capture

declare -a COMMON_BUILD_ARGS=(
  --build-dir="$BUILD_DIR"
  --cache="$BUILD_DIR/dnf-cache"
  --osbuild-manifest="$BUILD_DIR/image.json"
)
if [ "$USE_PERSISTENT_CACHE" = "true" ]; then
  COMMON_BUILD_ARGS+=(--define "reproducible_image=true" --cache-max-size=unlimited)
elif [ "$REPRODUCIBLE" = "true" ]; then
  COMMON_BUILD_ARGS+=(--define "reproducible_image=true")
fi

run_aib_command() {
  local description="$1"
  shift
  local -a command=("$@")

  AIB_COMMAND=$(printf '%q ' "${command[@]}")
  AIB_COMMAND="${AIB_COMMAND% }"
  write_result aib-command "$AIB_COMMAND"
  echo "$description"
  emit_progress "Building image" "$STEP_BUILD" "$PROGRESS_TOTAL"
  "${command[@]}"
}

annotate_oci_image() {
  local oci_dir="$1"
  python3 - "$oci_dir" "$BUILDER_IMAGE" "$AIB_VERSION" "$AIB_IMAGE_PINNED" "$AIB_COMMAND" \
    "$OCI_ANN_BUILDER_IMAGE" "$OCI_ANN_AIB_VERSION" "$OCI_ANN_AUTOMOTIVE_IMAGE_BUILDER" "$OCI_ANN_AIB_COMMAND" <<'PYEOF'
import hashlib
import json
import sys
from pathlib import Path


def update_blob(oci_dir, old_digest, data):
    content = json.dumps(data, indent=2).encode()
    new_digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    blob_path = Path(oci_dir) / "blobs" / "sha256"
    old_path = blob_path / old_digest.split(":", 1)[1]
    new_path = blob_path / new_digest.split(":", 1)[1]
    new_path.write_bytes(content)
    if old_path != new_path:
        old_path.unlink()
    return new_digest, len(content)


oci_dir, builder_image, aib_version, aib_image, aib_command = sys.argv[1:6]
key_builder, key_aib_version, key_aib_image, key_aib_command = sys.argv[6:10]

index_path = Path(oci_dir) / "index.json"
index = json.loads(index_path.read_text())
manifest_entry = index["manifests"][0]
manifest_path = Path(oci_dir) / "blobs" / manifest_entry["digest"].replace(":", "/")
manifest = json.loads(manifest_path.read_text())
config_path = Path(oci_dir) / "blobs" / manifest["config"]["digest"].replace(":", "/")
config = json.loads(config_path.read_text())

labels = config.setdefault("config", {}).setdefault("Labels", {})
labels[key_builder] = builder_image
if aib_version:
    labels[key_aib_version] = aib_version
if aib_image:
    labels[key_aib_image] = aib_image
if aib_command:
    labels[key_aib_command] = aib_command
manifest["config"]["digest"], manifest["config"]["size"] = update_blob(
    oci_dir, manifest["config"]["digest"], config
)

annotations = manifest.setdefault("annotations", {})
annotations[key_builder] = builder_image
if aib_version:
    annotations[key_aib_version] = aib_version
if aib_image:
    annotations[key_aib_image] = aib_image
if aib_command:
    annotations[key_aib_command] = aib_command
manifest_entry["digest"], manifest_entry["size"] = update_blob(
    oci_dir, manifest_entry["digest"], manifest
)
index_path.write_text(json.dumps(index, indent=2))
PYEOF
}

start_container_push() {
  [ "$NEEDS_PUSH" = "true" ] || return 0
  [ -n "$BUILDER_IMAGE" ] || fail "builder image is required to annotate the bootc container"

  finish_aib_metadata_capture
  emit_progress "Pushing container" $((STEP_BUILD + 1)) "$PROGRESS_TOTAL"
  rm -f /tmp/container-push-digest.txt
  CONTAINER_OCI_DIR=$(mktemp -d /tmp/bootc-oci.XXXXXX)
  local oci_dir="$CONTAINER_OCI_DIR"

  (
    local push_start copy_done annotate_done push_done
    push_start=$(date +%s)
    skopeo copy "containers-storage:$BOOTC_CONTAINER_NAME" "oci:${oci_dir}:latest"
    copy_done=$(date +%s)
    log_elapsed "Container copy to OCI" "$push_start" "$copy_done"

    annotate_oci_image "$oci_dir"
    annotate_done=$(date +%s)
    log_elapsed "Container annotation" "$copy_done" "$annotate_done"

    copy_to_registry "oci:${oci_dir}:latest" "$CONTAINER_PUSH" /tmp/container-push-digest.txt
    push_done=$(date +%s)
    log_elapsed "Container registry push" "$annotate_done" "$push_done"
    log_elapsed "Container push total" "$push_start" "$push_done"
    rm -rf "$oci_dir"
  ) &
  CONTAINER_PUSH_PID=$!
}

run_bootc() {
  local -a disk_output_args=()
  if [ "$NEEDS_DISK" = "true" ] && [ "$SPLIT_BUILD" = "false" ]; then
    disk_output_args=("/output/${EXPORT_FILE}")
  fi

  local -a command=(
    aib --verbose build
    --distro "$DISTRO"
    --target "$TARGET"
    --arch="$ARCH"
    "${COMMON_BUILD_ARGS[@]}"
  )
  if [ "$SPLIT_BUILD" = "false" ]; then
    command+=("${FORMAT_ARGS[@]}")
  fi
  command+=(
    "${BUILD_CONTAINER_ARGS[@]}"
    "${CUSTOM_DEFS_ARGS[@]}"
    "${AIB_EXTRA_ARGS[@]}"
    "${ROOT_PASSWORD_ARGS[@]}"
    "$MANIFEST_FILE"
    "$BOOTC_CONTAINER_NAME"
    "${disk_output_args[@]}"
  )

  run_aib_command "Running bootc build" "${command[@]}"
  start_container_push

  if [ "$SPLIT_BUILD" = "true" ]; then
    local disk_start
    disk_start=$(date +%s)
    aib --verbose to-disk-image \
      "${FORMAT_ARGS[@]}" \
      "${BUILD_CONTAINER_ARGS[@]}" \
      "${AIB_EXTRA_ARGS[@]}" \
      "$BOOTC_CONTAINER_NAME" \
      "/output/${EXPORT_FILE}"
    log_elapsed "Disk creation" "$disk_start"
  fi
}

run_traditional() {
  local -a command=(
    aib-dev --verbose build
    "${CUSTOM_DEFS_ARGS[@]}"
    --distro "$DISTRO"
    --target "$TARGET"
    --arch="$ARCH"
    "${FORMAT_ARGS[@]}"
    "${COMMON_BUILD_ARGS[@]}"
    "${AIB_EXTRA_ARGS[@]}"
    "${ROOT_PASSWORD_ARGS[@]}"
    "$MANIFEST_FILE"
    "/output/${EXPORT_FILE}"
  )
  run_aib_command "Running $BUILD_MODE build" "${command[@]}"
}

run_disk() {
  echo "Pulling source container: $CONTAINER_REF"
  pull_registry_image "$CONTAINER_REF" "containers-storage:$CONTAINER_REF"

  local -a command=(
    aib --verbose to-disk-image
    "${FORMAT_ARGS[@]}"
    "${BUILD_CONTAINER_ARGS[@]}"
    "${AIB_EXTRA_ARGS[@]}"
    "$CONTAINER_REF"
    "/output/${EXPORT_FILE}"
  )
  run_aib_command "Running disk build" "${command[@]}"
}

AIB_INVOKE_TIME=$(date +%s)
log_elapsed "Setup phase" "$BUILD_START_TIME" "$AIB_INVOKE_TIME"

case "$BUILD_MODE" in
  bootc) run_bootc ;;
  image|package) run_traditional ;;
  disk) run_disk ;;
esac

AIB_END_TIME=$(date +%s)
log_elapsed "AIB build phase" "$AIB_INVOKE_TIME" "$AIB_END_TIME"
finish_aib_metadata_capture

compress_stream() {
  case "$COMPRESSION" in
    gzip) "$GZIP_COMPRESSOR" -c ;;
    lz4) lz4 -z -f -q ;;
    xz) xz -T0 -c ;;
  esac
}

compress_file_atomic() {
  local source="$1" destination="$2"
  local temporary="${destination}.tmp.$$"
  rm -f "$temporary"

  if ! compress_stream < "$source" > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  mv "$temporary" "$destination"
}

tar_path_atomic() {
  local root="$1" relative_path="$2" destination="$3"
  local temporary="${destination}.tmp.$$"
  rm -f "$temporary"

  if ! tar -C "$root" -cf - "$relative_path" | compress_stream > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  mv "$temporary" "$destination"
}

finalize_directory_artifact() {
  local source="$1"
  local final_compressed_name="${EXPORT_FILE}${EXT_DIR}"
  local parts_dir="$WORKSPACE_PATH/${final_compressed_name}-parts"
  local parts_count=0 item base uncompressed_size
  local -a items=()

  rm -rf "$parts_dir"
  mkdir -p "$parts_dir"

  shopt -s nullglob dotglob
  items=("$source"/*)
  shopt -u nullglob dotglob

  for item in "${items[@]}"; do
    base=$(basename "$item")
    if [ -f "$item" ]; then
      uncompressed_size=$($GET_SIZE_CMD "$item" 2>/dev/null || true)
      compress_file_atomic "$item" "$parts_dir/${base}${EXT_FILE}" \
        || fail "failed to compress $item"
      if [ -n "$uncompressed_size" ]; then
        printf '%s\n' "$uncompressed_size" > "$parts_dir/${base}${EXT_FILE}.size"
      fi
      parts_count=$((parts_count + 1))
    elif [ -d "$item" ]; then
      tar_path_atomic /output "${EXPORT_FILE}/${base}" "$parts_dir/${base}${EXT_DIR}" \
        || fail "failed to archive $item"
      parts_count=$((parts_count + 1))
    fi
  done

  if [ "$parts_count" -gt 0 ]; then
    FINAL_NAME="$final_compressed_name"
  else
    rm -rf "$parts_dir"
    tar_path_atomic /output "$EXPORT_FILE" "$WORKSPACE_PATH/$final_compressed_name" \
      || fail "failed to archive $source"
    ln -sfn "$final_compressed_name" "$WORKSPACE_PATH/disk.img"
    FINAL_NAME="$final_compressed_name"
  fi

  rm -rf "$source"
}

finalize_artifact() {
  FINAL_NAME=""

  if [ "$NEEDS_DISK" = "true" ]; then
    local source="/output/${EXPORT_FILE}"
    [ -e "$source" ] || fail "expected disk artifact was not created at $source"
    emit_progress "Compressing artifacts" $((STEP_FINALIZE - 1)) "$PROGRESS_TOTAL"

    if [ -d "$source" ]; then
      finalize_directory_artifact "$source"
    else
      compress_file_atomic "$source" "$WORKSPACE_PATH/${EXPORT_FILE}${EXT_FILE}" \
        || fail "failed to compress $source"
      rm -f "$source"
      ln -sfn "${EXPORT_FILE}${EXT_FILE}" "$WORKSPACE_PATH/disk.img"
      FINAL_NAME="${EXPORT_FILE}${EXT_FILE}"
    fi
  elif [ "$NEEDS_PUSH" = "true" ]; then
    FINAL_NAME="container:$CONTAINER_PUSH"
  else
    echo "Build completed without a requested export"
  fi

  write_result artifact-filename "$FINAL_NAME"
  cp "$BUILD_DIR/image.json" "$WORKSPACE_PATH/image.json" || echo "Failed to copy image.json"
}

finalize_artifact

record_artifact_integrity() {
  [ -n "$FINAL_NAME" ] || return 0
  [ "$FINAL_NAME" != "container:$CONTAINER_PUSH" ] || return 0

  local parts_dir="$WORKSPACE_PATH/${FINAL_NAME}-parts"
  if [ -d "$parts_dir" ]; then
    case "$TARGET" in
      ride4*|ridesx4*)
        local a_file b_file
        for a_file in "$parts_dir"/boot_a.* "$parts_dir"/abl_a.*; do
          [ -f "$a_file" ] || continue
          b_file="${a_file/_a./_b.}"
          if [ ! -f "$b_file" ]; then
            cp "$a_file" "$b_file"
          fi
        done
        ;;
    esac
  fi

  local digest
  digest=$(compute_artifact_digest "$parts_dir" "$WORKSPACE_PATH/$FINAL_NAME")
  if [ -n "$digest" ]; then
    echo "Artifact integrity digest: $digest"
    write_result ARTIFACT_INTEGRITY_DIGEST "$digest"
  fi
}

record_artifact_integrity

wait_for_container_push() {
  [ -n "$CONTAINER_PUSH_PID" ] || return 0
  echo "Waiting for container push"
  wait "$CONTAINER_PUSH_PID" || fail "container push failed"
  CONTAINER_PUSH_PID=""
  rm -rf "$CONTAINER_OCI_DIR"
  CONTAINER_OCI_DIR=""
}

write_container_results() {
  [ "$NEEDS_PUSH" = "true" ] || return 0

  local pushed_digest result_path
  pushed_digest=$(cat /tmp/container-push-digest.txt 2>/dev/null || true)
  [ -n "$pushed_digest" ] || fail "container push completed without a digest"

  write_result IMAGE_URL "$CONTAINER_PUSH"
  write_result IMAGE_DIGEST "$pushed_digest"
  result_path="$WORKSPACE_PATH/.chains/container"
  mkdir -p "$result_path"
  printf '%s' "$CONTAINER_PUSH" > "$result_path/url"
  printf '%s' "$pushed_digest" > "$result_path/digest"
}

wait_for_container_push
write_container_results

package_reproducible_inputs() {
  [ "$REPRODUCIBLE" = "true" ] || return 0

  local sources_dir="$BUILD_DIR/osbuild_store/sources"
  local sources_archive="$WORKSPACE_PATH/build-sources.tar.gz"
  if [ -d "$sources_dir" ]; then
    tar -czf "$sources_archive" -C "$BUILD_DIR/osbuild_store" sources
    echo "Sources archive: $(du -sh "$sources_archive" | cut -f1)"
  else
    echo "WARNING: no osbuild sources found at $sources_dir"
  fi
  cp "$MANIFEST_FILE" "$WORKSPACE_PATH/aib-manifest.yml"
}

package_reproducible_inputs
emit_progress "Finalizing build" "$PROGRESS_TOTAL" "$PROGRESS_TOTAL"

BUILD_END_TIME=$(date +%s)
log_elapsed "Post-build phase" "$AIB_END_TIME" "$BUILD_END_TIME"
log_elapsed "Total build-image step" "$BUILD_START_TIME" "$BUILD_END_TIME"

BUILD_TIMING=$(printf '{"setup_s":%d,"build_s":%d,"post_build_s":%d,"total_s":%d}' \
  "$((AIB_INVOKE_TIME - BUILD_START_TIME))" \
  "$((AIB_END_TIME - AIB_INVOKE_TIME))" \
  "$((BUILD_END_TIME - AIB_END_TIME))" \
  "$((BUILD_END_TIME - BUILD_START_TIME))")
write_result build-timing "$BUILD_TIMING"
