# NOTE: common.sh is prepended to this script at embed time.

# Initialize optimizations
WORKSPACE_PATH="$(workspaces.shared-workspace.path)"
BUILD_START_TIME=$(date +%s)
detect_stat_command

# Make the internal registry trusted
# TODO think about whether this is really the right approach
setup_container_config
setup_var_tmp

umask 0077

setup_cluster_auth

# Initialize Tekton Chains type hint results with empty defaults.
# Tekton requires all declared results to exist; these are overwritten
# later if a container push actually happens.
echo -n "" > /tekton/results/IMAGE_URL
echo -n "" > /tekton/results/IMAGE_DIGEST

# Read registry credentials from workspace and set up auth
read_registry_creds "/workspace/registry-auth"
setup_registry_auth || echo "No custom registry auth found, using cluster auth only"

# Use REGISTRY_AUTH_FILE for buildah if available
[ -n "$REGISTRY_AUTH_FILE" ] && export BUILDAH_REGISTRY_AUTH_FILE="$REGISTRY_AUTH_FILE"

MANIFEST_FILE=$(cat /tekton/results/manifest-file-path)
if [ -z "$MANIFEST_FILE" ]; then
    echo "Error: No manifest file path provided"
    exit 1
fi

echo "using manifest file: $MANIFEST_FILE"

if [ ! -f "$MANIFEST_FILE" ]; then
    echo "error: Manifest file not found at $MANIFEST_FILE"
    exit 1
fi

if mountpoint -q "$OSBUILD_PATH"; then
    exit 0
fi

if [ "$(params.use-persistent-cache)" = "true" ]; then
  BUILD_DIR="$WORKSPACE_PATH/build-cache"

  # OpenShift applies setgid + namespace GID on the PVC mount point every time
  # a new pod mounts it. Clear setgid BEFORE creating any directories.
  chmod g-s "$WORKSPACE_PATH" 2>/dev/null || true

  mkdir -p "$BUILD_DIR"
  echo "Using persistent build cache at $BUILD_DIR"

  # OpenShift re-applies setgid + namespace GID on PVC directories each pod
  # mount. Clear setgid so NEW files get root GID (0) going forward.
  find "$BUILD_DIR" -type d -perm /2000 -exec chmod g-s {} + 2>/dev/null || true

  # Kubernetes also changes GIDs on ALL existing files to the namespace
  # supplemental GID at mount time. Reset to root GID so osbuild's cp -a
  # doesn't try to preserve namespace GIDs on FAT (EFI) partitions.
  chown -R :0 "$BUILD_DIR" 2>/dev/null || true

  echo "Cleaning up stale artifacts from persistent workspace..."
  for item in "$WORKSPACE_PATH"/*; do
    [ "$(basename "$item")" = "build-cache" ] && continue
    rm -rf "$item"
  done

  for orphan in "$BUILD_DIR"/image_output--*; do
    [ -e "$orphan" ] || break
    echo "Removing orphaned build output: $(basename "$orphan")"
    rm -rf "$orphan"
  done
else
  BUILD_DIR="/_build"

  # When scratch volumes are PVC-backed (usePVCScratchVolumes), OpenShift applies
  # setgid + namespace GID on the mount. Clear it so osbuild doesn't create files
  # with GIDs that don't exist in the target rootfs.
  chmod g-s "/_build" 2>/dev/null || true
fi

install_custom_ca_certs
setup_osbuild

cd "$WORKSPACE_PATH"

EXPORT_FORMAT="$(params.export-format)"
# If format is empty, AIB defaults to raw
if [ -z "$EXPORT_FORMAT" ] || [ "$EXPORT_FORMAT" = "image" ]; then
  file_extension=".raw"
elif [ "$EXPORT_FORMAT" = "qcow2" ]; then
  file_extension=".qcow2"
else
  file_extension=".$EXPORT_FORMAT"
fi

# Only pass --format to AIB if explicitly specified
# Note: to-disk-image accepts raw/qcow2/simg, not "image"
FORMAT_ARG=""
if [ -n "$EXPORT_FORMAT" ]; then
  AIB_FORMAT="$EXPORT_FORMAT"
  # Translate "image" to "raw" for AIB compatibility
  if [ "$AIB_FORMAT" = "image" ]; then
    AIB_FORMAT="raw"
  fi
  FORMAT_ARG="--format $AIB_FORMAT"
fi

cleanName=$(params.distro)-$(params.target)
exportFile=${cleanName}${file_extension}

BUILD_MODE="$(params.mode)"
if [ -z "$BUILD_MODE" ]; then
  BUILD_MODE="bootc"
fi

# Generic file loader for validated arguments
load_args_from_file() {
  local file="$1"
  local description="$2"
  local validator="$3"
  local -n result_array=$4  # nameref to output array

  if [ ! -f "$file" ]; then
    return 1
  fi

  echo "Loading $description from $file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [ -n "$validator" ] && $validator "$line" "$description"
    result_array+=("$line")
  done < "$file"
  echo "Loaded ${#result_array[@]} items for $description"
  return 0
}

# Load custom definitions
load_custom_definitions "$(workspaces.manifest-config-workspace.path)/custom-definitions.env"

# Load AIB extra arguments
declare -a AIB_EXTRA_ARGS=()
AIB_EXTRA_ARGS_FILE="$(workspaces.manifest-config-workspace.path)/aib-extra-args.txt"

if load_args_from_file "$AIB_EXTRA_ARGS_FILE" "AIB extra args" "" AIB_EXTRA_ARGS; then
  :  # Extra args loaded successfully
else
  echo "No AIB extra args file found"
fi

arch="$(params.target-architecture)"
case "$arch" in
  "arm64")
    arch="aarch64"
    ;;
  "amd64")
    arch="x86_64"
    ;;
esac

CONTAINER_PUSH="$(params.container-push)"
BUILD_DISK_IMAGE="$(params.build-disk-image)"
EXPORT_OCI="$(params.export-oci)"
BUILDER_IMAGE="$(params.builder-image)"
CLUSTER_REGISTRY_ROUTE="$(params.cluster-registry-route)"
CONTAINER_REF="$(params.container-ref)"

echo "=== Build Configuration ==="
echo "BUILD_MODE: $BUILD_MODE"
echo "CONTAINER_PUSH: ${CONTAINER_PUSH:-<empty>}"
echo "BUILD_DISK_IMAGE: $BUILD_DISK_IMAGE"
echo "EXPORT_OCI: ${EXPORT_OCI:-<empty>}"
echo "==========================="

REBUILD_BUILDER="$(params.rebuild-builder)"

# Calculate total progress steps based on build options.
# SYNC: keep in sync with internal/buildapi/progress.go (estimateBuildSteps).
# Base steps: 1=Preparing, 2=Building, 3=Finalizing
PROGRESS_TOTAL=3
STEP_BUILD=2
STEP_FINALIZE=3
# Builder preparation steps (bootc/disk without explicit builder + cluster registry available)
# 2 extra steps: "Preparing builder" (cache check + optional build/push) + "Pulling builder"
if [ -z "$BUILDER_IMAGE" ] && { [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; } && [ -n "$CLUSTER_REGISTRY_ROUTE" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 2))
  STEP_BUILD=$((STEP_BUILD + 2))
  STEP_FINALIZE=$((STEP_FINALIZE + 2))
elif [ -n "$BUILDER_IMAGE" ] && { [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; }; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_BUILD=$((STEP_BUILD + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi
if [ -n "$CONTAINER_PUSH" ] && [ "$BUILD_MODE" = "bootc" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi
# Compression step (for disk image builds)
if [ "$BUILD_DISK_IMAGE" = "true" ] || [ "$BUILD_MODE" = "image" ] || [ "$BUILD_MODE" = "package" ] || [ "$BUILD_MODE" = "disk" ]; then
  PROGRESS_TOTAL=$((PROGRESS_TOTAL + 1))
  STEP_FINALIZE=$((STEP_FINALIZE + 1))
fi

emit_progress "Preparing build" 1 "$PROGRESS_TOTAL"

# Use parameter expansion for cleaner default value assignment
BOOTC_CONTAINER_NAME="${CONTAINER_PUSH:-localhost/aib-build:$(params.distro)-$(params.target)}"

# Calculate AIB hash for consistent naming with build_builder.sh
AIB_HASH=$(echo -n "$(params.automotive-image-builder)" | sha256sum | cut -c1-8)
# Local builder image name (matches what build_builder.sh creates with --out)
LOCAL_BUILDER_IMAGE="localhost/aib-build:$(params.distro)-${TARGET_ARCH}-${AIB_HASH}"

# For bootc/disk builds, if no builder-image is provided but cluster-registry-route is set,
# prepare the builder image inline (previously done by separate prepare-builder task)
if [ -z "$BUILDER_IMAGE" ] && { [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; } && [ -n "$CLUSTER_REGISTRY_ROUTE" ]; then
  TARGET_BUILDER_IMAGE="${CLUSTER_REGISTRY_ROUTE}/${NAMESPACE}/aib-build:$(params.distro)-${TARGET_ARCH}-${AIB_HASH}"

  # Add auth entry for the external registry route hostname.
  # setup_cluster_auth only created an entry for the internal registry;
  # skopeo needs credentials for the route hostname too.
  ROUTE_HOST=$(echo "$CLUSTER_REGISTRY_ROUTE" | cut -d'/' -f1)
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")
  if [ -n "$TOKEN" ] && [ -n "$REGISTRY_AUTH_FILE" ]; then
    ROUTE_AUTH=$(echo -n "serviceaccount:$TOKEN" | base64 -w0)
    python3 -c "
import json, sys
f = sys.argv[1]
with open(f) as fh: d = json.load(fh)
d['auths'][sys.argv[2]] = {'auth': sys.argv[3]}
with open(f, 'w') as fh: json.dump(d, fh)
" "$REGISTRY_AUTH_FILE" "$ROUTE_HOST" "$ROUTE_AUTH"
    echo "Added auth entry for registry route: $ROUTE_HOST"
  fi

  emit_progress "Preparing builder" 2 "$PROGRESS_TOTAL"

  BUILDER_CACHED=false
  if [ "$REBUILD_BUILDER" = "true" ]; then
    echo "Rebuild requested, skipping cache check"
  else
    echo "Checking if $TARGET_BUILDER_IMAGE exists in cluster registry..."
    if skopeo inspect --authfile="$REGISTRY_AUTH_FILE" "docker://$TARGET_BUILDER_IMAGE" >/dev/null 2>&1; then
      echo "Builder image found in cluster registry: $TARGET_BUILDER_IMAGE"
      BUILDER_CACHED=true
    fi
  fi

  if [ "$BUILDER_CACHED" = "false" ]; then
    echo "Builder image not found, building..."
    echo "Running: aib build-builder --distro $(params.distro) --build-dir $BUILD_DIR --cache $BUILD_DIR/dnf-cache ${CUSTOM_DEFS_ARGS[*]} $LOCAL_BUILDER_IMAGE"
    aib --verbose build-builder --build-dir "$BUILD_DIR" --cache "$BUILD_DIR/dnf-cache" --distro "$(params.distro)" "${CUSTOM_DEFS_ARGS[@]}" "$LOCAL_BUILDER_IMAGE"

    echo "Built local image: $LOCAL_BUILDER_IMAGE"
    echo "Pushing to cluster registry: $TARGET_BUILDER_IMAGE"
    skopeo copy --authfile="$REGISTRY_AUTH_FILE" \
      "containers-storage:$LOCAL_BUILDER_IMAGE" \
      "docker://$TARGET_BUILDER_IMAGE"
    echo "Builder image pushed: $TARGET_BUILDER_IMAGE"
  fi

  BUILDER_IMAGE="$TARGET_BUILDER_IMAGE"
  echo "Using builder image: $BUILDER_IMAGE"
fi

# Record the effective builder image used for annotation
echo -n "${BUILDER_IMAGE:-}" > /tekton/results/builder-image

# Start AIB metadata capture in the background (runs in parallel with the build)
AIB_IMAGE_REF="$(params.automotive-image-builder)"
(
  aib --version 2>&1 | head -1 | tr -d '\r\n' | sed 's/^aib //' > /tmp/aib-version.txt 2>/dev/null || true
  AIB_DIGEST=$(skopeo inspect --format '{{.Digest}}' "docker://${AIB_IMAGE_REF}" 2>/dev/null || echo "")
  if [ -n "$AIB_DIGEST" ]; then
    case "$AIB_IMAGE_REF" in
      *@*) echo -n "$AIB_IMAGE_REF" > /tmp/aib-pinned.txt ;;
      *)   AIB_BASE=$(echo "$AIB_IMAGE_REF" | sed 's/:[^/]*$//')
           echo -n "${AIB_BASE}@${AIB_DIGEST}" > /tmp/aib-pinned.txt ;;
    esac
  else
    echo -n "$AIB_IMAGE_REF" > /tmp/aib-pinned.txt
  fi
) &
AIB_METADATA_PID=$!

# Set up builder image if needed (consolidated logic)
declare -a BUILD_CONTAINER_ARGS=()
if [ -n "$BUILDER_IMAGE" ] && { [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; }; then
  emit_progress "Pulling builder image" $((STEP_BUILD - 1)) "$PROGRESS_TOTAL"
  echo "Pulling builder image to local storage: $BUILDER_IMAGE"

  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")
  if [ -n "$TOKEN" ]; then
    REGISTRY_HOST=$(echo "$BUILDER_IMAGE" | cut -d'/' -f1)
    create_service_account_auth "$REGISTRY_HOST" /tmp/builder-auth.json
    skopeo copy --authfile=/tmp/builder-auth.json \
      "docker://$BUILDER_IMAGE" \
      "containers-storage:$LOCAL_BUILDER_IMAGE"
  else
    skopeo copy \
      "docker://$BUILDER_IMAGE" \
      "containers-storage:$LOCAL_BUILDER_IMAGE"
  fi

  echo "Builder image ready in local storage: $LOCAL_BUILDER_IMAGE"
  BUILD_CONTAINER_ARGS=("--build-container" "$LOCAL_BUILDER_IMAGE")
fi

# Parse FORMAT_ARG safely
declare -a FORMAT_ARGS=()
if [ -n "$FORMAT_ARG" ]; then
  # FORMAT_ARG is "--format <value>" or similar
  for word in $FORMAT_ARG; do
    FORMAT_ARGS+=("$word")
  done
fi

# Common build arguments used across all modes
declare -a COMMON_BUILD_ARGS=(
  --build-dir="$BUILD_DIR"
  --cache="$BUILD_DIR/dnf-cache"
  --osbuild-manifest="$BUILD_DIR/image.json"
)

if [ "$(params.use-persistent-cache)" = "true" ]; then
  COMMON_BUILD_ARGS+=(--define "reproducible_image=true")
  COMMON_BUILD_ARGS+=(--cache-max-size=unlimited)
fi

AIB_INVOKE_TIME=$(date +%s)
echo "⏱ Setup phase: $((AIB_INVOKE_TIME - BUILD_START_TIME))s"

case "$BUILD_MODE" in
    bootc)
      # When both container push and disk build are needed, split into two phases
      # so container push can overlap with disk creation:
      #   Phase 1: aib build (container only, no disk)
      #   Phase 2: container push (background) + aib to-disk-image (foreground, parallel)
      # When only one is needed, use the single aib build command.
      SPLIT_BUILD="false"
      if [ -n "$CONTAINER_PUSH" ] && [ "$BUILD_DISK_IMAGE" = "true" ]; then
        SPLIT_BUILD="true"
      fi

      if [ "$SPLIT_BUILD" = "true" ]; then
        # Phase 1: Build container only (no disk output)
        declare -a AIB_CMD=(
          aib --verbose build
          --distro "$(params.distro)"
          --target "$(params.target)"
          "--arch=${arch}"
          "${COMMON_BUILD_ARGS[@]}"
          "${BUILD_CONTAINER_ARGS[@]}"
          "${CUSTOM_DEFS_ARGS[@]}"
          "${AIB_EXTRA_ARGS[@]}"
          "$MANIFEST_FILE"
          "$BOOTC_CONTAINER_NAME"
        )
      else
        declare -a DISK_OUTPUT_ARGS=()
        if [ "$BUILD_DISK_IMAGE" = "true" ]; then
          DISK_OUTPUT_ARGS=("/output/${exportFile}")
        fi

        declare -a AIB_CMD=(
          aib --verbose build
          --distro "$(params.distro)"
          --target "$(params.target)"
          "--arch=${arch}"
          "${COMMON_BUILD_ARGS[@]}"
          "${FORMAT_ARGS[@]}"
          "${BUILD_CONTAINER_ARGS[@]}"
          "${CUSTOM_DEFS_ARGS[@]}"
          "${AIB_EXTRA_ARGS[@]}"
          "$MANIFEST_FILE"
          "$BOOTC_CONTAINER_NAME"
          "${DISK_OUTPUT_ARGS[@]}"
        )
      fi

      AIB_COMMAND=$(printf '%q ' "${AIB_CMD[@]}" | sed 's/ $//')
      echo -n "$AIB_COMMAND" > /tekton/results/aib-command

      echo "Running bootc build"
      emit_progress "Building image" "$STEP_BUILD" "$PROGRESS_TOTAL"
      "${AIB_CMD[@]}"

      CONTAINER_PUSH_PID=""
      if [ -n "$CONTAINER_PUSH" ]; then
        emit_progress "Pushing container" "$((STEP_BUILD + 1))" "$PROGRESS_TOTAL"

        if [ -z "$BUILDER_IMAGE" ]; then
          echo "Error: BUILDER_IMAGE is empty; cannot annotate bootc container"
          exit 1
        fi

        # Annotate + push container to registry in the background.
        # This overlaps with disk compression, saving wall-clock time.
        (
          PUSH_START=$(date +%s)
          PUSH_SRC="containers-storage:$BOOTC_CONTAINER_NAME"
          OCI_DIR="/tmp/bootc-oci"
          rm -rf "$OCI_DIR"
          skopeo copy "$PUSH_SRC" "oci:${OCI_DIR}:latest"
          COPY_DONE=$(date +%s)
          echo "⏱ Container copy to OCI: $((COPY_DONE - PUSH_START))s"

          # Wait for AIB metadata to be available for annotations
          # (can't use `wait` here — AIB_METADATA_PID is a sibling, not a child of this subshell)
          while kill -0 "$AIB_METADATA_PID" 2>/dev/null; do sleep 1; done
          _AIB_VERSION=$(cat /tmp/aib-version.txt 2>/dev/null || echo "")
          _AIB_IMAGE_PINNED=$(cat /tmp/aib-pinned.txt 2>/dev/null || echo "$AIB_IMAGE_REF")

          echo "Annotating bootc container with builder image: $BUILDER_IMAGE"
          python3 - "$OCI_DIR" "$BUILDER_IMAGE" "$_AIB_VERSION" "$_AIB_IMAGE_PINNED" "$AIB_COMMAND" <<'PYEOF'
import json, sys, hashlib, os
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

oci_dir, builder_image, aib_version, aib_image, aib_command = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
key_builder  = "automotive.sdv.cloud.redhat.com/builder-image"
key_aib_version = "automotive.sdv.cloud.redhat.com/aib-version"
key_aib_image   = "automotive.sdv.cloud.redhat.com/automotive-image-builder"
key_aib_command = "automotive.sdv.cloud.redhat.com/aib-command"

index_path = Path(oci_dir) / "index.json"
index = json.loads(index_path.read_text())
manifest_entry = index["manifests"][0]

manifest_path = Path(oci_dir) / "blobs" / manifest_entry["digest"].replace(":", "/")
manifest = json.loads(manifest_path.read_text())

config_path = Path(oci_dir) / "blobs" / manifest["config"]["digest"].replace(":", "/")
config = json.loads(config_path.read_text())

labels = config.setdefault("config", {}).setdefault("Labels", {})
labels[key_builder] = builder_image
if aib_version:   labels[key_aib_version]   = aib_version
if aib_image:     labels[key_aib_image]      = aib_image
if aib_command:   labels[key_aib_command]    = aib_command
manifest["config"]["digest"], manifest["config"]["size"] = update_blob(oci_dir, manifest["config"]["digest"], config)

annotations = manifest.setdefault("annotations", {})
annotations[key_builder] = builder_image
if aib_version:   annotations[key_aib_version]   = aib_version
if aib_image:     annotations[key_aib_image]      = aib_image
if aib_command:   annotations[key_aib_command]    = aib_command
manifest_entry["digest"], manifest_entry["size"] = update_blob(oci_dir, manifest_entry["digest"], manifest)

index_path.write_text(json.dumps(index, indent=2))
PYEOF
          ANNOTATE_DONE=$(date +%s)
          echo "⏱ Container annotate: $((ANNOTATE_DONE - COPY_DONE))s"

          echo "Pushing container to registry: $CONTAINER_PUSH"
          skopeo copy --digestfile /tmp/container-push-digest.txt \
            --authfile="$REGISTRY_AUTH_FILE" "oci:${OCI_DIR}:latest" "docker://$CONTAINER_PUSH"
          rm -rf "${OCI_DIR:-/tmp/nonexistent}" 2>/dev/null || true
          PUSH_DONE=$(date +%s)
          echo "⏱ Container registry push: $((PUSH_DONE - ANNOTATE_DONE))s"
          echo "⏱ Container push total: $((PUSH_DONE - PUSH_START))s"
          echo "Container pushed successfully to $CONTAINER_PUSH"
          echo "Container digest: $(cat /tmp/container-push-digest.txt 2>/dev/null)"
        ) &
        CONTAINER_PUSH_PID=$!
      fi

      if [ "$SPLIT_BUILD" = "true" ]; then
        # Phase 2b: Create disk image in foreground (runs in parallel with container push)
        echo "Creating disk image from container (parallel with push)..."
        DISK_START=$(date +%s)
        aib --verbose to-disk-image \
          "${FORMAT_ARGS[@]}" \
          "${BUILD_CONTAINER_ARGS[@]}" \
          "${AIB_EXTRA_ARGS[@]}" \
          "$BOOTC_CONTAINER_NAME" \
          "/output/${exportFile}"
        DISK_DONE=$(date +%s)
        echo "⏱ Disk creation: $((DISK_DONE - DISK_START))s"
        echo "Disk image created: /output/${exportFile}"
      elif [ "$BUILD_DISK_IMAGE" = "true" ]; then
        echo "Disk image created: /output/${exportFile}"
      fi
      # Note: Disk image push to OCI registry is handled by the separate push-disk-artifact task
      ;;
    image|package)
      declare -a AIB_CMD=(
        aib-dev --verbose build
        "${CUSTOM_DEFS_ARGS[@]}"
        --distro "$(params.distro)"
        --target "$(params.target)"
        "--arch=${arch}"
        "${FORMAT_ARGS[@]}"
        "${COMMON_BUILD_ARGS[@]}"
        "${AIB_EXTRA_ARGS[@]}"
        "$MANIFEST_FILE"
        "/output/${exportFile}"
      )
      AIB_COMMAND=$(printf '%q ' "${AIB_CMD[@]}" | sed 's/ $//')
      echo -n "$AIB_COMMAND" > /tekton/results/aib-command

      echo "Running $BUILD_MODE build"
      emit_progress "Building image" "$STEP_BUILD" "$PROGRESS_TOTAL"
      "${AIB_CMD[@]}"
      ;;
    disk)
      # Disk mode: create disk image from existing bootc container
      if [ -z "$CONTAINER_REF" ]; then
        echo "Error: container-ref is required for disk mode"
        exit 1
      fi
      validate_container_ref "$CONTAINER_REF"
      echo "Creating disk image from container: $CONTAINER_REF"

      # Pull the container image first
      echo "Pulling container image..."
      # Try without auth first (for public images), fall back to auth file if needed
      if ! skopeo copy "docker://$CONTAINER_REF" "containers-storage:$CONTAINER_REF" 2>/dev/null; then
        echo "Public pull failed, trying with auth..."
        skopeo copy --authfile="$REGISTRY_AUTH_FILE" \
          "docker://$CONTAINER_REF" \
          "containers-storage:$CONTAINER_REF"
      fi

      declare -a AIB_CMD=(
        aib --verbose to-disk-image
        "${FORMAT_ARGS[@]}"
        "${BUILD_CONTAINER_ARGS[@]}"
        "${AIB_EXTRA_ARGS[@]}"
        "$CONTAINER_REF"
        "/output/${exportFile}"
      )
      AIB_COMMAND=$(printf '%q ' "${AIB_CMD[@]}" | sed 's/ $//')
      echo -n "$AIB_COMMAND" > /tekton/results/aib-command

      echo "Running to-disk-image"
      emit_progress "Building image" "$STEP_BUILD" "$PROGRESS_TOTAL"
      "${AIB_CMD[@]}"

      # Note: Disk image push to OCI registry is handled by the separate push-disk-artifact task
      ;;
    *)
      echo "Error: Unknown build mode '$BUILD_MODE'. Supported modes: bootc, image, package, disk"
      exit 1
      ;;
  esac

AIB_END_TIME=$(date +%s)
echo "⏱ AIB build phase: $((AIB_END_TIME - BUILD_START_TIME))s"

# Wait for background AIB metadata capture to finish
wait $AIB_METADATA_PID 2>/dev/null || true
AIB_VERSION=$(cat /tmp/aib-version.txt 2>/dev/null || echo "")
echo -n "${AIB_VERSION}" > /tekton/results/aib-version
AIB_IMAGE_PINNED=$(cat /tmp/aib-pinned.txt 2>/dev/null || echo "$AIB_IMAGE_REF")
echo "AIB image pinned reference: $AIB_IMAGE_PINNED"
echo -n "${AIB_IMAGE_PINNED}" > /tekton/results/automotive-image-builder

pushd /output
mkdir -p "$WORKSPACE_PATH"

# Check if disk image was created (only exists when BUILD_DISK_IMAGE=true or non-bootc mode)
DISK_IMAGE_EXISTS=false
DISK_IMAGE_SOURCE="/output"
if [ -e "/output/${exportFile}" ]; then
    DISK_IMAGE_EXISTS=true

    if [ -d "/output/${exportFile}" ]; then
        echo "${exportFile} is a directory, copying recursively to workspace..."
        cp -rv "/output/${exportFile}" "$WORKSPACE_PATH/" || echo "Failed to copy ${exportFile}"
        DISK_IMAGE_SOURCE="$WORKSPACE_PATH"
    fi
    # For regular files, skip copy — compress directly from /output later
else
    echo "No disk image created (container-only build)"
fi

cp "$BUILD_DIR/image.json" "$WORKSPACE_PATH/image.json" || echo "Failed to copy image.json"

COMPRESSION="$(params.compression)"
if [ "$BUILD_DISK_IMAGE" = "true" ] || [ "$BUILD_MODE" = "image" ] || [ "$BUILD_MODE" = "package" ] || [ "$BUILD_MODE" = "disk" ]; then
  emit_progress "Compressing artifacts" "$((STEP_FINALIZE - 1))" "$PROGRESS_TOTAL"
fi
echo "Requested compression: $COMPRESSION"
GZIP_COMPRESSOR="gzip"

ensure_lz4() {
  if ! command -v lz4 >/dev/null 2>&1; then
    echo "lz4 not found. Attempting to install..."
    if command -v dnf >/dev/null 2>&1; then
      dnf -y install lz4 || true
    fi
    if command -v microdnf >/dev/null 2>&1; then
      microdnf install -y lz4 || true
    fi
    if command -v yum >/dev/null 2>&1; then
      yum -y install lz4 || true
    fi
    if ! command -v lz4 >/dev/null 2>&1; then
      echo "lz4 still not available; falling back to gzip"
      COMPRESSION="gzip"
    fi
  fi
}

setup_gzip_compressor() {
  if command -v pigz >/dev/null 2>&1; then
    GZIP_COMPRESSOR="pigz"
    echo "Using pigz for gzip compression"
  else
    echo "pigz not found; using gzip for compression"
  fi
}

if [ "$COMPRESSION" = "lz4" ]; then
  ensure_lz4
elif [ "$COMPRESSION" = "gzip" ]; then
  setup_gzip_compressor
fi

# Simplified compression functions - no unnecessary dispatching
compress_file() {
  local src="$1" dest="$2"
  case "$COMPRESSION" in
    lz4) lz4 -z -f -q "$src" "$dest" ;;
    gzip|*) "$GZIP_COMPRESSOR" -c "$src" > "$dest" ;;
  esac
}

tar_dir() {
  local dir="$1" out="$2"
  case "$COMPRESSION" in
    lz4) tar -C "$WORKSPACE_PATH" -cf - "$dir" | lz4 -z -f -q > "$out" ;;
    gzip|*) tar -C "$WORKSPACE_PATH" -cf - "$dir" | "$GZIP_COMPRESSOR" -c > "$out" ;;
  esac
}

case "$COMPRESSION" in
  lz4)
    EXT_FILE=".lz4"
    EXT_DIR=".tar.lz4"
    ;;
  gzip|*)
    EXT_FILE=".gz"
    EXT_DIR=".tar.gz"
    ;;
esac

final_name=""

# For container-only builds (no disk image), record the container push URL as the artifact
if [ "$DISK_IMAGE_EXISTS" = "false" ] && [ -n "$CONTAINER_PUSH" ]; then
  echo "Container-only build completed. Container pushed to: $CONTAINER_PUSH"
  final_name="container:$CONTAINER_PUSH"
elif [ -d "$WORKSPACE_PATH/${exportFile}" ]; then
  echo "Preparing compressed parts for directory ${exportFile}..."
  final_compressed_name="${exportFile}${EXT_DIR}"
  parts_dir="$WORKSPACE_PATH/${final_compressed_name}-parts"
  mkdir -p "$parts_dir"
  (
    cd "$WORKSPACE_PATH"
    for item in "${exportFile}"/*; do
      [ -e "$item" ] || continue
      base=$(basename "$item")
      if [ -f "$item" ]; then
        # Record uncompressed size before compression (for OCI layer annotations)
        uncompressed_size=$($GET_SIZE_CMD "$item" 2>/dev/null || echo "")
        echo "Creating $parts_dir/${base}${EXT_FILE} (uncompressed: ${uncompressed_size:-unknown} bytes)"
        compress_file "$item" "$parts_dir/${base}${EXT_FILE}" || echo "Failed to create $parts_dir/${base}${EXT_FILE}"
        # Store uncompressed size in sidecar file for push_artifact.sh
        if [ -n "$uncompressed_size" ]; then
          echo "$uncompressed_size" > "$parts_dir/${base}${EXT_FILE}.size"
        fi
      elif [ -d "$item" ]; then
        echo "Creating $parts_dir/${base}${EXT_DIR}"
        tar_dir "${exportFile}/$base" "$parts_dir/${base}${EXT_DIR}" || echo "Failed to create $parts_dir/${base}${EXT_DIR}"
      fi
    done
  )
  echo "Creating compressed archive ${final_compressed_name} in shared workspace..."
  tar_dir "${exportFile}" "$WORKSPACE_PATH/${final_compressed_name}" || echo "Failed to create ${final_compressed_name}"
  echo "Compressed archive size:" && ls -lah "$WORKSPACE_PATH/${final_compressed_name}" || true
  if [ -f "$WORKSPACE_PATH/${final_compressed_name}" ]; then
    echo "Removing uncompressed directory ${exportFile} (keeping parts directory)"
    rm -rf "$WORKSPACE_PATH/${exportFile}"
    pushd "$WORKSPACE_PATH"
    ln -sf ${final_compressed_name} disk.img
    final_name="${final_compressed_name}"
    popd
    echo "Available artifacts:"
    ls -la "$WORKSPACE_PATH/" || true
    if [ -d "$WORKSPACE_PATH/${final_compressed_name}-parts" ]; then
      echo "Individual compressed parts in ${final_compressed_name}-parts/:"
      ls -la "$WORKSPACE_PATH/${final_compressed_name}-parts/" || true
    fi
  fi
elif [ -f "${DISK_IMAGE_SOURCE}/${exportFile}" ]; then
  echo "Compressing ${exportFile} directly to workspace..."
  compress_file "${DISK_IMAGE_SOURCE}/${exportFile}" "$WORKSPACE_PATH/${exportFile}${EXT_FILE}" || { echo "Error: Failed to compress ${exportFile}"; exit 1; }
  echo "Compressed file size:" && ls -lah "$WORKSPACE_PATH/${exportFile}${EXT_FILE}" || true
  if [ -f "$WORKSPACE_PATH/${exportFile}${EXT_FILE}" ]; then
    pushd "$WORKSPACE_PATH"
    ln -sf ${exportFile}${EXT_FILE} disk.img
    final_name="${exportFile}${EXT_FILE}"
    popd
  fi
fi

if [ -z "$final_name" ]; then
  # Try to find artifact with priority: compressed file > compressed dir > any file
  # This ensures we prefer compressed artifacts when compression is enabled
  patterns_to_try=(
    "${cleanName}*${EXT_FILE}"
    "${cleanName}*${EXT_DIR}"
    "${cleanName}*"
  )

  # If compression is disabled, only try the general pattern
  if [ "$COMPRESSION" = "none" ]; then
    patterns_to_try=("${cleanName}*")
  fi

  if final_name=$(find_artifact "$WORKSPACE_PATH" "${patterns_to_try[@]}"); then
    echo "Fallback: using found artifact: $final_name"
  fi
fi

emit_progress "Finalizing build" "$PROGRESS_TOTAL" "$PROGRESS_TOTAL"

if [ -n "$final_name" ]; then
  echo "$final_name" > /tekton/results/artifact-filename || echo "Failed to write Tekton result"
else
  echo "Warning: final_name is empty, no artifact filename will be recorded"
fi

# Wait for background container push to complete (bootc mode only)
if [ -n "${CONTAINER_PUSH_PID:-}" ]; then
  echo "Waiting for container push to complete..."
  wait "$CONTAINER_PUSH_PID" || { echo "Error: Container push failed"; exit 1; }
fi

# Write Tekton Chains type hint results for bootc container
if [ -n "${CONTAINER_PUSH:-}" ]; then
  PUSHED_DIGEST=$(cat /tmp/container-push-digest.txt 2>/dev/null || echo "")
  echo -n "$CONTAINER_PUSH" > /tekton/results/IMAGE_URL
  echo -n "$PUSHED_DIGEST" > /tekton/results/IMAGE_DIGEST
  echo "Tekton Chains: IMAGE_URL=$CONTAINER_PUSH IMAGE_DIGEST=$PUSHED_DIGEST"
fi

BUILD_END_TIME=$(date +%s)
echo "⏱ Post-build phase: $((BUILD_END_TIME - AIB_END_TIME))s"
echo "⏱ Total build-image step: $((BUILD_END_TIME - BUILD_START_TIME))s"

# Write structured timing data as a Tekton result for Prometheus metrics
cat > /tekton/results/build-timing <<TIMING_EOF
{"setup_s":$((AIB_INVOKE_TIME - BUILD_START_TIME)),"build_s":$((AIB_END_TIME - AIB_INVOKE_TIME)),"post_build_s":$((BUILD_END_TIME - AIB_END_TIME)),"total_s":$((BUILD_END_TIME - BUILD_START_TIME))}
TIMING_EOF