#!/bin/bash
set -e

validate_arg() {
  local arg="$1"
  local name="$2"
  # Block shell metacharacters that could be used for injection
  if [[ "$arg" =~ [\;\|\&\$\`\(\)\{\}\<\>\!\\] ]]; then
    echo "ERROR: Invalid characters in $name: $arg"
    exit 1
  fi
}

validate_custom_def() {
  local def="$1"
  # Custom defs should be KEY=VALUE format only
  if [[ ! "$def" =~ ^[a-zA-Z_][a-zA-Z0-9_]*=.*$ ]]; then
    echo "ERROR: Invalid custom definition format: $def (expected KEY=VALUE)"
    exit 1
  fi
  validate_arg "$def" "custom definition"
}


# Make the internal registry trusted
# TODO think about whether this is really the right approach
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << EOF
[registries.insecure]
registries = ['image-registry.openshift-image-registry.svc:5000']
EOF

if [ -e /dev/fuse ]; then
  if ! command -v fuse-overlayfs >/dev/null 2>&1; then
    echo "Installing fuse-overlayfs..."
    dnf install -y fuse-overlayfs 2>/dev/null || yum install -y fuse-overlayfs 2>/dev/null || true
  fi

  if command -v fuse-overlayfs >/dev/null 2>&1; then
    echo "Configuring fuse-overlayfs for container storage..."
    cat > /etc/containers/storage.conf << EOF
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
  else
    echo "Warning: fuse-overlayfs install failed, using vfs driver"
    export STORAGE_DRIVER=vfs
  fi
else
  echo "Warning: /dev/fuse not available, using vfs driver"
  export STORAGE_DRIVER=vfs
fi

umask 0077

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
REGISTRY="image-registry.openshift-image-registry.svc:5000"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

mkdir -p $HOME/.config
cat > $HOME/.authjson <<EOF
{
  "auths": {
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF

export REGISTRY_AUTH_FILE=$HOME/.authjson
export CONTAINERS_REGISTRIES_CONF="/etc/containers/registries.conf"

# Read registry credentials from workspace if available
REGISTRY_AUTH_DIR="/workspace/registry-auth"
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_URL" ]; then
    REGISTRY_URL=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_URL")
fi
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_USERNAME" ]; then
    REGISTRY_USERNAME=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_USERNAME")
fi
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_PASSWORD" ]; then
    REGISTRY_PASSWORD=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_PASSWORD")
fi
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_TOKEN" ]; then
    REGISTRY_TOKEN=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_TOKEN")
fi
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_AUTH_FILE_CONTENT" ]; then
    REGISTRY_AUTH_FILE_CONTENT=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_AUTH_FILE_CONTENT")
fi

if [ -n "$REGISTRY_AUTH_FILE_CONTENT" ]; then
    echo "Using provided registry auth file content"
    echo "$REGISTRY_AUTH_FILE_CONTENT" > $HOME/.custom_authjson
    export REGISTRY_AUTH_FILE=$HOME/.custom_authjson
elif [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
    echo "Creating registry auth from username/password for $REGISTRY_URL"
    mkdir -p $HOME/.config
    AUTH_STRING=$(echo -n "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64 -w0)
    cat > $HOME/.custom_authjson <<EOF
{
  "auths": {
    "$REGISTRY_URL": {
      "auth": "$AUTH_STRING"
    }
  }
}
EOF
    export REGISTRY_AUTH_FILE=$HOME/.custom_authjson
elif [ -n "$REGISTRY_TOKEN" ] && [ -n "$REGISTRY_URL" ]; then
    echo "Creating registry auth from token for $REGISTRY_URL"
    mkdir -p $HOME/.config
    cat > $HOME/.custom_authjson <<EOF
{
  "auths": {
    "$REGISTRY_URL": {
      "auth": "$(echo -n "token:$REGISTRY_TOKEN" | base64 -w0)"
    },
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
    export REGISTRY_AUTH_FILE=$HOME/.custom_authjson
fi

if [ -n "$BUILDAH_REGISTRY_AUTH_FILE" ]; then
    export BUILDAH_REGISTRY_AUTH_FILE="$REGISTRY_AUTH_FILE"
fi

osbuildPath="/usr/bin/osbuild"
storePath="/_build"
runTmp="/run/osbuild/"

mkdir -p "$storePath"
mkdir -p "$runTmp"

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

if mountpoint -q "$osbuildPath"; then
    exit 0
fi

rootType="system_u:object_r:root_t:s0"
chcon "$rootType" "$storePath"

installType="system_u:object_r:install_exec_t:s0"
if ! mountpoint -q "$runTmp"; then
  mount -t tmpfs tmpfs "$runTmp"
fi

destPath="$runTmp/osbuild"
cp -p "$osbuildPath" "$destPath"
chcon "$installType" "$destPath"

mount --bind "$destPath" "$osbuildPath"

cd $(workspaces.shared-workspace.path)

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
    for item in $line; do
      $validator "$item" "$description"
      result_array+=("$item")
    done
  done < "$file"
  echo "Loaded ${#result_array[@]} items for $description"
  return 0
}

# Load custom definitions
declare -a CUSTOM_DEFS_ARGS=()
CUSTOM_DEFS_FILE="$(workspaces.manifest-config-workspace.path)/custom-definitions.env"
if load_args_from_file "$CUSTOM_DEFS_FILE" "custom definitions" validate_custom_def temp_defs; then
  for def in "${temp_defs[@]}"; do
    CUSTOM_DEFS_ARGS+=("--define" "$def")
  done
fi

# Load AIB arguments (override or extra)
declare -a AIB_EXTRA_ARGS=()
USE_AIB_OVERRIDE=false
AIB_OVERRIDE_ARGS_FILE="$(workspaces.manifest-config-workspace.path)/aib-override-args.txt"
AIB_EXTRA_ARGS_FILE="$(workspaces.manifest-config-workspace.path)/aib-extra-args.txt"

if load_args_from_file "$AIB_OVERRIDE_ARGS_FILE" "AIB override args" validate_arg AIB_EXTRA_ARGS; then
  USE_AIB_OVERRIDE=true
elif load_args_from_file "$AIB_EXTRA_ARGS_FILE" "AIB extra args" validate_arg AIB_EXTRA_ARGS; then
  :  # Extra args loaded successfully
else
  echo "No AIB extra/override args files found"
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

get_flag_value() {
  flag_name="$1"; shift
  args_str="$*"
  val=$(echo "$args_str" | sed -nE "s/.*${flag_name}=([^ ]+).*/\1/p" | head -n1)
  if [ -n "$val" ]; then
    echo "$val"; return 0
  fi
  val=$(echo "$args_str" | awk -v f="$flag_name" '{for (i=1;i<=NF;i++) if ($i==f && (i+1)<=NF) {print $(i+1); exit}}')
  [ -n "$val" ] && echo "$val"
}

# Handle override args for file naming
if [ "$USE_AIB_OVERRIDE" = true ]; then
  aib_args_str="${AIB_EXTRA_ARGS[*]}"
  override_format=$(get_flag_value "--format" "$aib_args_str")
  if [ -z "$override_format" ]; then
    override_format=$(get_flag_value "--export" "$aib_args_str")
  fi
  override_distro=$(get_flag_value "--distro" "$aib_args_str")
  override_target=$(get_flag_value "--target" "$aib_args_str")
  [ -n "$override_distro" ] && cleanName="$override_distro-${cleanName#*-}"
  [ -n "$override_target" ] && cleanName="${cleanName%-*}-$override_target"
  if [ -n "$override_format" ]; then
    case "$override_format" in
      image|raw)
        file_extension=".raw" ;;
      qcow2)
        file_extension=".qcow2" ;;
      *)
        file_extension=".$override_format" ;;
    esac
  fi
  exportFile=${cleanName}${file_extension}
fi

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

BOOTC_CONTAINER_NAME="localhost/aib-build:$(params.distro)-$(params.target)"

BUILD_CONTAINER_ARG=""
LOCAL_BUILDER_IMAGE="localhost/aib-build:$(params.distro)-$TARGET_ARCH"

# For bootc/disk builds, if no builder-image is provided but cluster-registry-route is set,
# use the image that prepare-builder cached in the cluster registry
if [ -z "$BUILDER_IMAGE" ] && { [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; } && [ -n "$CLUSTER_REGISTRY_ROUTE" ]; then
  NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
  BUILDER_IMAGE="${CLUSTER_REGISTRY_ROUTE}/${NAMESPACE}/aib-build:$(params.distro)-$TARGET_ARCH"
  echo "Using builder image from cluster registry: $BUILDER_IMAGE"
fi

if [ -n "$BUILDER_IMAGE" ] && { [ "$BUILD_MODE" = "bootc" ] || [ "$BUILD_MODE" = "disk" ]; }; then
  echo "Pulling builder image to local storage: $BUILDER_IMAGE"

  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")
  if [ -n "$TOKEN" ]; then
    REGISTRY_HOST=$(echo "$BUILDER_IMAGE" | cut -d'/' -f1)
    cat > /tmp/builder-auth.json <<EOF
{
  "auths": {
    "$REGISTRY_HOST": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
    skopeo copy --authfile=/tmp/builder-auth.json \
      "docker://$BUILDER_IMAGE" \
      "containers-storage:$LOCAL_BUILDER_IMAGE"
  else
    skopeo copy \
      "docker://$BUILDER_IMAGE" \
      "containers-storage:$LOCAL_BUILDER_IMAGE"
  fi

  echo "Builder image ready in local storage: $LOCAL_BUILDER_IMAGE"
  BUILD_CONTAINER_ARG="--build-container $LOCAL_BUILDER_IMAGE"
fi

# Build command execution using arrays for security (no eval)
# Parse BUILD_CONTAINER_ARG safely
declare -a BUILD_CONTAINER_ARGS=()
if [ -n "$LOCAL_BUILDER_IMAGE" ]; then
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
  --build-dir=/output/_build
  --osbuild-manifest=/output/image.json
)

if [ "$USE_AIB_OVERRIDE" = true ]; then
  echo "Running the build command (override mode)"
  aib --verbose build \
    "${CUSTOM_DEFS_ARGS[@]}" \
    "${COMMON_BUILD_ARGS[@]}" \
    "${AIB_EXTRA_ARGS[@]}" \
    "$MANIFEST_FILE" \
    "/output/${exportFile}"
else
  case "$BUILD_MODE" in
    bootc)
      # Build bootc container and optionally disk image in a single command
      # aib build takes: manifest out [disk] where disk is optional
      declare -a DISK_OUTPUT_ARGS=()
      if [ "$BUILD_DISK_IMAGE" = "true" ]; then
        DISK_OUTPUT_ARGS=("/output/${exportFile}")
      fi

      echo "Running bootc build"
      aib --verbose build \
        --distro "$(params.distro)" \
        --target "$(params.target)" \
        "--arch=${arch}" \
        "${COMMON_BUILD_ARGS[@]}" \
        "${FORMAT_ARGS[@]}" \
        "${BUILD_CONTAINER_ARGS[@]}" \
        "${CUSTOM_DEFS_ARGS[@]}" \
        "${AIB_EXTRA_ARGS[@]}" \
        "$MANIFEST_FILE" \
        "$BOOTC_CONTAINER_NAME" \
        "${DISK_OUTPUT_ARGS[@]}"

      if [ -n "$CONTAINER_PUSH" ]; then
        echo "Pushing container to registry: $CONTAINER_PUSH"
        skopeo copy \
          --authfile="$REGISTRY_AUTH_FILE" \
          "containers-storage:$BOOTC_CONTAINER_NAME" \
          "docker://$CONTAINER_PUSH"
        echo "Container pushed successfully to $CONTAINER_PUSH"
      fi

      if [ "$BUILD_DISK_IMAGE" = "true" ]; then
        echo "Disk image created: /output/${exportFile}"
        # Note: Disk image push to OCI registry is handled by the separate push-disk-artifact task
      fi
      ;;
    image|package)
      echo "Running $BUILD_MODE build"
      aib-dev --verbose build \
        "${CUSTOM_DEFS_ARGS[@]}" \
        --distro "$(params.distro)" \
        --target "$(params.target)" \
        "--arch=${arch}" \
        "${FORMAT_ARGS[@]}" \
        "${COMMON_BUILD_ARGS[@]}" \
        "${AIB_EXTRA_ARGS[@]}" \
        "$MANIFEST_FILE" \
        "/output/${exportFile}"
      ;;
    disk)
      # Disk mode: create disk image from existing bootc container
      if [ -z "$CONTAINER_REF" ]; then
        echo "Error: container-ref is required for disk mode"
        exit 1
      fi
      # Validate container reference for shell injection
      validate_arg "$CONTAINER_REF" "container-ref"
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

      # to-disk-image only accepts: --format, --build-container, src_container, out
      echo "Running to-disk-image"
      aib --verbose to-disk-image \
        "${FORMAT_ARGS[@]}" \
        "${BUILD_CONTAINER_ARGS[@]}" \
        "$CONTAINER_REF" \
        "/output/${exportFile}"

      # Note: Disk image push to OCI registry is handled by the separate push-disk-artifact task
      ;;
    *)
      echo "Error: Unknown build mode '$BUILD_MODE'. Supported modes: bootc, image, package, disk"
      exit 1
      ;;
  esac
fi

echo "Build completed. Contents of output directory:"
ls -la /output/ || true

pushd /output
ln -sf ./${exportFile} ./disk.img

echo "copying build artifacts to shared workspace..."

mkdir -p $(workspaces.shared-workspace.path)

if [ -d "/output/${exportFile}" ]; then
    echo "${exportFile} is a directory, copying recursively..."
    cp -rv "/output/${exportFile}" $(workspaces.shared-workspace.path)/ || echo "Failed to copy ${exportFile}"
else
    echo "${exportFile} is a regular file, copying..."
    cp -v "/output/${exportFile}" $(workspaces.shared-workspace.path)/ || echo "Failed to copy ${exportFile}"
fi

pushd $(workspaces.shared-workspace.path)
if [ -d "${exportFile}" ]; then
    echo "Creating symlink to directory ${exportFile}"
    ln -sf ${exportFile} disk.img
elif [ -f "${exportFile}" ]; then
    echo "Creating symlink to file ${exportFile}"
    ln -sf ${exportFile} disk.img
else
    echo "Warning: ${exportFile} not found in workspace, cannot create symlink"
fi
popd

cp -v /output/image.json $(workspaces.shared-workspace.path)/image.json || echo "Failed to copy image.json"

echo "Contents of shared workspace:"
ls -la $(workspaces.shared-workspace.path)/

COMPRESSION="$(params.compression)"
echo "Requested compression: $COMPRESSION"

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

if [ "$COMPRESSION" = "lz4" ]; then
  ensure_lz4
fi

compress_file_gzip() {
  src="$1"; dest="$2"
  gzip -c "$src" > "$dest"
}

compress_file_lz4() {
  src="$1"; dest="$2"
  lz4 -z -f -q "$src" "$dest"
}

tar_dir_gzip() {
  dir="$1"; out="$2"
  tar -C $(workspaces.shared-workspace.path) -czf "$out" "$dir"
}

tar_dir_lz4() {
  dir="$1"; out="$2"
  tar -C $(workspaces.shared-workspace.path) -cf - "$dir" | lz4 -z -f -q > "$out"
}

compress_file() {
  src="$1"; dest="$2"
  case "$COMPRESSION" in
    lz4) compress_file_lz4 "$src" "$dest" ;;
    gzip|*) compress_file_gzip "$src" "$dest" ;;
  esac
}

tar_dir() {
  dir="$1"; out="$2"
  case "$COMPRESSION" in
    lz4) tar_dir_lz4 "$dir" "$out" ;;
    gzip|*) tar_dir_gzip "$dir" "$out" ;;
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
if [ -d "$(workspaces.shared-workspace.path)/${exportFile}" ]; then
  echo "Preparing compressed parts for directory ${exportFile}..."
  final_compressed_name="${exportFile}${EXT_DIR}"
  parts_dir="$(workspaces.shared-workspace.path)/${final_compressed_name}-parts"
  mkdir -p "$parts_dir"
  (
    cd "$(workspaces.shared-workspace.path)"
    for item in "${exportFile}"/*; do
      [ -e "$item" ] || continue
      base=$(basename "$item")
      if [ -f "$item" ]; then
        echo "Creating $parts_dir/${base}${EXT_FILE}"
        compress_file "$item" "$parts_dir/${base}${EXT_FILE}" || echo "Failed to create $parts_dir/${base}${EXT_FILE}"
      elif [ -d "$item" ]; then
        echo "Creating $parts_dir/${base}${EXT_DIR}"
        tar_dir "${exportFile}/$base" "$parts_dir/${base}${EXT_DIR}" || echo "Failed to create $parts_dir/${base}${EXT_DIR}"
      fi
    done
  )
  echo "Creating compressed archive ${final_compressed_name} in shared workspace..."
  tar_dir "${exportFile}" "$(workspaces.shared-workspace.path)/${final_compressed_name}" || echo "Failed to create ${final_compressed_name}"
  echo "Compressed archive size:" && ls -lah $(workspaces.shared-workspace.path)/${final_compressed_name} || true
  if [ -f "$(workspaces.shared-workspace.path)/${final_compressed_name}" ]; then
    echo "Removing uncompressed directory ${exportFile} (keeping parts directory)"
    rm -rf "$(workspaces.shared-workspace.path)/${exportFile}"
    pushd $(workspaces.shared-workspace.path)
    ln -sf ${final_compressed_name} disk.img
    final_name="${final_compressed_name}"
    popd
    echo "Available artifacts:"
    ls -la $(workspaces.shared-workspace.path)/ || true
    if [ -d "$(workspaces.shared-workspace.path)/${final_compressed_name}-parts" ]; then
      echo "Individual compressed parts in ${final_compressed_name}-parts/:"
      ls -la "$(workspaces.shared-workspace.path)/${final_compressed_name}-parts/" || true
    fi
  fi
elif [ -f "$(workspaces.shared-workspace.path)/${exportFile}" ]; then
  echo "Creating compressed file ${exportFile}${EXT_FILE} in shared workspace..."
  compress_file "$(workspaces.shared-workspace.path)/${exportFile}" "$(workspaces.shared-workspace.path)/${exportFile}${EXT_FILE}" || echo "Failed to create ${exportFile}${EXT_FILE}"
  echo "Compressed file size:" && ls -lah $(workspaces.shared-workspace.path)/${exportFile}${EXT_FILE} || true
  if [ -f "$(workspaces.shared-workspace.path)/${exportFile}${EXT_FILE}" ]; then
    pushd $(workspaces.shared-workspace.path)
    ln -sf ${exportFile}${EXT_FILE} disk.img
    final_name="${exportFile}${EXT_FILE}"
    popd
  fi
fi

if [ -z "$final_name" ]; then
  workspace_path=$(workspaces.shared-workspace.path)

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

  for pattern in "${patterns_to_try[@]}"; do
    guess=$(ls -1 "${workspace_path}/${pattern}" 2>/dev/null | head -n1)
    if [ -n "$guess" ]; then
      final_name=$(basename "$guess")
      echo "Fallback: using found artifact: $final_name"
      break
    fi
  done
fi
if [ -n "$final_name" ]; then
  echo "Writing artifact filename to Tekton result: $final_name"
  echo "$final_name" > /tekton/results/artifact-filename || echo "Failed to write Tekton result"
  echo "Verifying Tekton result file:"
  cat /tekton/results/artifact-filename || echo "Failed to read Tekton result"
else
  echo "Warning: final_name is empty, no artifact filename will be recorded"
fi


echo "Syncing filesystem to ensure all artifacts are written..."
sync
echo "Filesystem sync completed"
