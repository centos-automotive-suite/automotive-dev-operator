#!/bin/bash
set -e

validate_arg() {
  local arg="$1"
  local name="$2"
  if [[ "$arg" =~ [\;\|\&\$\`\(\)\{\}\<\>\!\\] ]]; then
    echo "ERROR: Invalid characters in $name: $arg"
    exit 1
  fi
}

log_command() {
  local -a cmd=("$@")
  local -a redacted=()
  local skip_next=0
  local arg=""

  for arg in "${cmd[@]}"; do
    if [ "$skip_next" -eq 1 ]; then
      redacted+=("[REDACTED]")
      skip_next=0
      continue
    fi
    case "$arg" in
      --passwd|--password|--token|--auth|--key)
        redacted+=("$arg")
        skip_next=1
        ;;
      pass:*)
        redacted+=("pass:[REDACTED]")
        ;;
      *)
        redacted+=("$arg")
        ;;
    esac
  done

  echo "Running: ${redacted[*]}"
}

echo "=== Sealed operation: ${OPERATION} ==="
echo "Input ref: ${INPUT_REF}"

WORKSPACE="${WORKSPACE:-/workspace/shared}"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# ── Container storage setup (needed for prepare-reseal and reseal) ──
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

# ── Registry auth (combined SA token + user credentials) ──
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")
REGISTRY="image-registry.openshift-image-registry.svc:5000"

mkdir -p "$HOME/.config"
if [ -n "$TOKEN" ]; then
  cat > "$HOME/.authjson" <<EOF
{
  "auths": {
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
else
  echo '{"auths":{}}' > "$HOME/.authjson"
fi
export REGISTRY_AUTH_FILE="$HOME/.authjson"

# Read additional registry credentials from workspace
REGISTRY_AUTH_DIR="${REGISTRY_AUTH_PATH:-/workspace/registry-auth}"
REGISTRY_URL=""
REGISTRY_USERNAME=""
REGISTRY_PASSWORD=""
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_URL" ]; then
  REGISTRY_URL=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_URL")
fi
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_USERNAME" ]; then
  REGISTRY_USERNAME=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_USERNAME")
fi
if [ -f "$REGISTRY_AUTH_DIR/REGISTRY_PASSWORD" ]; then
  REGISTRY_PASSWORD=$(cat "$REGISTRY_AUTH_DIR/REGISTRY_PASSWORD")
fi

if [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
  echo "Creating registry auth from username/password for $REGISTRY_URL"
  AUTH_STRING=$(echo -n "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64 -w0)
  SA_AUTH=""
  if [ -n "$TOKEN" ]; then
    SA_AUTH=",\"$REGISTRY\":{\"auth\":\"$(echo -n "serviceaccount:$TOKEN" | base64 -w0)\"}"
  fi
  cat > "$HOME/.custom_authjson" <<EOF
{
  "auths": {
    "$REGISTRY_URL": {
      "auth": "$AUTH_STRING"
    }${SA_AUTH}
  }
}
EOF
  export REGISTRY_AUTH_FILE="$HOME/.custom_authjson"
fi

# Also build an oras-compatible config (oras needs --registry-config)
ORAS_REGISTRY_CONFIG=""
if [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
  ORAS_REGISTRY_CONFIG="$WORKSPACE/.oras-auth.json"
  cp "$REGISTRY_AUTH_FILE" "$ORAS_REGISTRY_CONFIG"
fi

# ── Seal key setup (same as teammate's ImageReseal) ──
SEAL_KEY_FILE=""
declare -a SEAL_KEY_ARGS=()
if [ -f "/workspace/sealing-key/private-key" ]; then
  SEAL_KEY_FILE="/workspace/sealing-key/private-key"
  SEAL_KEY_ARGS=("--key" "$SEAL_KEY_FILE")
  echo "Using seal key from workspace"
fi
if [ -f "/workspace/sealing-key-password/password" ]; then
  SEAL_KEY_PASSWORD=$(cat /workspace/sealing-key-password/password)
  SEAL_KEY_ARGS+=("--passwd" "pass:$SEAL_KEY_PASSWORD")
  echo "Using seal key password from workspace"
fi

validate_arg "${INPUT_REF}" "input-ref"
validate_arg "${OUTPUT_REF:-}" "output-ref"
validate_arg "${SIGNED_REF:-}" "signed-ref"

# ── Install oras (for extract-for-signing / inject-signed) ──
install_oras() {
  if command -v oras >/dev/null 2>&1; then return; fi
  ORAS_VERSION="1.2.0"
  case "$(uname -m)" in
    x86_64) ORAS_ARCH="amd64" ;;
    aarch64|arm64) ORAS_ARCH="arm64" ;;
    *) echo "ERROR: Unsupported architecture $(uname -m)" >&2; exit 1 ;;
  esac
  echo "Installing oras ${ORAS_VERSION}..."
  curl -sSLf "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${ORAS_ARCH}.tar.gz" | tar -xz -C /tmp oras
  mv /tmp/oras /usr/local/bin/oras
  chmod +x /usr/local/bin/oras
}

oras_pull() {
  if [ -n "$ORAS_REGISTRY_CONFIG" ]; then
    oras pull --registry-config "$ORAS_REGISTRY_CONFIG" "$@"
  else
    oras pull "$@"
  fi
}

oras_push() {
  if [ -n "$ORAS_REGISTRY_CONFIG" ]; then
    oras push --registry-config "$ORAS_REGISTRY_CONFIG" "$@"
  else
    oras push "$@"
  fi
}

# ── Operation: prepare-reseal / reseal (container-based, same as teammate) ──
run_container_seal_op() {
  local op="$1"
  local source_container="${INPUT_REF}"
  local output_container="${OUTPUT_REF:-localhost/sealed-output:latest}"
  local builder_image="${BUILDER_IMAGE:-}"

  echo "=== ${op} Configuration ==="
  echo "SOURCE: $source_container"
  echo "OUTPUT: $output_container"
  echo "BUILDER: ${builder_image:-<not specified>}"
  echo "============================"

  if [ -z "$source_container" ]; then
    echo "ERROR: input-ref (source container) is required" >&2
    exit 1
  fi

  # Pull the source container into local podman storage
  echo "Pulling source container: $source_container"
  pull_cmd=(skopeo copy "docker://$source_container" "containers-storage:$source_container")
  log_command "${pull_cmd[@]}"
  if ! "${pull_cmd[@]}" 2>/dev/null; then
    echo "Public pull failed, trying with auth..."
    pull_auth_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$source_container" "containers-storage:$source_container")
    log_command "${pull_auth_cmd[@]}"
    "${pull_auth_cmd[@]}"
  fi

  # Build --build-container argument (required for reseal/prepare-reseal)
  declare -a BUILD_CONTAINER_ARGS=()
  if [ -n "$builder_image" ]; then
    LOCAL_BUILDER="localhost/aib-builder:local"
    echo "Pulling builder image: $builder_image -> $LOCAL_BUILDER"
    pull_builder_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$builder_image" "containers-storage:$LOCAL_BUILDER")
    log_command "${pull_builder_cmd[@]}"
    if ! "${pull_builder_cmd[@]}" 2>/dev/null; then
      echo "Auth pull failed for builder, trying public pull..."
      pull_builder_public=(skopeo copy "docker://$builder_image" "containers-storage:$LOCAL_BUILDER")
      log_command "${pull_builder_public[@]}"
      "${pull_builder_public[@]}"
    fi
    BUILD_CONTAINER_ARGS=("--build-container" "$LOCAL_BUILDER")
  else
    echo "Warning: builder-image not specified; aib may fail if it requires one"
  fi

  # Run the sealed operation
  if [ -z "$SEAL_KEY_FILE" ] || [ ! -f "$SEAL_KEY_FILE" ]; then
    echo "No key provided - aib may generate ephemeral key"
    seal_cmd=(aib --verbose "$op" "${BUILD_CONTAINER_ARGS[@]}" "$source_container" "$output_container")
    log_command "${seal_cmd[@]}"
    "${seal_cmd[@]}"
  else
    echo "Key provided - running $op with provided key..."
    seal_cmd=(aib --verbose "$op" "${SEAL_KEY_ARGS[@]}" "${BUILD_CONTAINER_ARGS[@]}" "$source_container" "$output_container")
    log_command "${seal_cmd[@]}"
    "${seal_cmd[@]}"
  fi

  echo "${op} completed successfully"

  # Push output container to registry
  if [ -n "${OUTPUT_REF:-}" ]; then
    echo "Pushing sealed container to registry: $OUTPUT_REF"
    push_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "containers-storage:$output_container" "docker://$OUTPUT_REF")
    log_command "${push_cmd[@]}"
    "${push_cmd[@]}"
    echo "Sealed container pushed successfully to $OUTPUT_REF"
  fi
}

# ── Operation: extract-for-signing (container-based input, OCI artifact output) ──
# AIB extract-for-signing takes only: src_container out (no --build-container, no --key)
run_extract_for_signing() {
  local source_container="${INPUT_REF}"

  echo "=== extract-for-signing Configuration ==="
  echo "SOURCE: $source_container"
  echo "OUTPUT: ${OUTPUT_REF:-<local only>}"
  echo "=========================================="

  if [ -z "$source_container" ]; then
    echo "ERROR: input-ref (source container) is required" >&2
    exit 1
  fi

  # Pull the source container into local podman storage
  echo "Pulling source container: $source_container"
  pull_cmd=(skopeo copy "docker://$source_container" "containers-storage:$source_container")
  log_command "${pull_cmd[@]}"
  if ! "${pull_cmd[@]}" 2>/dev/null; then
    echo "Public pull failed, trying with auth..."
    pull_auth_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$source_container" "containers-storage:$source_container")
    log_command "${pull_auth_cmd[@]}"
    "${pull_auth_cmd[@]}"
  fi

  # Run extract-for-signing: input is a container, output is a directory
  mkdir -p output_dir
  extract_cmd=(aib --verbose extract-for-signing "$source_container" output_dir)
  log_command "${extract_cmd[@]}"
  "${extract_cmd[@]}"

  echo "extract-for-signing completed successfully"
  echo "Extracted signing artifacts:"
  ls -la output_dir/

  # Push extracted signing artifacts as OCI tarball
  if [ -n "${OUTPUT_REF:-}" ]; then
    install_oras
    echo "Pushing signing artifacts to ${OUTPUT_REF}..."
    tar -C output_dir -czf output.tar.gz .
    oras_push "${OUTPUT_REF}" output.tar.gz
    echo "Signing artifacts pushed to ${OUTPUT_REF}"
  fi
}

# ── Operation: inject-signed (container-based input/output, OCI artifact for signed files) ──
# AIB inject-signed accepts SHARED_RESEAL_ARGS (--build-container, --passwd) plus --reseal-with-key
run_inject_signed() {
  local source_container="${INPUT_REF}"
  local output_container="${OUTPUT_REF:-localhost/injected-signed:latest}"
  local builder_image="${BUILDER_IMAGE:-}"

  echo "=== inject-signed Configuration ==="
  echo "SOURCE: $source_container"
  echo "OUTPUT: $output_container"
  echo "SIGNED: ${SIGNED_REF:-<not set>}"
  echo "BUILDER: ${builder_image:-<not specified>}"
  echo "RESEAL-WITH-KEY: ${SEAL_KEY_FILE:-<not set>}"
  echo "====================================="

  if [ -z "$source_container" ]; then
    echo "ERROR: input-ref (source container) is required" >&2
    exit 1
  fi
  if [ -z "${SIGNED_REF:-}" ]; then
    echo "ERROR: SIGNED_REF is required for inject-signed" >&2
    exit 1
  fi

  # Pull the source container into local podman storage
  echo "Pulling source container: $source_container"
  pull_cmd=(skopeo copy "docker://$source_container" "containers-storage:$source_container")
  log_command "${pull_cmd[@]}"
  if ! "${pull_cmd[@]}" 2>/dev/null; then
    echo "Public pull failed, trying with auth..."
    pull_auth_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$source_container" "containers-storage:$source_container")
    log_command "${pull_auth_cmd[@]}"
    "${pull_auth_cmd[@]}"
  fi

  # Build --build-container argument (from SHARED_RESEAL_ARGS in AIB)
  declare -a BUILD_CONTAINER_ARGS=()
  if [ -n "$builder_image" ]; then
    LOCAL_BUILDER="localhost/aib-builder:local"
    echo "Pulling builder image: $builder_image -> $LOCAL_BUILDER"
    pull_builder_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$builder_image" "containers-storage:$LOCAL_BUILDER")
    log_command "${pull_builder_cmd[@]}"
    if ! "${pull_builder_cmd[@]}" 2>/dev/null; then
      echo "Auth pull failed for builder, trying public pull..."
      pull_builder_public=(skopeo copy "docker://$builder_image" "containers-storage:$LOCAL_BUILDER")
      log_command "${pull_builder_public[@]}"
      "${pull_builder_public[@]}"
    fi
    BUILD_CONTAINER_ARGS=("--build-container" "$LOCAL_BUILDER")
  fi

  # Build --reseal-with-key argument (specific to inject-signed in AIB)
  # When a seal key is provided for inject-signed, AIB uses --reseal-with-key (not --key)
  # This combines inject-signed + reseal into a single operation
  declare -a RESEAL_KEY_ARGS=()
  if [ -n "$SEAL_KEY_FILE" ] && [ -f "$SEAL_KEY_FILE" ]; then
    RESEAL_KEY_ARGS=("--reseal-with-key" "$SEAL_KEY_FILE")
    echo "Will reseal after injecting signed files"
    # --passwd from SHARED_RESEAL_ARGS
    if [ -f "/workspace/sealing-key-password/password" ]; then
      SEAL_KEY_PASSWORD=$(cat /workspace/sealing-key-password/password)
      RESEAL_KEY_ARGS+=("--passwd" "pass:$SEAL_KEY_PASSWORD")
    fi
  fi

  # Pull signed artifacts via oras (these are files, not container images)
  install_oras
  echo "Pulling signed artifacts from ${SIGNED_REF}..."
  mkdir -p signed_extract
  oras_pull "${SIGNED_REF}" --output signed_extract

  # Handle tarball extraction: if the artifact is a tarball, extract it
  mkdir -p signed_dir
  TARBALL=$(find signed_extract -type f -name '*.tar.gz' -o -name '*.tgz' 2>/dev/null | head -1)
  if [ -n "$TARBALL" ]; then
    echo "Extracting signed artifacts tarball: $TARBALL"
    tar -xzf "$TARBALL" -C signed_dir
  else
    find signed_extract -type f -exec cp {} signed_dir/ \;
  fi
  echo "Signed artifacts ready:"
  ls -la signed_dir/

  # Run inject-signed: aib inject-signed [--build-container BC] [--reseal-with-key KEY] [--passwd PW] src_container srcdir new_container
  inject_cmd=(aib --verbose inject-signed "${BUILD_CONTAINER_ARGS[@]}" "${RESEAL_KEY_ARGS[@]}" "$source_container" signed_dir "$output_container")
  log_command "${inject_cmd[@]}"
  "${inject_cmd[@]}"

  echo "inject-signed completed successfully"

  # Push output container to registry
  if [ -n "${OUTPUT_REF:-}" ]; then
    echo "Pushing injected container to registry: $OUTPUT_REF"
    push_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "containers-storage:$output_container" "docker://$OUTPUT_REF")
    log_command "${push_cmd[@]}"
    "${push_cmd[@]}"
    echo "Injected container pushed successfully to $OUTPUT_REF"
  fi
}

# ── Dispatch ──
echo "Running: aib --verbose ${OPERATION} ..."
case "${OPERATION}" in
  prepare-reseal|reseal)
    run_container_seal_op "${OPERATION}"
    ;;
  extract-for-signing)
    run_extract_for_signing
    ;;
  inject-signed)
    run_inject_signed
    ;;
  *)
    echo "ERROR: Unknown operation ${OPERATION}" >&2
    exit 1
    ;;
esac

echo "=== Sealed operation completed ==="
