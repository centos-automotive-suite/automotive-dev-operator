#!/bin/bash
set -e
umask 0022

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

echo "=== Operation: ${OPERATION} ==="
echo "Input ref: ${INPUT_REF}"

WORKSPACE="${WORKSPACE:-/workspace/shared}"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# ── Container storage and /var/tmp setup (shared with build task via common.sh) ──
setup_container_config
setup_var_tmp
install_custom_ca_certs

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
chmod 600 "$HOME/.authjson"
export REGISTRY_AUTH_FILE="$HOME/.authjson"

# Read additional registry credentials from workspace
REGISTRY_AUTH_DIR="${REGISTRY_AUTH_PATH:-/workspace/registry-auth}"
REGISTRY_URL=""
REGISTRY_USERNAME=""
REGISTRY_PASSWORD=""
REGISTRY_AUTH_FILE_CONTENT=""
read_registry_creds "$REGISTRY_AUTH_DIR"

ORAS_REGISTRY_CONFIG=""
if [ -n "$REGISTRY_AUTH_FILE_CONTENT" ]; then
  echo "Using provided registry auth file content"
  echo "$REGISTRY_AUTH_FILE_CONTENT" > "$HOME/.custom_authjson"
  # Merge SA token for internal registry access if available
  if [ -n "$TOKEN" ]; then
    SA_AUTH_B64=$(echo -n "serviceaccount:$TOKEN" | base64 -w0)
    python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
cfg.setdefault('auths', {})[sys.argv[2]] = {'auth': sys.argv[3]}
with open(sys.argv[1], 'w') as f:
    json.dump(cfg, f)
" "$HOME/.custom_authjson" "$REGISTRY" "$SA_AUTH_B64" 2>/dev/null || true
  fi
  chmod 600 "$HOME/.custom_authjson"
  export REGISTRY_AUTH_FILE="$HOME/.custom_authjson"
  ORAS_REGISTRY_CONFIG="$WORKSPACE/.oras-auth.json"
  cp "$REGISTRY_AUTH_FILE" "$ORAS_REGISTRY_CONFIG"
  chmod 600 "$ORAS_REGISTRY_CONFIG"
elif [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
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
  chmod 600 "$HOME/.custom_authjson"
  export REGISTRY_AUTH_FILE="$HOME/.custom_authjson"
  ORAS_REGISTRY_CONFIG="$WORKSPACE/.oras-auth.json"
  cp "$REGISTRY_AUTH_FILE" "$ORAS_REGISTRY_CONFIG"
  chmod 600 "$ORAS_REGISTRY_CONFIG"
fi

# ── Seal key setup ──
SEAL_KEY_FILE=""
SEAL_KEY_PASSWORD=""
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

# ── Resolve architecture ──
if [ -n "${ARCHITECTURE:-}" ]; then
  RESOLVED_ARCH="$ARCHITECTURE"
else
  case "$(uname -m)" in
    x86_64)  RESOLVED_ARCH="amd64" ;;
    aarch64) RESOLVED_ARCH="arm64" ;;
    *)       RESOLVED_ARCH="$(uname -m)" ;;
  esac
fi
echo "Architecture: $RESOLVED_ARCH"

# Build the same short AIB hash suffix used by builder image naming in build tasks.
AIB_HASH=""
if [ -n "${AIB_IMAGE:-}" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    AIB_HASH=$(echo -n "$AIB_IMAGE" | sha256sum | cut -c1-8)
  elif command -v shasum >/dev/null 2>&1; then
    AIB_HASH=$(echo -n "$AIB_IMAGE" | shasum -a 256 | cut -c1-8)
  fi
fi

# ── Shared helpers ──

pull_source_container() {
  local source="$1"
  if [ -z "$source" ]; then
    echo "ERROR: input-ref (source container) is required" >&2
    exit 1
  fi
  local -a tls_args=()
  if [ "${INSECURE_REGISTRY:-}" = "true" ]; then
    tls_args=(--src-tls-verify=false)
  fi
  echo "Pulling source container: $source"
  local -a pull_cmd=(skopeo copy "${tls_args[@]}" "docker://$source" "containers-storage:$source")
  log_command "${pull_cmd[@]}"
  if ! "${pull_cmd[@]}" 2>/dev/null; then
    echo "Public pull failed, trying with auth..."
    pull_cmd=(skopeo copy "${tls_args[@]}" --authfile="$REGISTRY_AUTH_FILE" "docker://$source" "containers-storage:$source")
    log_command "${pull_cmd[@]}"
    "${pull_cmd[@]}"
  fi
}

# Priority: 1) explicit BUILDER_IMAGE param  2) source container annotation  3) internal registry default
resolve_and_pull_builder() {
  local source="$1"
  local builder_image="${BUILDER_IMAGE:-}"

  if [ -z "${builder_image:-}" ]; then
    local annotation_key="$OCI_ANN_BUILDER_IMAGE"
    echo "No builder image specified, checking source container labels..."
    builder_image=$(skopeo inspect "containers-storage:$source" 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Labels',{}).get('$annotation_key',''))" 2>/dev/null) || true

    if [ -n "$builder_image" ]; then
      # Rewrite external OpenShift registry route to internal service URL
      if [[ "$builder_image" == default-route-openshift-image-registry.apps.* ]]; then
        local path="${builder_image#*/}"
        builder_image="image-registry.openshift-image-registry.svc:5000/${path}"
        echo "Rewrote external registry route to internal URL"
      fi
      echo "Resolved builder image from source container label: $builder_image"
    else
      local ns
      ns=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo "automotive-dev-operator-system")
      if [ -n "$AIB_HASH" ]; then
        builder_image="image-registry.openshift-image-registry.svc:5000/${ns}/aib-build:autosd-${RESOLVED_ARCH}-${AIB_HASH}"
      else
        builder_image="image-registry.openshift-image-registry.svc:5000/${ns}/aib-build:autosd-${RESOLVED_ARCH}"
      fi
      echo "No annotation found, using default builder image: $builder_image"
    fi
  else
    echo "Using explicitly provided builder image: $builder_image"
  fi

  BUILD_CONTAINER_ARGS=()
  LOCAL_BUILDER="localhost/aib-builder:local"
  local -a tls_args=()
  if [ "${INSECURE_REGISTRY:-}" = "true" ]; then
    tls_args=(--src-tls-verify=false)
  fi
  echo "Pulling builder image: $builder_image -> $LOCAL_BUILDER"
  local -a pull_cmd=(skopeo copy "${tls_args[@]}" --authfile="$REGISTRY_AUTH_FILE" "docker://$builder_image" "containers-storage:$LOCAL_BUILDER")
  log_command "${pull_cmd[@]}"
  if ! "${pull_cmd[@]}" 2>/dev/null; then
    echo "Auth pull failed for builder, trying public pull..."
    pull_cmd=(skopeo copy "${tls_args[@]}" "docker://$builder_image" "containers-storage:$LOCAL_BUILDER")
    log_command "${pull_cmd[@]}"
    "${pull_cmd[@]}"
  fi
  BUILD_CONTAINER_ARGS=("--build-container" "$LOCAL_BUILDER")
}

push_output_container() {
  local output_ref="$1"
  local source_tag="$2"
  if [ -n "$output_ref" ]; then
    local -a tls_args=()
    if [ "${INSECURE_REGISTRY:-}" = "true" ]; then
      tls_args=(--dest-tls-verify=false)
    fi
    echo "Pushing output container to registry: $output_ref"
    local -a push_cmd=(skopeo copy "${tls_args[@]}" --authfile="$REGISTRY_AUTH_FILE" "containers-storage:$source_tag" "docker://$output_ref")
    log_command "${push_cmd[@]}"
    "${push_cmd[@]}"
    echo "Output container pushed successfully to $output_ref"
  fi
}

validate_arg "${INPUT_REF}" "input-ref"
validate_arg "${OUTPUT_REF:-}" "output-ref"
validate_arg "${SIGNED_REF:-}" "signed-ref"

insecure_oras_flags=()
if [ "${INSECURE_REGISTRY:-}" = "true" ]; then
  # shellcheck disable=SC2207
  insecure_oras_flags=($(detect_registry_protocol "$REGISTRY"))
fi

oras_pull() {
  local -a extra_args=()
  if [ -n "$ORAS_REGISTRY_CONFIG" ]; then
    extra_args+=(--registry-config "$ORAS_REGISTRY_CONFIG")
  fi
  extra_args+=("${insecure_oras_flags[@]}")
  oras pull "${extra_args[@]}" "$@"
}

oras_push() {
  local -a extra_args=()
  if [ -n "$ORAS_REGISTRY_CONFIG" ]; then
    extra_args+=(--registry-config "$ORAS_REGISTRY_CONFIG")
  fi
  extra_args+=("${insecure_oras_flags[@]}")
  oras push "${extra_args[@]}" "$@"
}

# ── Operation: prepare-reseal / reseal ──
run_container_seal_op() {
  local op="$1"
  local source_container="${INPUT_REF}"
  local output_container="${OUTPUT_REF:-localhost/reseal-output:latest}"

  echo "=== ${op} Configuration ==="
  echo "SOURCE: $source_container"
  echo "OUTPUT: $output_container"
  echo "BUILDER: ${BUILDER_IMAGE:-<will resolve from source>}"
  echo "============================"

  pull_source_container "$source_container"
  resolve_and_pull_builder "$source_container"

  # Run the operation
  local -a seal_cmd=(aib --verbose "$op")
  if [ -n "$SEAL_KEY_FILE" ] && [ -f "$SEAL_KEY_FILE" ]; then
    echo "Key provided - running $op with provided key..."
    seal_cmd+=("${SEAL_KEY_ARGS[@]}")
  else
    echo "No key provided - aib may use ephemeral key for one-time seal"
  fi
  seal_cmd+=("${BUILD_CONTAINER_ARGS[@]}" "$source_container" "$output_container")
  log_command "${seal_cmd[@]}"
  "${seal_cmd[@]}"

  echo "${op} completed successfully"
  push_output_container "${OUTPUT_REF:-}" "$output_container"
}

# ── Operation: extract-for-signing ──
run_extract_for_signing() {
  local source_container="${INPUT_REF}"

  echo "=== extract-for-signing Configuration ==="
  echo "SOURCE: $source_container"
  echo "OUTPUT: ${OUTPUT_REF:-<local only>}"
  echo "=========================================="

  pull_source_container "$source_container"

  mkdir -p output_dir
  local -a extract_cmd=(aib --verbose extract-for-signing "$source_container" output_dir)
  log_command "${extract_cmd[@]}"
  "${extract_cmd[@]}"

  echo "extract-for-signing completed successfully"
  echo "Extracted signing artifacts:"
  ls -la output_dir/

  if [ -n "${OUTPUT_REF:-}" ]; then
    install_oras
    echo "Pushing signing artifacts to ${OUTPUT_REF}..."
    tar -C output_dir -czf output.tar.gz .
    oras_push "${OUTPUT_REF}" output.tar.gz
    echo "Signing artifacts pushed to ${OUTPUT_REF}"
  fi
}

# ── Operation: inject-signed ──
run_inject_signed() {
  local source_container="${INPUT_REF}"
  local output_container="${OUTPUT_REF:-localhost/injected-signed:latest}"

  echo "=== inject-signed Configuration ==="
  echo "SOURCE: $source_container"
  echo "OUTPUT: $output_container"
  echo "SIGNED: ${SIGNED_REF:-<not set>}"
  echo "BUILDER: ${BUILDER_IMAGE:-<will resolve from source>}"
  echo "RESEAL-WITH-KEY: ${SEAL_KEY_FILE:-<not set>}"
  echo "====================================="

  if [ -z "${SIGNED_REF:-}" ]; then
    echo "ERROR: SIGNED_REF is required for inject-signed" >&2
    exit 1
  fi

  pull_source_container "$source_container"
  resolve_and_pull_builder "$source_container"

  # Build --reseal-with-key argument (inject-signed uses different flag than reseal)
  declare -a RESEAL_KEY_ARGS=()
  if [ -n "$SEAL_KEY_FILE" ] && [ -f "$SEAL_KEY_FILE" ]; then
    RESEAL_KEY_ARGS=("--reseal-with-key" "$SEAL_KEY_FILE")
    if [ -n "$SEAL_KEY_PASSWORD" ]; then
      RESEAL_KEY_ARGS+=("--passwd" "pass:$SEAL_KEY_PASSWORD")
    fi
    echo "Will reseal after injecting signed files"
  fi

  # Pull signed artifacts via oras
  install_oras
  echo "Pulling signed artifacts from ${SIGNED_REF}..."
  mkdir -p signed_extract
  oras_pull "${SIGNED_REF}" --output signed_extract

  # Handle tarball extraction
  mkdir -p signed_dir
  TARBALL=$(find signed_extract -type f \( -name '*.tar.gz' -o -name '*.tgz' \) 2>/dev/null | head -1)
  if [ -n "$TARBALL" ]; then
    echo "Extracting signed artifacts tarball: $TARBALL"
    tar -xzf "$TARBALL" -C signed_dir
  else
    echo "Copying signed artifacts preserving directory structure"
    cp -r signed_extract/. signed_dir/
  fi
  echo "Signed artifacts ready:"
  ls -la signed_dir/

  local -a inject_cmd=(aib --verbose inject-signed "${BUILD_CONTAINER_ARGS[@]}" "${RESEAL_KEY_ARGS[@]}" "$source_container" signed_dir "$output_container")
  log_command "${inject_cmd[@]}"
  "${inject_cmd[@]}"

  echo "inject-signed completed successfully"
  push_output_container "${OUTPUT_REF:-}" "$output_container"
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

# Write the output reference to the Tekton result for downstream consumption
if [ -n "${RESULT_PATH:-}" ] && [ -n "${OUTPUT_REF:-}" ]; then
  printf '%s' "${OUTPUT_REF}" > "${RESULT_PATH}"
  echo "Result written to ${RESULT_PATH}: ${OUTPUT_REF}"
fi

echo "=== Operation completed ==="
