#!/bin/bash
set -e

# Common constants and functions shared between build scripts.
# This file is prepended to task scripts at embed time.

emit_progress() {
  local stage="$1" done="$2" total="$3"
  # Run in background to avoid blocking the build on API server round-trip
  (curl -s --connect-timeout 3 --max-time 5 \
    --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    -X PATCH \
    -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    -H "Content-Type: application/merge-patch+json" \
    "https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods/${HOSTNAME}" \
    -d "{\"metadata\":{\"annotations\":{\"automotive.sdv.cloud.redhat.com/progress\":\"${stage}|${done}|${total}\"}}}" \
    > /dev/null 2>&1 || true) &
}

INTERNAL_REGISTRY="image-registry.openshift-image-registry.svc:5000"
OSBUILD_PATH="/usr/bin/osbuild"
OSBUILD_STORE="/_build"
OSBUILD_RUN="/run/osbuild/"

if [[ -n "${ADO_TRACE_ID:-}" ]]; then
  echo "{\"traceID\":\"${ADO_TRACE_ID}\",\"msg\":\"task started\",\"hostname\":\"${HOSTNAME:-unknown}\"}"
fi

# Add OCI volume tool paths when mounted (OCIVolumes feature gate)
OCI_TOOLS_BASE="/oci-tools"
if [ -d "$OCI_TOOLS_BASE/oras/bin" ]; then
  export PATH="$OCI_TOOLS_BASE/oras/bin:$PATH"
fi

# --- ORAS install ---

# install_oras downloads and checksum-verifies the ORAS CLI binary.
# Sets ORAS_BIN to the installed path and adds it to PATH.
# Skips if oras is already available (e.g. via OCI volume mount).
install_oras() {
  if command -v oras >/dev/null 2>&1; then
    ORAS_BIN="$(command -v oras)"
    echo "ORAS already available at $ORAS_BIN"
    return 0
  fi

  if [ -d "$OCI_TOOLS_BASE/oras" ]; then
    echo "WARN: OCI volume mounted at $OCI_TOOLS_BASE/oras but oras binary not found on PATH, falling back to download" >&2
  fi

  ORAS_VERSION="1.2.0"
  case "$(uname -m)" in
    x86_64) ORAS_ARCH="amd64" ;;
    aarch64|arm64) ORAS_ARCH="arm64" ;;
    *)
      echo "ERROR: Unsupported architecture: $(uname -m)" >&2
      return 1
      ;;
  esac
  ORAS_TARBALL="oras_${ORAS_VERSION}_linux_${ORAS_ARCH}.tar.gz"
  ORAS_BASE_URL="https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}"
  ORAS_CHECKSUMS="oras_${ORAS_VERSION}_checksums.txt"

  _cleanup_oras_files() {
    rm -f "$ORAS_TARBALL" "$ORAS_CHECKSUMS" oras
  }

  trap _cleanup_oras_files EXIT

  echo "Downloading ORAS ${ORAS_VERSION} with integrity verification..."

  curl -LO "${ORAS_BASE_URL}/${ORAS_TARBALL}" || {
    echo "ERROR: Failed to download ORAS tarball" >&2
    return 1
  }

  curl -LO "${ORAS_BASE_URL}/${ORAS_CHECKSUMS}" || {
    echo "ERROR: Failed to download ORAS checksums" >&2
    return 1
  }

  expected_checksum=$(grep "${ORAS_TARBALL}" "${ORAS_CHECKSUMS}" | cut -d' ' -f1)
  if [ -z "$expected_checksum" ]; then
    echo "ERROR: Could not find checksum for ${ORAS_TARBALL} in checksums file" >&2
    return 1
  fi

  if command -v sha256sum >/dev/null; then
    actual_checksum=$(sha256sum "${ORAS_TARBALL}" | cut -d' ' -f1)
  elif command -v shasum >/dev/null; then
    actual_checksum=$(shasum -a 256 "${ORAS_TARBALL}" | cut -d' ' -f1)
  else
    echo "ERROR: Neither sha256sum nor shasum available for checksum verification" >&2
    return 1
  fi

  if [ "$expected_checksum" != "$actual_checksum" ]; then
    echo "ERROR: Checksum verification failed for ${ORAS_TARBALL}" >&2
    echo "  Expected: $expected_checksum" >&2
    echo "  Actual:   $actual_checksum" >&2
    return 1
  fi

  echo "Checksum verification passed: $expected_checksum"

  tar -zxf "$ORAS_TARBALL" oras || {
    echo "ERROR: Failed to extract ORAS from tarball" >&2
    return 1
  }

  ORAS_INSTALL_DIR="${HOME:-/tmp}/bin"
  if [ "$ORAS_INSTALL_DIR" = "//bin" ] || [ "$ORAS_INSTALL_DIR" = "/bin" ]; then
    ORAS_INSTALL_DIR="/tmp/bin"
  fi
  mkdir -p "$ORAS_INSTALL_DIR"
  mv oras "$ORAS_INSTALL_DIR/" || {
    echo "ERROR: Failed to install ORAS binary" >&2
    return 1
  }

  if ! echo "$PATH" | grep -q "$ORAS_INSTALL_DIR"; then
    export PATH="$ORAS_INSTALL_DIR:$PATH"
  fi

  _cleanup_oras_files
  trap - EXIT

  ORAS_BIN="$ORAS_INSTALL_DIR/oras"
  echo "ORAS ${ORAS_VERSION} installed successfully"
}

# --- Validation ---

validate_container_ref() {
  local ref="$1"
  # Container image references may only contain alphanumerics and . / : - _ @
  if [[ ! "$ref" =~ ^[a-zA-Z0-9][a-zA-Z0-9./_:@-]*$ ]]; then
    echo "ERROR: Invalid container reference: $ref"
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
}

# --- Setup functions ---

# Configure container registries (insecure internal registry) and overlay storage driver.
setup_container_config() {
  mkdir -p /etc/containers
  cat > /etc/containers/registries.conf << EOF
[[registry]]
location = "$INTERNAL_REGISTRY"
insecure = true
EOF

  echo "Configuring kernel overlay storage driver"
  cat > /etc/containers/storage.conf << EOF
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
EOF

  export CONTAINERS_REGISTRIES_CONF="/etc/containers/registries.conf"
}

# Create a filesystem for /var/tmp if not already mounted.
# Uses tmpfs (RAM) when USE_MEMORY_VOLUMES=true, otherwise loopback ext4 for SELinux isolation.
setup_var_tmp() {
  if ! mountpoint -q /var/tmp; then
    if [ "$USE_MEMORY_VOLUMES" = "true" ]; then
      if [ -n "$VAR_TMP_SIZE" ]; then
        echo "Creating tmpfs filesystem for /var/tmp (${VAR_TMP_SIZE} memory)"
        mount -t tmpfs -o size="$VAR_TMP_SIZE" tmpfs /var/tmp
      else
        echo "Creating tmpfs filesystem for /var/tmp (default size)"
        mount -t tmpfs tmpfs /var/tmp
      fi
    else
      # Larger default for sparse loopback (doesn't use real disk space initially)
      VAR_TMP_SIZE="${VAR_TMP_SIZE:-20G}"
      echo "Creating loopback ext4 filesystem for /var/tmp (${VAR_TMP_SIZE} sparse)"
      truncate -s "$VAR_TMP_SIZE" /tmp/var-tmp.img
      mkfs.ext4 -q /tmp/var-tmp.img
      mount -o loop /tmp/var-tmp.img /var/tmp
    fi
  fi
}

# Set up Kubernetes service account authentication for a container registry.
# Sets globals: TOKEN, NAMESPACE, REGISTRY
# Exports: REGISTRY_AUTH_FILE
# Args: $1 - registry URL (defaults to INTERNAL_REGISTRY)
setup_cluster_auth() {
  echo "DEBUG: Reading service account token"
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  echo "DEBUG: Reading service account namespace"
  # shellcheck disable=SC2034 # NAMESPACE is used by scripts prepended with common.sh
  NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
  REGISTRY="${1:-$INTERNAL_REGISTRY}"
  echo "DEBUG: Using registry: $REGISTRY"

  mkdir -p "$HOME/.config"
  echo "DEBUG: Creating auth JSON"
  (umask 0177; cat > "$HOME/.authjson" <<EOF
{
  "auths": {
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
)

  export REGISTRY_AUTH_FILE="$HOME/.authjson"
  echo "DEBUG: Auth file created: $REGISTRY_AUTH_FILE"
}

# Install custom CA certificates if available.
install_custom_ca_certs() {
  if [ -d /etc/pki/ca-trust/custom ] && (ls /etc/pki/ca-trust/custom/*.pem >/dev/null 2>&1 || ls /etc/pki/ca-trust/custom/*.crt >/dev/null 2>&1); then
    echo "Installing custom CA certificates..."
    cp /etc/pki/ca-trust/custom/*.pem /etc/pki/ca-trust/source/anchors/ 2>/dev/null || true
    cp /etc/pki/ca-trust/custom/*.crt /etc/pki/ca-trust/source/anchors/ 2>/dev/null || true
    update-ca-trust extract 2>/dev/null || true
  fi
}

# Set up SELinux contexts and bind-mount osbuild for privileged execution.
# Creates OSBUILD_STORE and OSBUILD_RUN directories.
setup_osbuild() {
  mkdir -p "$OSBUILD_STORE"
  mkdir -p "$OSBUILD_RUN"

  chcon "system_u:object_r:root_t:s0" "$OSBUILD_STORE" || true

  if ! mountpoint -q "$OSBUILD_RUN"; then
    mount -t tmpfs tmpfs "$OSBUILD_RUN"
  fi

  local destPath="$OSBUILD_RUN/osbuild"
  cp -p "$OSBUILD_PATH" "$destPath"
  chcon "system_u:object_r:install_exec_t:s0" "$destPath" || true

  mount --bind "$destPath" "$OSBUILD_PATH"
}

# Load custom definitions (KEY=VALUE) from a file into CUSTOM_DEFS_ARGS array.
# Sets global: CUSTOM_DEFS_ARGS (array of --define KEY=VALUE pairs)
# Args: $1 - path to custom definitions file
load_custom_definitions() {
  local defs_file="$1"
  declare -g -a CUSTOM_DEFS_ARGS=()

  if [ ! -f "$defs_file" ]; then
    return
  fi

  echo "Loading custom definitions from $defs_file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    validate_custom_def "$line"
    CUSTOM_DEFS_ARGS+=("--define" "$line")
    echo "  Custom definition: $line"
  done < "$defs_file"
  echo "Loaded $((${#CUSTOM_DEFS_ARGS[@]} / 2)) custom definitions"
}

# Compute a content-addressable digest of an artifact (parts directory or single file).
# Outputs "sha256:<hex>" to stdout, or empty string if nothing found.
# Args: $1 = parts directory path, $2 = single file path
compute_artifact_digest() {
  local parts_dir="$1" single_file="$2"
  if [ -d "$parts_dir" ] && [ -n "$(ls -A "$parts_dir" 2>/dev/null)" ]; then
    echo "sha256:$(cd "$parts_dir" && find . -maxdepth 1 -type f ! -name '*.size' ! -name 'aib-manifest.yml' -printf '%f\n' | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)"
  elif [ -f "$single_file" ]; then
    echo "sha256:$(sha256sum "$single_file" | cut -d' ' -f1)"
  fi
}

# Create service account authentication JSON for container registries.
# Args: $1 - registry URL, $2 - output file path, $3 - optional token (defaults to SA token)
create_service_account_auth() {
  local registry="$1"
  local output_file="$2"
  local token="${3:-$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)}"

  cat > "$output_file" <<EOF
{
  "auths": {
    "$registry": {
      "auth": "$(echo -n "serviceaccount:$token" | base64 -w0)"
    }
  }
}
EOF
}

# Read registry credentials from workspace files into global variables.
# Sets globals: REGISTRY_URL, REGISTRY_USERNAME, REGISTRY_PASSWORD, REGISTRY_TOKEN, REGISTRY_AUTH_FILE_CONTENT
# Args: $1 - registry auth directory path
read_registry_creds() {
  local auth_dir="$1"
  echo "DEBUG: Reading registry creds from $auth_dir"
  [ -f "$auth_dir/REGISTRY_URL" ] && REGISTRY_URL=$(cat "$auth_dir/REGISTRY_URL") && echo "DEBUG: Found REGISTRY_URL"
  [ -f "$auth_dir/REGISTRY_USERNAME" ] && REGISTRY_USERNAME=$(cat "$auth_dir/REGISTRY_USERNAME") && echo "DEBUG: Found REGISTRY_USERNAME"
  [ -f "$auth_dir/REGISTRY_PASSWORD" ] && REGISTRY_PASSWORD=$(cat "$auth_dir/REGISTRY_PASSWORD") && echo "DEBUG: Found REGISTRY_PASSWORD"
  [ -f "$auth_dir/REGISTRY_TOKEN" ] && REGISTRY_TOKEN=$(cat "$auth_dir/REGISTRY_TOKEN") && echo "DEBUG: Found REGISTRY_TOKEN"
  [ -f "$auth_dir/REGISTRY_AUTH_FILE_CONTENT" ] && REGISTRY_AUTH_FILE_CONTENT=$(cat "$auth_dir/REGISTRY_AUTH_FILE_CONTENT") && echo "DEBUG: Found REGISTRY_AUTH_FILE_CONTENT"
  [ -z "$REGISTRY_AUTH_FILE_CONTENT" ] && [ -f "$auth_dir/.dockerconfigjson" ] && REGISTRY_AUTH_FILE_CONTENT=$(cat "$auth_dir/.dockerconfigjson") && echo "DEBUG: Found .dockerconfigjson"
  echo "DEBUG: Registry creds read completed"
}

# Create registry auth JSON from loaded credentials.
# Uses globals: REGISTRY_URL, REGISTRY_USERNAME, REGISTRY_PASSWORD, REGISTRY_TOKEN, REGISTRY_AUTH_FILE_CONTENT, TOKEN, REGISTRY
# Exports: REGISTRY_AUTH_FILE
setup_registry_auth() {
  echo "DEBUG: setup_registry_auth starting"
  mkdir -p "$HOME/.config"
  local auth_file="$HOME/.custom_authjson"

  if [ -n "$REGISTRY_AUTH_FILE_CONTENT" ]; then
    echo "Using provided registry auth file content"
    echo "$REGISTRY_AUTH_FILE_CONTENT" > "$auth_file"
    if [ -n "${TOKEN:-}" ] && [ -n "${REGISTRY:-}" ]; then
      python3 -c "
import json, sys
f = sys.argv[1]
with open(f) as fh: d = json.load(fh)
d.setdefault('auths', {})[sys.argv[2]] = {'auth': sys.argv[3]}
with open(f, 'w') as fh: json.dump(d, fh)
" "$auth_file" "$REGISTRY" "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
      echo "Merged cluster registry auth into provided credentials"
    fi
  elif [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
    echo "Creating registry auth from username/password for $REGISTRY_URL"
    create_auth_json "$auth_file" "$REGISTRY_URL" "$(echo -n "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64 -w0)"
  elif [ -n "$REGISTRY_TOKEN" ] && [ -n "$REGISTRY_URL" ]; then
    echo "Creating registry auth from token for $REGISTRY_URL"
    echo "DEBUG: Creating dual registry auth JSON"
    # Create auth JSON with both custom registry and cluster registry
    cat > "$auth_file" <<EOF
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
  else
    echo "DEBUG: No custom registry auth found, returning 1"
    return 1
  fi

  export REGISTRY_AUTH_FILE="$auth_file"
  echo "DEBUG: setup_registry_auth completed"
}

# Create auth JSON with single registry entry.
# Args: $1 - file path, $2 - registry URL, $3 - base64 auth string
create_auth_json() {
  local file="$1" url="$2" auth="$3"
  echo "DEBUG: Creating auth JSON for $url"
  cat > "$file" <<EOF
{
  "auths": {
    "$url": {
      "auth": "$auth"
    }
  }
}
EOF
  echo "DEBUG: Auth JSON created at $file"
}


# Detect best stat command for file size on this system.
# Sets global: GET_SIZE_CMD
detect_stat_command() {
  echo "DEBUG: detect_stat_command starting"
  if stat -c%s /dev/null >/dev/null 2>&1; then
    declare -g GET_SIZE_CMD="stat -c%s"
    echo "DEBUG: Using GNU stat"
  elif stat -f%z /dev/null >/dev/null 2>&1; then
    declare -g GET_SIZE_CMD="stat -f%z"
    echo "DEBUG: Using BSD stat"
  else
    # shellcheck disable=SC2034 # GET_SIZE_CMD is used by scripts prepended with common.sh
    declare -g GET_SIZE_CMD="echo ''"
    echo "DEBUG: No working stat command found"
  fi
  echo "DEBUG: detect_stat_command completed"
}

# Find artifact file using bash globbing instead of ls.
# Returns first matching file basename, or empty string if none found.
# Args: $1 - workspace path, $2+ - glob patterns to try
find_artifact() {
  local workspace="$1"
  shift
  local patterns=("$@")

  for pattern in "${patterns[@]}"; do
    for file in "$workspace"/$pattern; do
      [ -e "$file" ] && { basename "$file"; return 0; }
    done
  done
  return 1
}

# detect_registry_protocol determines the appropriate oras flags for insecure registries.
# Probes HTTPS first (handles OpenShift/self-signed certs), falls back to plain HTTP (Kind).
# Usage: detect_registry_protocol <registry_host>
# Output (stdout): space-separated oras flags (--insecure, or --insecure --plain-http)
# Logs (stderr): detection result message
detect_registry_protocol() {
  local registry_host="$1"
  local oras_flags="--insecure"

  local https_code
  https_code=$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w "%{http_code}" "https://${registry_host}/v2/" 2>/dev/null || true)

  case "$https_code" in
    200|401|403)
      echo "Insecure registry: HTTPS detected (HTTP $https_code), using --insecure for oras" >&2
      echo "$oras_flags"
      return 0
      ;;
  esac

  local http_code
  http_code=$(curl -s --connect-timeout 3 --max-time 5 -o /dev/null -w "%{http_code}" "http://${registry_host}/v2/" 2>/dev/null || true)

  case "$http_code" in
    200|401|403)
      oras_flags="$oras_flags --plain-http"
      echo "Insecure registry: plain HTTP detected (HTTP $http_code), using --insecure --plain-http for oras" >&2
      echo "$oras_flags"
      return 0
      ;;
  esac

  echo "Insecure registry: protocol unclear, using --insecure for oras" >&2
  echo "$oras_flags"
}
