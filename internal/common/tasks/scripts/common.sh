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
[registries.insecure]
registries = ['$INTERNAL_REGISTRY']
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
