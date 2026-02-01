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

# Configure container storage
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

# Set up registry auth from serviceaccount
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
REGISTRY="image-registry.openshift-image-registry.svc:5000"

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

# Read additional registry credentials from workspace if available
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

if [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
    echo "Creating registry auth from username/password for $REGISTRY_URL"
    AUTH_STRING=$(echo -n "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64 -w0)
    cat > $HOME/.custom_authjson <<EOF
{
  "auths": {
    "$REGISTRY_URL": {
      "auth": "$AUTH_STRING"
    },
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
    export REGISTRY_AUTH_FILE=$HOME/.custom_authjson
fi

# Parameters from Tekton
SOURCE_CONTAINER="$(params.source-container)"
CONTAINER_PUSH="$(params.container-push)"
BUILDER_IMAGE="$(params.builder-image)"

echo "=== Reseal Configuration ==="
echo "SOURCE: $SOURCE_CONTAINER"
echo "PUSH TO: ${CONTAINER_PUSH:-<local only>}"
echo "BUILDER: ${BUILDER_IMAGE:-<not specified>}"
echo "============================"

if [ -z "$SOURCE_CONTAINER" ]; then
  echo "Error: source-container is required"
  exit 1
fi

validate_arg "$SOURCE_CONTAINER" "source-container"
validate_arg "$CONTAINER_PUSH" "container-push"
validate_arg "$BUILDER_IMAGE" "builder-image"

# Read seal key from workspace if provided
SEAL_KEY_FILE=""
SEAL_KEY_PASSWORD_OPTS=""
if [ -f "/workspace/seal-key/private-key" ]; then
  SEAL_KEY_FILE="/workspace/seal-key/private-key"
  echo "Using seal key from workspace"
fi

if [ -f "/workspace/seal-key-password/password" ]; then
  SEAL_KEY_PASSWORD=$(cat /workspace/seal-key-password/password)
  SEAL_KEY_PASSWORD_OPTS="pass:$SEAL_KEY_PASSWORD"
  echo "Using seal key password from workspace"
fi

# Build seal key arguments
declare -a SEAL_KEY_ARGS=()
if [ -n "$SEAL_KEY_FILE" ]; then
  SEAL_KEY_ARGS=("--key" "$SEAL_KEY_FILE")
  if [ -n "$SEAL_KEY_PASSWORD_OPTS" ]; then
    SEAL_KEY_ARGS+=("--passwd" "$SEAL_KEY_PASSWORD_OPTS")
  fi
fi

# Output container name
if [ -n "$CONTAINER_PUSH" ]; then
  OUTPUT_CONTAINER="$CONTAINER_PUSH"
else
  OUTPUT_CONTAINER="localhost/resealed:latest"
fi

# Pull the source container
echo "Pulling source container: $SOURCE_CONTAINER"
pull_cmd=(skopeo copy "docker://$SOURCE_CONTAINER" "containers-storage:$SOURCE_CONTAINER")
log_command "${pull_cmd[@]}"
if ! "${pull_cmd[@]}" 2>/dev/null; then
  echo "Public pull failed, trying with auth..."
  pull_auth_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$SOURCE_CONTAINER" "containers-storage:$SOURCE_CONTAINER")
  log_command "${pull_auth_cmd[@]}"
  "${pull_auth_cmd[@]}"
fi

# Build --build-container argument - builder image is required for reseal
declare -a BUILD_CONTAINER_ARGS=()
if [ -n "$BUILDER_IMAGE" ]; then
  BUILD_CONTAINER_ARGS=("--build-container" "$BUILDER_IMAGE")

  # Add auth for builder registry if it's an internal registry
  BUILDER_REGISTRY=""
  if [[ "$BUILDER_IMAGE" == *"/"* ]]; then
    BUILDER_REGISTRY="${BUILDER_IMAGE%%/*}"
  fi

  if [ -n "$BUILDER_REGISTRY" ] && [ "$BUILDER_REGISTRY" != "$REGISTRY" ] && [[ "$BUILDER_REGISTRY" == *"openshift-image-registry"* ]]; then
    echo "Adding serviceaccount auth for builder registry: $BUILDER_REGISTRY"
    if [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ] && [ -n "$REGISTRY_URL" ]; then
      AUTH_STRING=$(echo -n "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64 -w0)
      cat > $HOME/.custom_authjson <<EOF
{
  "auths": {
    "$REGISTRY_URL": {
      "auth": "$AUTH_STRING"
    },
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    },
    "$BUILDER_REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
      export REGISTRY_AUTH_FILE=$HOME/.custom_authjson
    else
      cat > $HOME/.custom_authjson <<EOF
{
  "auths": {
    "$REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    },
    "$BUILDER_REGISTRY": {
      "auth": "$(echo -n "serviceaccount:$TOKEN" | base64 -w0)"
    }
  }
}
EOF
      export REGISTRY_AUTH_FILE=$HOME/.custom_authjson
    fi
  fi
else
  echo "Error: builder-image is required for reseal operations"
  echo "Use --builder-image to specify the osbuild builder container"
  exit 1
fi

echo "Running reseal operation..."

# Pre-pull the builder image to a LOCAL name so AIB's internal podman can use it
# without trying to pull from the registry (which would fail without auth)
LOCAL_BUILDER="localhost/aib-builder:local"
echo "Pulling builder image: $BUILDER_IMAGE -> $LOCAL_BUILDER"
pull_builder_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "docker://$BUILDER_IMAGE" "containers-storage:$LOCAL_BUILDER")
log_command "${pull_builder_cmd[@]}"
if ! "${pull_builder_cmd[@]}" 2>/dev/null; then
  echo "Auth pull failed for builder, trying public pull..."
  pull_builder_public=(skopeo copy "docker://$BUILDER_IMAGE" "containers-storage:$LOCAL_BUILDER")
  log_command "${pull_builder_public[@]}"
  "${pull_builder_public[@]}"
fi

# Update BUILD_CONTAINER_ARGS to use the local name
BUILD_CONTAINER_ARGS=("--build-container" "$LOCAL_BUILDER")

# Run the reseal command
# If no key is provided, aib will generate an ephemeral key
if [ -z "$SEAL_KEY_FILE" ] || [ ! -f "$SEAL_KEY_FILE" ]; then
  echo "No key provided - generating ephemeral key for one-time seal"
  reseal_cmd=(aib --verbose reseal "${BUILD_CONTAINER_ARGS[@]}" "$SOURCE_CONTAINER" "$OUTPUT_CONTAINER")
  log_command "${reseal_cmd[@]}"
  "${reseal_cmd[@]}"
else
  echo "Key provided - running reseal with provided key..."
  reseal_cmd=(aib --verbose reseal "${SEAL_KEY_ARGS[@]}" "${BUILD_CONTAINER_ARGS[@]}" "$SOURCE_CONTAINER" "$OUTPUT_CONTAINER")
  log_command "${reseal_cmd[@]}"
  "${reseal_cmd[@]}"
fi

echo "Reseal operation completed successfully"

# Push resealed container to registry if target is specified
if [ -n "$CONTAINER_PUSH" ]; then
  echo "Pushing resealed container to registry: $CONTAINER_PUSH"
  push_cmd=(skopeo copy --authfile="$REGISTRY_AUTH_FILE" "containers-storage:$OUTPUT_CONTAINER" "docker://$CONTAINER_PUSH")
  log_command "${push_cmd[@]}"
  "${push_cmd[@]}"
  echo "Resealed container pushed successfully to $CONTAINER_PUSH"

  # Write result for Tekton
  echo "$CONTAINER_PUSH" > /tekton/results/sealed-container
fi

echo "Done"
