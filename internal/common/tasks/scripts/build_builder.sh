#!/bin/sh
set -e

echo "Prepare builder for distro: $DISTRO"

# If BUILDER_IMAGE is provided, use it directly
if [ -n "$BUILDER_IMAGE" ]; then
  echo "Using provided builder image: $BUILDER_IMAGE"
  echo -n "$BUILDER_IMAGE" > "$RESULT_PATH"
  exit 0
fi

# Set up cluster registry details
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

if [ -n "$CLUSTER_REGISTRY_ROUTE" ]; then
  echo "Using external registry route: $CLUSTER_REGISTRY_ROUTE"
  REGISTRY="$CLUSTER_REGISTRY_ROUTE"
else
  REGISTRY="image-registry.openshift-image-registry.svc:5000"
fi

TARGET_IMAGE="${REGISTRY}/${NAMESPACE}/aib-build:$DISTRO"

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

# Make internal registry trusted (fallback for internal service)
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << EOF
[registries.insecure]
registries = ['image-registry.openshift-image-registry.svc:5000']
EOF

# Configure fuse-overlayfs for nested container builds
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

# Local image name (what we'll actually use - nested containers can access this)
LOCAL_IMAGE="localhost/aib-build:$DISTRO"

# Check if image already exists in cluster registry
echo "Checking if $TARGET_IMAGE exists in cluster registry..."
if skopeo inspect --authfile="$REGISTRY_AUTH_FILE" "docker://$TARGET_IMAGE" >/dev/null 2>&1; then
  echo "Builder image found in cluster registry: $TARGET_IMAGE"
  echo -n "$TARGET_IMAGE" > "$RESULT_PATH"
  exit 0
fi

echo "Builder image not found, building..."

# Set up SELinux contexts for osbuild
osbuildPath="/usr/bin/osbuild"
storePath="/_build"
runTmp="/run/osbuild/"

mkdir -p "$storePath"
mkdir -p "$runTmp"

rootType="system_u:object_r:root_t:s0"
chcon "$rootType" "$storePath" || true

installType="system_u:object_r:install_exec_t:s0"
if ! mountpoint -q "$runTmp"; then
  mount -t tmpfs tmpfs "$runTmp"
fi

destPath="$runTmp/osbuild"
cp -p "$osbuildPath" "$destPath"
chcon "$installType" "$destPath" || true

mount --bind "$destPath" "$osbuildPath"

echo "Running: aib build-builder --distro $DISTRO"
aib --verbose build-builder --distro "$DISTRO"

echo "Pushing to cluster registry: $TARGET_IMAGE"
skopeo copy --authfile="$REGISTRY_AUTH_FILE" \
  "containers-storage:$LOCAL_IMAGE" \
  "docker://$TARGET_IMAGE"

echo "Builder image ready: $TARGET_IMAGE"
echo -n "$TARGET_IMAGE" > "$RESULT_PATH"
