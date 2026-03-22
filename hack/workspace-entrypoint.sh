#!/bin/bash
set -e

# Create workspace user (UID 1000) for rootless podman.
# Must run before /etc overlay so the user exists in the lower dir.
if ! id workspace &>/dev/null; then
  useradd -u 1000 -d /workspace -s /bin/bash workspace
fi

# Persist system changes across pod restarts via overlayfs on PVC.
# Covers /usr (binaries), /etc (configs), /var/lib (package state), /opt.
mkdir -p /workspace/.pkg-overlay/{usr,etc,var-lib,opt}-{upper,work}

# Kubernetes bind-mounts resolv.conf/hostname/hosts into /etc — copy them into
# the overlay upper dir so each restart gets current network config alongside
# any persisted package configs.
for f in resolv.conf hostname hosts; do
  [ -f /etc/$f ] && cp /etc/$f /workspace/.pkg-overlay/etc-upper/$f
done

if ! {
  mount -t overlay overlay \
    -o lowerdir=/usr,upperdir=/workspace/.pkg-overlay/usr-upper,workdir=/workspace/.pkg-overlay/usr-work /usr
  mount -t overlay overlay \
    -o lowerdir=/etc,upperdir=/workspace/.pkg-overlay/etc-upper,workdir=/workspace/.pkg-overlay/etc-work /etc
  mount -t overlay overlay \
    -o lowerdir=/var/lib,upperdir=/workspace/.pkg-overlay/var-lib-upper,workdir=/workspace/.pkg-overlay/var-lib-work /var/lib
  mount -t overlay overlay \
    -o lowerdir=/opt,upperdir=/workspace/.pkg-overlay/opt-upper,workdir=/workspace/.pkg-overlay/opt-work /opt
} 2>/dev/null; then
  echo "WARNING: overlay mounts failed — packages installed with dnf will not persist across workspace restarts" >&2
fi

# Configure subuid/subgid for rootless podman (writes through overlay to PVC)
echo 'workspace:1001:64535' > /etc/subuid
echo 'workspace:1001:64535' > /etc/subgid

# Workspace directories owned by workspace user
mkdir -p /workspace/src /workspace/cache /workspace/.cache /workspace/.ssh \
         /workspace/.config /workspace/.local/share/containers
chown -R 1000:1000 /workspace/src /workspace/cache /workspace/.cache /workspace/.ssh \
                   /workspace/.config /workspace/.local

# Generate SSH key for deploy
[ -f /workspace/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -f /workspace/.ssh/id_ed25519 -N '' -q
chown 1000:1000 /workspace/.ssh/id_ed25519 /workspace/.ssh/id_ed25519.pub 2>/dev/null || true

# Set up Jumpstarter client config if available
if [ -f /jumpstarter/client.yaml ]; then
  mkdir -p /workspace/.config/jumpstarter/clients
  cp /jumpstarter/client.yaml /workspace/.config/jumpstarter/clients/workspace.yaml
  chown -R 1000:1000 /workspace/.config
  jmp config client use workspace || true
fi

exec sleep infinity
