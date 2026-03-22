#!/bin/bash
set -e

# Create workspace user (UID 1000) for rootless podman
if ! id workspace &>/dev/null; then
  useradd -u 1000 -d /workspace -s /bin/bash workspace
fi
echo 'workspace:1001:64535' > /etc/subuid
echo 'workspace:1001:64535' > /etc/subgid

# Persist dnf-installed packages across pod restarts via overlayfs on PVC
mkdir -p /workspace/.pkg-overlay/{usr-upper,usr-work,rpm-upper,rpm-work,dnf-upper,dnf-work}
{
  mount -t overlay overlay \
    -o lowerdir=/usr,upperdir=/workspace/.pkg-overlay/usr-upper,workdir=/workspace/.pkg-overlay/usr-work /usr
  mount -t overlay overlay \
    -o lowerdir=/var/lib/rpm,upperdir=/workspace/.pkg-overlay/rpm-upper,workdir=/workspace/.pkg-overlay/rpm-work /var/lib/rpm
  mount -t overlay overlay \
    -o lowerdir=/var/lib/dnf,upperdir=/workspace/.pkg-overlay/dnf-upper,workdir=/workspace/.pkg-overlay/dnf-work /var/lib/dnf
} 2>/dev/null || true

# Workspace directories owned by workspace user
mkdir -p /workspace/src /workspace/cache /workspace/.ssh \
         /workspace/.config /workspace/.local/share/containers
chown -R 1000:1000 /workspace/src /workspace/cache /workspace/.ssh \
                   /workspace/.config /workspace/.local

# Generate SSH key for deploy
[ -f /workspace/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -f /workspace/.ssh/id_ed25519 -N '' -q
chown 1000:1000 /workspace/.ssh/id_ed25519 /workspace/.ssh/id_ed25519.pub 2>/dev/null || true

# Set up Jumpstarter client config if available
if [ -f /jumpstarter/client.yaml ]; then
  mkdir -p /workspace/.config/jumpstarter/clients
  cp /jumpstarter/client.yaml /workspace/.config/jumpstarter/clients/workspace.yaml
  chown -R 1000:1000 /workspace/.config
  setpriv --reuid=1000 --regid=1000 --init-groups -- jmp config client use workspace || true
fi

exec sleep infinity
