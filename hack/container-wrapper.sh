#!/bin/sh
# Wrapper for podman/buildah: auto-switch to workspace user (UID 1000).
# Installed at /usr/local/bin/podman and hard-linked as /usr/local/bin/buildah.
# When invoked as root (via oc exec / caib workspace exec), re-execs as the
# workspace user with ambient capabilities so newuidmap works in the user namespace.
CMD=$(basename "$0")
if [ "$(id -u)" = "0" ]; then
  export HOME=/workspace
  exec setpriv --reuid=1000 --regid=1000 --init-groups \
    --inh-caps=+setuid,+setgid --ambient-caps=+setuid,+setgid \
    -- /usr/bin/$CMD "$@"
fi
exec /usr/bin/$CMD "$@"
