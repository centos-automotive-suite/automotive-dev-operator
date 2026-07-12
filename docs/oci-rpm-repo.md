# Using OCI Images as RPM Repositories

This guide explains how to package RPMs into an OCI image and use it as an extra
(or primary) RPM source during automotive OS image builds.

## Overview

The operator can mount an OCI image containing an RPM repository directly into
the build pod using Kubernetes
[image volumes](https://kubernetes.io/docs/concepts/storage/volumes/#image).
The RPMs inside the image are exposed to the build as a local `file://` DNF
repository — no HTTP server, no sidecar, no network transfer at build time.

Two CLI flags control this:

| Flag | Purpose | DNF priority |
|------|---------|-------------|
| `--extra-repo oci:<ref>` | Add RPMs as a supplementary repo | Default (99) — network repos take precedence |
| `--local-repo <ref>` | Add RPMs as the *primary* repo | 1 — prefers local RPMs over network |

Both flags accept an OCI image reference (e.g. `quay.io/myorg/my-rpms:latest`).

## Step 1: Download RPMs and Build the OCI Image

Use AIB's `download` command to resolve your manifest and fetch all RPMs, then
package them into an OCI image.

```bash
# 1. Download all RPMs for the manifest
./auto-image-builder.sh -d download \
  --distro autosd \
  --build-dir _build \
  manifest.aib.yml

# 2. Build the OCI repo image
podman build -t quay.io/myorg/my-rpms:latest -f Containerfile _build/

# 3. Push to registry
podman push quay.io/myorg/my-rpms:latest
```

### Containerfile

```dockerfile
FROM quay.io/centos/centos:stream9 AS builder

RUN dnf install -y createrepo_c && dnf clean all

WORKDIR /rpms
COPY osbuild_store/sources/org.osbuild.files/ .
RUN for f in sha256:*; do mv "$f" "${f#sha256:}.rpm"; done 2>/dev/null; \
    for f in *.rpm; do rpm -qp "$f" >/dev/null 2>&1 || rm -f "$f"; done; \
    createrepo_c .

FROM scratch
COPY --from=builder /rpms/ /
```

AIB downloads files into an osbuild content-addressed store
(`osbuild_store/sources/org.osbuild.files/sha256:*`). The blobs are mostly RPMs
but include GPG keys and other metadata. The rename step strips the `sha256:`
prefix and adds `.rpm` extension (`createrepo_c` requires it). The `rpm -qp`
filter then removes non-RPM files before indexing.

## Step 2: Use in a Build

### As an extra repo (supplementary RPMs)

Use `--extra-repo oci:` when you want the RPMs available alongside the standard
distro repos. Network repos still take precedence for packages available in both:

```bash
caib image build manifest.aib.yml \
  --extra-repo oci:quay.io/myorg/my-rpms:latest \
  --push quay.io/myorg/automotive-os:v1

# Works with build-dev too
caib image build-dev manifest.aib.yml \
  --mode image --format qcow2 \
  --extra-repo oci:quay.io/myorg/my-rpms:latest \
  -o ./disk.qcow2
```

### As a local repo (primary RPM source)

Use `--local-repo` when you want the OCI RPMs to take precedence over network
repos. This sets DNF priority to 1 (lowest number = highest preference):

```bash
caib image build manifest.aib.yml \
  --local-repo quay.io/myorg/my-rpms:latest \
  --push quay.io/myorg/automotive-os:v1
```

Note: `--local-repo` does not need the `oci:` prefix.

### Combining with workspace repos

OCI repos can be combined with workspace-served repos in the same build:

```bash
caib image build-dev manifest.aib.yml \
  --mode image --format qcow2 \
  --extra-repo my-ws:/path/to/rpms \
  --extra-repo oci:quay.io/myorg/my-rpms:latest \
  -o ./disk.qcow2
```

### Constraints

- Only one OCI repo image is supported per build. Multiple `--extra-repo oci:`
  entries will be rejected.
- `--local-repo` and `--extra-repo oci:` are mutually exclusive.
- The image must be pullable from the build cluster. If using a private registry,
  configure an image pull secret on the namespace.

## How It Works

1. **CLI** parses `--extra-repo oci:<ref>` or `--local-repo <ref>` and sends the
   OCI image reference to the Build API.

2. **Build API** resolves the reference into a DNF `extra_repos` custom
   definition with `baseurl=file:///extra-repos/oci-repo`. If `--local-repo` was
   used, the entry gets `priority: 1`.

3. **Controller** creates the PipelineRun with a volume in the PodTemplate:
   - With an OCI ref: an `ImageVolumeSource` with `pullPolicy: Always`
   - Without: an `EmptyDir` placeholder (so the volume mount in the Task always
     resolves)

4. **Tekton Task** has a read-only volume mount at `/extra-repos/oci-repo` on the
   `build-image` step. DNF reads the repo from that path during the osbuild/bootc
   build.
