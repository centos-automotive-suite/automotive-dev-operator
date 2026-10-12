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

Before submission, `caib` attempts to resolve tags using the user's registry
credentials (`--registry-auth-file`, environment credentials, or local registry
auth). Environment credentials are used only when the repository registry matches
their push target registry, or `REGISTRY_URL` when no push target is specified.
It uses a manifest HEAD request with a GET fallback and submits
`ref:tag@digest`, preserving the requested tag. If resolution fails, it warns and
submits the original reference. Already pinned references need no lookup. Short
names without an explicit registry host are submitted unchanged so the cluster's
search registries determine where to pull them.

The Build API validates and preserves this reference without contacting the
repository registry or loading image pull secrets. The kubelet pulls the
repository volume using the node's registry trust, credentials, and mirror
configuration. To select immutable content explicitly, supply a digest reference
such as `quay.io/myorg/my-rpms:v1@sha256:<64 hex characters>`; the tag remains
visible but the digest selects the content.

`status.ociRepoImagesUsed` records the submitted references. If the kubelet reports
the mounted image reference, the controller records that value instead. The
`ImageVolumeWithDigest` feature gate is optional.

Secure builds (including reproducible builds) require OCI repository references
pinned to a SHA-256 digest (`^.+@sha256:[a-fA-F0-9]{64}$`). Both the Build API and
CRD validation enforce this requirement, including `ScheduledImageBuild`
templates. If the CLI cannot resolve a tag, secure submission fails; supply an
explicit digest reference instead.

Locked HTTP(S) RPMs are fetched by Hermeto. Locked local RPMs are handled by the
build task: only `file://` URLs under `/extra-repos/oci-repo/` are accepted. Each
file must resolve to a regular file inside that mount; symlink escapes and
checksum mismatches fail the build. Verified local RPMs are copied into the
osbuild content-addressed store and included in the sources archive. A lockfile
containing only local RPMs skips Hermeto and still produces a CycloneDX SBOM.
The SBOM includes local RPM components with name, version, architecture,
checksum, and the `ado:oci-repo:image` property containing the submitted OCI
repository reference and digest.

Restoring sources verifies both HTTP(S) and local RPM checksums against the
archived store and reuses the archived SBOM. The repository image is not mounted
on restore, so the build does not require that image to remain in the registry.

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

### Secure and reproducible builds

Supply an immutable repository reference for secure builds:

```bash
caib image build manifest.aib.yml \
  --secure --reproducible \
  --local-repo quay.io/myorg/my-rpms:v1@sha256:<64-hex-digest> \
  --push quay.io/myorg/automotive-os:v1
```

Replace `<64-hex-digest>` with the repository image's SHA-256 digest. The same
requirement applies to `--extra-repo oci:` and schedule templates.

### Combining with a Git manifest

Use a Git source for the manifest and an OCI image for application RPMs:

```bash
caib image build images/manifest.aib.yml \
  --git-url https://git.example.com/vehicle/os.git \
  --git-ref main \
  --extra-repo oci:quay.io/myorg/my-rpms:latest \
  --push quay.io/myorg/automotive-os:v1
```

This also works with `build-dev`. Use `--local-repo` instead of
`--extra-repo oci:` when the OCI RPMs should take precedence over network repos.
Git builds still cannot use workspace-served repositories or local file uploads.

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
- The image must be pullable from the build cluster. The kubelet pulls the repo
  image using the build pod's image pull secrets. For a private registry, link a
  pull secret to the `ado-build` service account, or rely on the cluster global
  pull secret. Private CAs and registry mirrors require node registry
  configuration.

## How It Works

1. **CLI** parses `--extra-repo oci:<ref>` or `--local-repo <ref>` and sends the
   OCI image reference to the Build API after attempting client-side digest
   resolution.

2. **Build API** resolves the reference into a DNF `extra_repos` custom
   definition with `baseurl=file:///extra-repos/oci-repo`. If `--local-repo` was
   used, the entry gets `priority: 1`.

3. **Controller** creates the PipelineRun with a volume in the PodTemplate:
   - With an OCI ref: an `ImageVolumeSource` with `pullPolicy: Always`
   - Without, or when restoring sources: an `EmptyDir` placeholder (so the
     volume mount in the Task always resolves)

4. **Tekton Task** has a read-only volume mount at `/extra-repos/oci-repo` on the
   `build-image` step. DNF reads the repo from that path during the osbuild/bootc
   build. For locked prefetch, the task sends only HTTP(S) entries to Hermeto,
   copies and verifies local entries separately, and adds their OCI provenance
   to the SBOM. Restore verification reads the archived store.
