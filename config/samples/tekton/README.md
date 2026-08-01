# Standalone Tekton Pipeline for Automotive Image Builds

Build automotive OS images directly with Tekton Pipelines, without the automotive-dev operator.
Tasks are resolved from a pre-built [Tekton Bundle](https://tekton.dev/docs/pipelines/tekton-bundle-contracts/) OCI image.

## Prerequisites

- OpenShift cluster with Tekton Pipelines installed
- `oc` and `tkn` CLI tools
- A git repository containing an AIB manifest (`.aib.yml` or `.mpp.yml`)

## Quick Start

### 1. Create the Pipeline

```bash
oc apply -f pipeline-git-source.yaml -n <namespace>
```

### 2. (Optional) Set up registry credentials for pushing artifacts

```bash
oc create secret docker-registry push-creds \
  --docker-server=quay.io \
  --docker-username=<username> \
  --docker-password=<token> \
  -n <namespace>
```

### 3. Create a PipelineRun

Edit `pipelinerun-git-source.yaml` to set your values, then:

```bash
oc create -f pipelinerun-git-source.yaml -n <namespace>
```

Or run directly with `tkn`:

```bash
tkn pipeline start automotive-build-from-git \
  -p git-url=https://github.com/centos-automotive-suite/sample-repo.git \
  -p git-revision=main \
  -p task-bundle-ref=quay.io/rh-sdv-cloud/automotive-dev-operator-tekton-tasks:0.1.0 \
  -p distro=autosd \
  -p target=qemu \
  -p arch=x86_64 \
  -w name=shared-workspace,claimSize=30Gi,storageClassName=gp3-csi \
  -n <namespace>
```

### 4. Watch the build

```bash
tkn pipelinerun logs -f -n <namespace>
```

## Pipeline Overview

```text
fetch-manifest ──> build-image ──> push-disk-artifact (conditional)
```

| Task | Description |
|------|-------------|
| `fetch-manifest` | Clones the git repo and copies manifest files to the shared workspace |
| `build-image` | Runs automotive-image-builder to produce a disk image (from Tekton Bundle) |
| `push-disk-artifact` | Pushes the artifact to an OCI registry via oras (skipped if `export-oci` is empty) |

## Parameters

### Required

| Parameter | Description |
|-----------|-------------|
| `git-url` | Git repository URL containing the AIB manifest |
| `task-bundle-ref` | OCI reference to the Tekton Bundle (see [Finding the bundle ref](#finding-the-bundle-ref)) |

### Build Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `git-revision` | `main` | Branch, tag, or commit SHA to checkout |
| `manifest-path` | `.` | Directory within the repo containing the manifest |
| `distro` | `autosd` | Distribution to build |
| `target` | `qemu` | Target platform |
| `arch` | `x86_64` | Target architecture |
| `mode` | `package` | Build mode: `package`, `image`, `bootc`, or `disk` |
| `export-format` | `qcow2` | Disk image format |
| `compression` | `gzip` | Compression algorithm: `gzip`, `xz` |
| `storage-class` | *(empty)* | Storage class for the build PVC |

### Artifact Push (Optional)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `export-oci` | *(empty)* | Registry URL to push the disk image as an OCI artifact |
| `secret-ref` | *(empty)* | Name of a `kubernetes.io/dockerconfigjson` Secret for registry auth |
| `container-push` | *(empty)* | Registry URL to push a bootc container image |
| `build-disk-image` | `false` | Build a disk image from a bootc container |

The `push-disk-artifact` task only runs when both `export-oci` and `secret-ref` are set.

## Finding the Bundle Ref

The Tekton Bundle is published to:

```text
quay.io/rh-sdv-cloud/automotive-dev-operator-tekton-tasks:<version>
```

For reproducible builds, use the digest-pinned reference:

```bash
skopeo inspect docker://quay.io/rh-sdv-cloud/automotive-dev-operator-tekton-tasks:0.1.0 \
  --format '{{.Digest}}'
```

Then use: `quay.io/rh-sdv-cloud/automotive-dev-operator-tekton-tasks@sha256:<digest>`

## Storage Class

The build requires a block-storage PVC (`ReadWriteOnce`).

```yaml
storageClassName: gp3-csi  # AWS EBS
```
