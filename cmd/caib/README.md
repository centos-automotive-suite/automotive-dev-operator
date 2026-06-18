# caib — Cloud Automotive Image Builder CLI

`caib` is a CLI that talks to the Automotive Dev Build API to create, monitor, and download automotive OS image builds.

## Installation

Build from source (requires Go):

```bash
make build-caib
```

## Quick Start

Set the API endpoint (or pass `--server` on every command):

```bash
export CAIB_SERVER=https://your-build-api.example
```

Alternatively, use `caib login` to save the server URL and authenticate via OIDC:

```bash
# Explicit server URL
caib login https://build-api.my-cluster.example.com

# Auto-derive from Jumpstarter config (if available)
caib login
```

Check server connectivity:

```bash
caib status
```

### Build a Bootc Container Image

Build a bootc container and push it to a registry:

```bash
caib image build manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive-os:latest
```

Systems running bootc can then switch to this image:

```bash
bootc switch quay.io/myorg/automotive-os:latest
```

### Build a Bootc Disk Image

Build a bootc container and also create a disk image from it:

```bash
caib image build manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive-os:latest \
  --disk \
  --push-disk quay.io/myorg/automotive-disk:latest \
  -o ./output/disk.qcow2
```

### Build a Development (Non-Bootc) Image

Build an ostree-based or package-based disk image for development:

```bash
caib image build-dev manifest.aib.yml \
  --arch arm64 \
  --mode image \
  --format qcow2 \
  -o ./output/disk.qcow2
```

## Flag Inference

Many flags are automatically inferred from context:

| Flag | Inferred from |
|------|---------------|
| `--server` | `CAIB_SERVER` env → saved config (`caib login`) → Jumpstarter client config |
| `--token` | `CAIB_TOKEN` env → kubeconfig (`oc login`) → `oc whoami -t` |
| `--arch` | `--target` lookup in OperatorConfig target defaults → host architecture |
| `--format` | `--target` lookup in OperatorConfig target defaults → `-o` filename extension |
| `--disk` | Implied by `-o`, `--push-disk`, or `--flash` |
| `--client` | Auto-detected from `~/.config/jumpstarter/` |
| `--extra-args` | Prepended from OperatorConfig target defaults (user args appended) |
| `--follow` | Defaults to `true` for build commands, `false` for flash |
| `--wait` | Defaults to `false` for build commands, `true` for flash and workspace |

For example, `--target ride4_sa8775p_sx_r3` automatically sets `--arch arm64`, `--format simg`, and adds `--separate-partitions` to extra-args. Explicitly setting a flag always overrides the inferred value.

## Commands

All image workflow commands live under `caib image`.

### image build

Builds a bootc container image with optional disk image creation. This is the recommended approach for production.

```bash
caib image build <manifest.aib.yml> [flags]
```

**Required flags:**
| Flag | Description |
|------|-------------|
| `--push` or `--internal-registry` | Push destination (external registry URL or OpenShift internal registry) |

**Optional flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token (auto-detected from kubeconfig) |
| `-n`, `--name` | (auto-generated) | Unique build name |
| `-d`, `--distro` | `autosd` | Distribution to build |
| `-t`, `--target` | `qemu` | Target platform |
| `-a`, `--arch` | (current system) | Architecture (`amd64`, `arm64`) |
| `--disk` | `false` | Also build a disk image from the container |
| `--format` | (inferred from `-o`) | Disk image format (`qcow2`, `raw`, `simg`) |
| `--compress` | `gzip` | Compression algorithm (`gzip`, `lz4`, `xz`) |
| `--push-disk` | | Push disk image as OCI artifact to registry |
| `-o`, `--output` | | Download disk image to local file (implies `--disk`) |
| `--builder-image` | | Custom aib-build container |
| `--aib-image` | `quay.io/.../automotive-image-builder:1.3.2` | AIB container image |
| `-D`, `--define` | | Custom definition `KEY=VALUE` (repeatable) |
| `--timeout` | `60` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for build to complete |
| `-f`, `--follow` | `true` | Follow build logs |
| `--internal-registry` | `false` | Push to OpenShift internal registry (no credentials needed) |
| `--image-name` | (build name) | Override image name in internal registry |
| `--image-tag` | (build name) | Override tag in internal registry |
| `--flash` | `false` | Flash image to device after build completes (via Jumpstarter) |
| `--client` | (auto-detected) | Path to Jumpstarter client config file |
| `--exporter` | | Direct exporter selector (alternative to `--target` lookup) |
| `--flash-cmd` | | Override flash command (default: from OperatorConfig target mapping) |
| `--lease-duration` | `03:00:00` | Device lease duration for flash (HH:MM:SS) |
| `--lease` | | Existing Jumpstarter lease name (mutually exclusive with `--lease-duration`) |
| `--secure` | `false` | Resolve tasks from signed Tekton Bundle (requires OperatorConfig `taskBundleRef`) |
| `--reproducible` | `false` | Save RPMs, manifest, and task bundle as OCI referrers for future reproduction (requires `--secure`) |
| `--task-bundle-ref` | | Digest-pinned Tekton bundle ref for reproducible rebuild (e.g. `quay.io/org/tasks@sha256:abc...`) |
| `--restore-sources` | | OCI image ref from prior build — restores archived sources for exact reproducible rebuild |
| `--ttl` | | Time-to-live for the build (e.g. `24h`, `72h`; empty=server default, `0`=no expiry) |

**Examples:**

```bash
# Build and push bootc container only
caib image build my-manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive:v1.0

# Build bootc container + qcow2 disk image, download locally
caib image build my-manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive:v1.0 \
  --disk \
  --format qcow2 \
  --push-disk quay.io/myorg/automotive-disk:v1.0 \
  -o ./my-image.qcow2

# Push to OpenShift internal registry (no credentials required)
caib image build my-manifest.aib.yml \
  --arch arm64 \
  --internal-registry

# Internal registry with custom image name and tag
caib image build my-manifest.aib.yml \
  --arch arm64 \
  --internal-registry \
  --image-name my-automotive-os \
  --image-tag v1.0

# Internal registry with disk image
caib image build my-manifest.aib.yml \
  --arch arm64 \
  --internal-registry \
  --disk

# Use custom builder image
caib image build my-manifest.aib.yml \
  --arch amd64 \
  --builder-image quay.io/myorg/my-aib-build:latest \
  --push quay.io/myorg/result:latest
```

### image disk

Creates a disk image from an existing bootc container in a registry.

```bash
caib image disk <container-ref> [flags]
```

**Optional flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-n`, `--name` | (auto-generated) | Build job name |
| `-o`, `--output` | | Download disk image to local file |
| `--format` | (inferred from `-o`) | Disk image format (`qcow2`, `raw`, `simg`) |
| `--compress` | `gzip` | Compression algorithm (`gzip`, `lz4`, `xz`) |
| `--push` | | Push disk image as OCI artifact to registry |
| `-d`, `--distro` | `autosd` | Distribution |
| `-t`, `--target` | `qemu` | Target platform |
| `-a`, `--arch` | (current system) | Architecture (`amd64`, `arm64`) |
| `--aib-image` | `quay.io/.../automotive-image-builder:1.3.2` | AIB container image |
| `--extra-args` | | Extra arguments to pass to AIB (repeatable) |
| `--timeout` | `60` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for build to complete |
| `-f`, `--follow` | `true` | Follow build logs |
| `--flash` | `false` | Flash image to device after build completes (via Jumpstarter) |
| `--client` | (auto-detected) | Path to Jumpstarter client config file |
| `--exporter` | | Direct exporter selector (alternative to `--target` lookup) |
| `--flash-cmd` | | Override flash command (default: from OperatorConfig target mapping) |
| `--lease-duration` | `03:00:00` | Device lease duration for flash (HH:MM:SS) |
| `--lease` | | Existing Jumpstarter lease name (mutually exclusive with `--lease-duration`) |
| `--secure` | `false` | Resolve tasks from signed Tekton Bundle (requires OperatorConfig `taskBundleRef`) |
| `--task-bundle-ref` | | Digest-pinned Tekton bundle ref for reproducible rebuild (e.g. `quay.io/org/tasks@sha256:abc...`) |
| `--ttl` | | Time-to-live for the build (e.g. `24h`, `72h`) |
| `--internal-registry` | `false` | Push to OpenShift internal registry |
| `--image-name` | (build name) | Override image name in internal registry |
| `--image-tag` | `disk` | Override tag in internal registry |

> **Note:** `--reproducible` and `--restore-sources` are not supported by `image disk`. This command creates a disk image from an existing container rather than performing a full build, so source archival and reproducibility tracking do not apply. Use `image build` or `image build-dev` for reproducible builds.

**Examples:**

```bash
# Create disk image from container, download locally
caib image disk quay.io/myorg/my-os:v1 \
  -o ./disk.qcow2 \
  --format qcow2

# Push disk as OCI artifact instead of downloading
caib image disk quay.io/myorg/my-os:v1 \
  --push quay.io/myorg/my-disk:v1
```

### image build-dev

Builds a disk image (ostree or package-based) for development workflows. Creates standalone disk images without bootc container integration.

```bash
caib image build-dev <manifest.aib.yml> [flags]
```

**Required flags:**
| Flag | Description |
|------|-------------|
| `--mode` | Build mode: `image` (ostree) or `package` |
| `--format` | Export format: `qcow2`, `raw`, `simg`, etc. |

**Optional flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token (auto-detected from kubeconfig) |
| `-n`, `--name` | | Unique build name |
| `-d`, `--distro` | `autosd` | Distribution to build |
| `-t`, `--target` | `qemu` | Target platform |
| `-a`, `--arch` | (current system) | Architecture (`amd64`, `arm64`) |
| `--compress` | `gzip` | Compression algorithm (`gzip`, `lz4`, `xz`) |
| `--push` | | Push disk image as OCI artifact to registry |
| `-o`, `--output` | | Download artifact to local file |
| `--aib-image` | `quay.io/.../automotive-image-builder:1.3.2` | AIB container image |
| `-D`, `--define` | | Custom definition `KEY=VALUE` (repeatable) |
| `--define-file` | | Load defines from YAML dictionary file (repeatable) |
| `--extra-args` | | Extra arguments to pass to AIB (repeatable) |
| `--extra-repo` | | Serve RPMs from workspace as extra repo (`workspace:path`, repeatable) |
| `--workspace` | | Workspace name for build caching and lease forwarding |
| `--timeout` | `60` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for build to complete |
| `-f`, `--follow` | `true` | Follow build logs |
| `--flash` | `false` | Flash image to device after build completes (via Jumpstarter) |
| `--client` | (auto-detected) | Path to Jumpstarter client config file |
| `--exporter` | | Direct exporter selector (alternative to `--target` lookup) |
| `--flash-cmd` | | Override flash command (default: from OperatorConfig target mapping) |
| `--lease-duration` | `03:00:00` | Device lease duration for flash (HH:MM:SS) |
| `--lease` | | Existing Jumpstarter lease name (mutually exclusive with `--lease-duration`) |
| `--secure` | `false` | Resolve tasks from signed Tekton Bundle (requires OperatorConfig `taskBundleRef`) |
| `--reproducible` | `false` | Save RPMs, manifest, and task bundle as OCI referrers for future reproduction (requires `--secure`) |
| `--task-bundle-ref` | | Digest-pinned Tekton bundle ref for reproducible rebuild (e.g. `quay.io/org/tasks@sha256:abc...`) |
| `--restore-sources` | | OCI image ref from prior build — restores archived sources for exact reproducible rebuild |
| `--ttl` | | Time-to-live for the build (e.g. `24h`, `72h`) |
| `--internal-registry` | `false` | Push to OpenShift internal registry |
| `--image-name` | (build name) | Override image name in internal registry |
| `--image-tag` | `disk` | Override tag in internal registry |

**Examples:**

```bash
# Build ostree-based image and download
caib image build-dev my-manifest.aib.yml \
  --arch arm64 \
  --mode image \
  --format qcow2 \
  -o ./disk.qcow2

# Build and push to OCI registry (requires REGISTRY_USERNAME/REGISTRY_PASSWORD env vars)
caib image build-dev my-manifest.aib.yml \
  --arch arm64 \
  --mode image \
  --format qcow2 \
  --push quay.io/myorg/disk-image:v1.0
```

### image reseal / prepare-reseal / extract-for-signing / inject-signed

Sealed operations manage TPM-based image sealing for secure boot workflows. All sealed commands share a common set of flags.

**Shared flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `--input` | | Input/source container ref (alternative to positional) |
| `--output` | | Output container ref (alternative to positional) |
| `--aib-image` | `quay.io/.../automotive-image-builder:1.3.2` | AIB container image |
| `--builder-image` | | Builder container image (overrides `--arch` default) |
| `--arch` | (auto-detected) | Target architecture (`amd64`, `arm64`) |
| `--key` | | Path to local PEM key file |
| `--passwd` | | Password for encrypted key file |
| `--key-secret` | | Name of cluster secret containing sealing key |
| `--key-password-secret` | | Name of cluster secret containing key password |
| `--registry-auth-file` | | Path to Docker/Podman auth file for registry authentication |
| `--extra-args` | | Extra arguments to pass to AIB (repeatable) |
| `--timeout` | `120` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for completion |
| `-f`, `--follow` | `true` | Stream task logs |

#### reseal

Reseal a bootc container image with a new TPM key. If no key is provided, an ephemeral key is generated.

```bash
caib image reseal <source-container> <output-container> [flags]
```

**Examples:**

```bash
# Reseal with ephemeral key
caib image reseal quay.io/myorg/my-os:v1 quay.io/myorg/my-os:resealed

# Reseal with explicit key
caib image reseal quay.io/myorg/my-os:v1 quay.io/myorg/my-os:resealed \
  --key ./seal-key.pem

# Using --input/--output flags instead of positionals
caib image reseal --input quay.io/myorg/my-os:v1 --output quay.io/myorg/my-os:resealed
```

#### prepare-reseal

Prepare a bootc container image for resealing (first step in a two-step seal workflow).

```bash
caib image prepare-reseal <source-container> <output-container> [flags]
```

#### extract-for-signing

Extract components from a container image for external signing (e.g. secure boot).

```bash
caib image extract-for-signing <source-container> <output-artifact> [flags]
```

#### inject-signed

Inject externally signed components back into a container image.

```bash
caib image inject-signed <source-container> <signed-artifact> <output-container> [flags]
```

Additional flag:
| Flag | Description |
|------|-------------|
| `--signed` | Signed artifact ref (alternative to positional) |

### image download

Downloads artifacts from a completed build.

```bash
caib image download <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-o`, `--output` | (required) | Destination file or directory for downloaded artifact |

### image list

Lists existing builds.

```bash
caib image list [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |

### image show

Shows detailed information for a single build, including current status and resolved build parameters.

```bash
caib image show <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-o`, `--output` | `table` | Output format: `table`, `json`, `yaml` |

**Examples:**

```bash
# Human-friendly detail view
caib image show my-build

# Machine-readable output
caib image show my-build -o json
caib image show my-build -o yaml
```

### image flash

Flash a disk image from an OCI registry to a hardware device using Jumpstarter.

```bash
caib image flash <oci-registry-reference> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-n`, `--name` | (auto-generated) | Name for the flash job |
| `-t`, `--target` | | Target platform for exporter lookup |
| `--client` | (auto-detected) | Path to Jumpstarter client config file |
| `--exporter` | | Direct exporter selector (alternative to `--target`) |
| `--flash-cmd` | | Override flash command (default: from OperatorConfig target mapping) |
| `--lease-duration` | `03:00:00` | Device lease duration (HH:MM:SS) |
| `--lease` | | Existing Jumpstarter lease name (mutually exclusive with `--lease-duration`) |
| `--registry-auth-file` | | Path to Docker/Podman auth file for OCI image pull |
| `-f`, `--follow` | `false` | Follow flash logs |
| `-w`, `--wait` | `true` | Wait for flash to complete |

**Examples:**

```bash
# Flash using auto-detected client config
caib image flash quay.io/org/disk:v1 --target j784s4evm

# Flash with explicit client config
caib image flash quay.io/org/disk:v1 --client ~/.jumpstarter/client.yaml --target j784s4evm

# Flash with explicit exporter selector
caib image flash quay.io/org/disk:v1 --exporter "board-type=j784s4evm"
```

### image logs

Follow the log output of an active or completed build. Useful when reconnecting after restarting your terminal.

```bash
caib image logs <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |

### image inspect

Show build provenance and reproducibility info for an OCI artifact. Reads manifest annotations and OCI referrers to display the exact build parameters and a command to reproduce the build.

```bash
caib image inspect <oci-registry-reference> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--registry-auth-file` | | Path to Docker/Podman auth file for registry authentication |
| `-o`, `--output-dir` | | Download referrer artifacts (manifest, RPMs, osbuild manifest) to this directory |

Discovered referrer types:

| Artifact Type | Description |
|---------------|-------------|
| `application/vnd.automotive.manifest.v1+yaml` | Original AIB manifest used for the build |
| `application/vnd.automotive.sources.v1+tar+gzip` | Archived RPMs and build inputs |
| `application/vnd.osbuild.manifest.v1+json` | Resolved osbuild manifest |

**Examples:**

```bash
# Show build provenance
caib image inspect quay.io/org/my-os:v1

# Show provenance and download artifacts for reproduction
caib image inspect quay.io/org/my-os:v1 -o ./rebuild/

# Inspect with explicit auth file
caib image inspect quay.io/org/my-os:v1 --registry-auth-file ~/.config/containers/auth.json
```

### image token

Request a fresh, short-lived registry token (valid ~4 hours) for a completed build that used `--internal-registry`. Can be used with podman, skopeo, or any OCI-compatible tool.

```bash
caib image token <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |

### image delete

Delete an ImageBuild and all its associated resources (PipelineRuns, TaskRuns, PVCs, Secrets). If the build used `--internal-registry`, ImageStream tags are removed. You can only delete builds that you created.

```bash
caib image delete <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |

### image cancel

Cancel an in-progress build. Only builds in Pending, Uploading, or Building phase can be cancelled. You can only cancel builds that you created.

```bash
caib image cancel <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |

## Bootc vs Dev Builds

| Aspect | `build` (bootc) | `build-dev` |
|--------|-----------------|-------------|
| Output | Container image (+ optional disk) | Disk image only |
| Update mechanism | `bootc switch/upgrade` | Requires re-imaging |
| Use case | OTA-updatable systems | Development/standalone disk images |
| Mode | Always `bootc` | `image` or `package` |

## Secure & Reproducible Builds

The `--secure` and `--reproducible` flags enable supply-chain security and build reproducibility.

### Secure builds (`--secure`)

When `--secure` is set, the build resolves Tekton tasks from a digest-pinned, cosign-signed bundle instead of using the operator's default tasks. This ensures the build pipeline itself is verified and tamper-proof.

**Requirements:**
- OperatorConfig must have `osBuilds.taskBundleRef` set to a digest-pinned bundle (e.g. `quay.io/org/tasks@sha256:...`)
- If `osBuilds.taskBundleVerify` is `true`, a cosign public key must be configured via `osBuilds.taskBundleCosignKeyRef` (a ConfigMap key reference)

**OperatorConfig setup:**

```yaml
apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: OperatorConfig
metadata:
  name: config
spec:
  osBuilds:
    taskBundleRef: "quay.io/centos-automotive-suite/automotive-dev-operator-bundle@sha256:..."
    taskBundleVerify: true
    taskBundleCosignKeyRef:
      name: cosign-public-key    # ConfigMap name
      key: cosign.pub            # Key within the ConfigMap
```

Create the ConfigMap with your cosign public key:

```bash
kubectl create configmap cosign-public-key \
  --from-file=cosign.pub=hack/cosign.pub
```

### Reproducible builds (`--reproducible`)

When `--reproducible` is set (requires `--secure`), the build archives its inputs as OCI referrer artifacts alongside the output image:

- **AIB manifest** — the exact manifest used
- **Build sources** — RPMs and other inputs (tar.gz)
- **osbuild manifest** — the resolved osbuild pipeline definition

These artifacts enable exact rebuild reproduction. Use `caib image inspect` to view them and get a rebuild command.

### Rebuilding from a previous build

```bash
# 1. Download the manifest and metadata for local inspection
caib image inspect quay.io/org/my-os:v1 -o ./rebuild/

# 2. Rebuild using the downloaded manifest; --restore-sources tells the build
#    to fetch archived RPMs/inputs from the OCI registry at build time
caib image build ./rebuild/manifest.aib.yml \
  --secure \
  --reproducible \
  --task-bundle-ref quay.io/org/tasks@sha256:abc... \
  --restore-sources quay.io/org/my-os:v1@sha256:def... \
  --push quay.io/org/my-os:v2
```

Key flags for reproduction:
- `--task-bundle-ref` pins the exact Tekton bundle used in the original build
- `--restore-sources` tells the build to fetch archived RPMs and inputs from the original build's OCI referrers at build time (the build pod pulls from the registry, not from your local download)

## Authentication

The CLI automatically detects authentication in this order:

1. `--token` flag
2. `CAIB_TOKEN` environment variable
3. Bearer token from kubeconfig (OpenShift `oc login`, exec plugins)
4. `oc whoami -t` command (if `oc` is available)

For registry authentication (`--push`, `--push-disk`, sealed operations):

1. `--registry-auth-file` flag — explicit path to a Docker/Podman auth file (highest priority)
2. `REGISTRY_USERNAME` / `REGISTRY_PASSWORD` environment variables
3. Auto-discovery of auth files from standard locations:
   - `$REGISTRY_AUTH_FILE` environment variable
   - `$XDG_RUNTIME_DIR/containers/auth.json`
   - `/run/containers/<uid>/auth.json`
   - `~/.config/containers/auth.json`

For the OpenShift internal registry (`--internal-registry`):

No credentials are needed. The system automatically creates a short-lived service account token for the `pipeline` SA and uses it to authenticate to the internal registry. The `pipeline` SA must have `registry-editor` permissions (applied automatically by the operator's RBAC).

## Manifest File References

The CLI automatically handles local file references in manifests. Relative paths in `source_path` are uploaded to the build workspace.

```yaml
content:
  add_files:
    - path: /etc/myapp/config.yaml
      source_path: files/config.yaml  # Local file, uploaded automatically
```

Supported locations:
- `content.add_files[].source_path`
- `qm.content.add_files[].source_path`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CAIB_SERVER` | Build API base URL (equivalent to `--server`) |
| `CAIB_TOKEN` | Bearer token (equivalent to `--token`) |
| `REGISTRY_USERNAME` | Registry username for push operations |
| `REGISTRY_PASSWORD` | Registry password for push operations |
| `REGISTRY_AUTH_FILE` | Path to Docker/Podman auth file (auto-discovery candidate) |
| `CAIB_SKIP_MANIFEST_VALIDATION` | Skip local manifest schema validation when set to any value |

## Timeouts and Retries

- **Upload readiness**: Waits up to 10 minutes for the upload pod
- **Log following**: Retries on 503/504 while build pod starts
- **Build wait**: Controlled by `--timeout` (default 60 minutes)
- **Artifact download**: Waits up to 30 minutes for artifact availability

## Exit Codes

- `0`: Success
- Non-zero: Validation errors, upload failures, or build failure

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| "upload pod not ready" | Upload pod starting | CLI retries automatically |
| HTTP 503/504 during log follow | Build pod starting | CLI retries automatically |
| Build fails after upload | PVC transition timing | Increase `--timeout`, check operator logs |
| "no bearer token found" | Not logged in | Run `oc login` or set `CAIB_TOKEN` |
| Registry auth failure | Missing credentials | Run `podman login`, set `REGISTRY_USERNAME/REGISTRY_PASSWORD` env vars, or use `--registry-auth-file` |

## Version

```bash
caib --version
```

## Auth Commands

### auth status

Display token status and expiry information.

```bash
caib auth status [--verbose]
```

With `--verbose`, shows additional details (issued-at, auth-time, refresh token presence).

### auth refresh

Refresh the access token using a stored refresh token.

```bash
caib auth refresh
```

## Workspace Commands

Create and manage persistent developer workspaces with cross-compilation toolchains for building C/C++/Rust applications targeting automotive boards.

### workspace create

```bash
caib workspace create <name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--from-build` | | ImageBuild name to extract Jumpstarter lease from |
| `--lease` | | Direct Jumpstarter lease ID |
| `-a`, `--arch` | (from OperatorConfig) | Target architecture |
| `--image` | (from OperatorConfig) | Toolchain container image |
| `--client` | | Path to Jumpstarter client config file |
| `--cpu` | | CPU request/limit (e.g. `1`, `500m`) |
| `--memory` | | Memory request/limit (e.g. `2Gi`, `512Mi`) |
| `--tmpfs` | `false` | Mount tmpfs at /tmp/build for faster compilation (uses RAM) |
| `--auto-pause-timeout` | `-1` | Auto-pause timeout in minutes (`0`=disable, `-1`=global default) |
| `-w`, `--wait` | `true` | Wait for workspace to be running |

**Examples:**

```bash
# Basic workspace
caib workspace create my-app

# Workspace linked to a flashed board
caib workspace create my-app --from-build my-os-build

# Workspace with explicit lease
caib workspace create my-app --lease lease-abc123 --arch arm64
```

### workspace list

```bash
caib workspace list
```

### workspace show

```bash
caib workspace show <name>
```

### workspace delete

```bash
caib workspace delete <name>
```

### workspace start

Start a previously stopped workspace (persistent storage is preserved).

```bash
caib workspace start <name> [-w]
```

### workspace stop

Stop a workspace without deleting its storage. Frees cluster resources.

```bash
caib workspace stop <name>
```

### workspace sync

Upload a local directory to the workspace's `/workspace/src/` path. Only git-tracked files are synced, with delta support (only changed files are uploaded).

```bash
caib workspace sync <name> [directory]
```

If no directory is specified, the current directory is used.

### workspace exec

Execute a command in the workspace pod. Everything after `--` is the command.

```bash
caib workspace exec <name> -- <command...>
```

**Examples:**

```bash
caib workspace exec my-app -- make -j4
caib workspace exec my-app -- cargo build --release
```

### workspace shell

Open an interactive shell session in the workspace pod.

```bash
caib workspace shell <name>
```

### workspace deploy

Deploy artifacts from the workspace to a board via the workspace's Jumpstarter lease. Uses rsync for delta transfer.

```bash
caib workspace deploy <name> --artifact <src:dest> [--artifact ...]
```

**Examples:**

```bash
# Single file
caib workspace deploy my-app --artifact /workspace/src/build/app:/usr/local/bin/app

# Multiple files
caib workspace deploy my-app \
  --artifact /workspace/src/engine-service:/usr/local/bin/engine-service \
  --artifact /workspace/src/radio-service:/usr/local/bin/radio-service
```

## Container Commands

Build container images on-cluster using Shipwright (OpenShift Builds).

### container build

```bash
caib container build [context-dir] [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-n`, `--name` | (auto-generated) | Build name |
| `-f`, `--containerfile` | (required) | Path to Containerfile or Dockerfile |
| `--push` | | Push destination registry URL (required unless `--internal-registry`) |
| `--strategy` | `buildah` | Shipwright build strategy name |
| `--build-arg` | | Build argument `KEY=VALUE` (repeatable) |
| `-a`, `--arch` | (current system) | Target architecture (`amd64`, `arm64`) |
| `--timeout` | `30` | Build timeout in minutes |
| `--registry-auth-file` | | Path to Docker/Podman auth file |
| `--internal-registry` | `false` | Push to OpenShift internal registry |

**Examples:**

```bash
# Build from current directory
caib container build -f Containerfile --push quay.io/myorg/myimage:latest

# Build with build args
caib container build -f Containerfile --push quay.io/myorg/myimage:latest \
  --build-arg VERSION=1.0 --build-arg ENV=prod

# Push to internal registry
caib container build -f Containerfile --internal-registry
```

### container logs

Follow logs of a container build.

```bash
caib container logs <build-name>
```
