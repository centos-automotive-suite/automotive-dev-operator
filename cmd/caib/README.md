# caib — Cloud Automotive Image Builder CLI

`caib` is a CLI that talks to the Automotive Dev Build API to create, monitor, and download automotive OS image builds.

## Installation

Build from source (requires Go):

```bash
make build-caib
# or
go build -o bin/caib ./cmd/caib
```

## Quick Start

Set the API endpoint (or pass `--server` on every command):

```bash
export CAIB_SERVER=https://your-build-api.example
```

### Build a Bootc Container Image

Build a bootc container and push it to a registry:

```bash
bin/caib image build manifest.aib.yml \
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
bin/caib image build manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive-os:latest \
  --disk \
  --push-disk quay.io/myorg/automotive-disk:latest \
  -o ./output/disk.qcow2
```

### Build a Development (Non-Bootc) Image

Build an ostree-based or package-based disk image for development:

```bash
bin/caib image build-dev manifest.aib.yml \
  --arch arm64 \
  --mode image \
  --format qcow2 \
  -o ./output/disk.qcow2
```

## Commands

All image workflow commands live under `caib image`.

### image build

Builds a bootc container image with optional disk image creation. This is the recommended approach for production.

```bash
bin/caib image build <manifest.aib.yml> [flags]
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
| `--aib-image` | `quay.io/.../automotive-image-builder:1.1.14` | AIB container image |
| `--storage-class` | | Storage class for build workspace PVC |
| `-D`, `--define` | | Custom definition `KEY=VALUE` (repeatable) |
| `--timeout` | `60` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for build to complete |
| `-f`, `--follow` | `true` | Follow build logs |
| `--internal-registry` | `false` | Push to OpenShift internal registry (no credentials needed) |
| `--image-name` | (build name) | Override image name in internal registry |
| `--image-tag` | (build name) | Override tag in internal registry |

**Examples:**

```bash
# Build and push bootc container only
bin/caib image build my-manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive:v1.0

# Build bootc container + qcow2 disk image, download locally
bin/caib image build my-manifest.aib.yml \
  --arch arm64 \
  --push quay.io/myorg/automotive:v1.0 \
  --disk \
  --format qcow2 \
  --push-disk quay.io/myorg/automotive-disk:v1.0 \
  -o ./my-image.qcow2

# Push to OpenShift internal registry (no credentials required)
bin/caib image build my-manifest.aib.yml \
  --arch arm64 \
  --internal-registry

# Internal registry with custom image name and tag
bin/caib image build my-manifest.aib.yml \
  --arch arm64 \
  --internal-registry \
  --image-name my-automotive-os \
  --image-tag v1.0

# Internal registry with disk image
bin/caib image build my-manifest.aib.yml \
  --arch arm64 \
  --internal-registry \
  --disk

# Use custom builder image
bin/caib image build my-manifest.aib.yml \
  --arch amd64 \
  --builder-image quay.io/myorg/my-aib-build:latest \
  --push quay.io/myorg/result:latest
```

### image disk

Creates a disk image from an existing bootc container in a registry.

```bash
bin/caib image disk <container-ref> [flags]
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
| `--aib-image` | `quay.io/.../automotive-image-builder:1.1.14` | AIB container image |
| `--storage-class` | | Kubernetes storage class |
| `--timeout` | `60` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for build to complete |
| `-f`, `--follow` | `true` | Follow build logs |

**Examples:**

```bash
# Create disk image from container, download locally
bin/caib image disk quay.io/myorg/my-os:v1 \
  -o ./disk.qcow2 \
  --format qcow2

# Push disk as OCI artifact instead of downloading
bin/caib image disk quay.io/myorg/my-os:v1 \
  --push quay.io/myorg/my-disk:v1
```

### image build-dev

Builds a disk image (ostree or package-based) for development workflows. Creates standalone disk images without bootc container integration.

```bash
bin/caib image build-dev <manifest.aib.yml> [flags]
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
| `--aib-image` | `quay.io/.../automotive-image-builder:1.1.14` | AIB container image |
| `--storage-class` | | Storage class for build workspace PVC |
| `-D`, `--define` | | Custom definition `KEY=VALUE` (repeatable) |
| `--timeout` | `60` | Timeout in minutes |
| `-w`, `--wait` | `false` | Wait for build to complete |
| `-f`, `--follow` | `true` | Follow build logs |

**Examples:**

```bash
# Build ostree-based image and download
bin/caib image build-dev my-manifest.aib.yml \
  --arch arm64 \
  --mode image \
  --format qcow2 \
  -o ./disk.qcow2

# Build and push to OCI registry (requires REGISTRY_USERNAME/REGISTRY_PASSWORD env vars)
bin/caib image build-dev my-manifest.aib.yml \
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
| `--aib-image` | `quay.io/.../automotive-image-builder:1.1.14` | AIB container image |
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
bin/caib image reseal <source-container> <output-container> [flags]
```

**Examples:**

```bash
# Reseal with ephemeral key
bin/caib image reseal quay.io/myorg/my-os:v1 quay.io/myorg/my-os:resealed

# Reseal with explicit key
bin/caib image reseal quay.io/myorg/my-os:v1 quay.io/myorg/my-os:resealed \
  --key ./seal-key.pem

# Using --input/--output flags instead of positionals
bin/caib image reseal --input quay.io/myorg/my-os:v1 --output quay.io/myorg/my-os:resealed
```

#### prepare-reseal

Prepare a bootc container image for resealing (first step in a two-step seal workflow).

```bash
bin/caib image prepare-reseal <source-container> <output-container> [flags]
```

#### extract-for-signing

Extract components from a container image for external signing (e.g. secure boot).

```bash
bin/caib image extract-for-signing <source-container> <output-artifact> [flags]
```

#### inject-signed

Inject externally signed components back into a container image.

```bash
bin/caib image inject-signed <source-container> <signed-artifact> <output-container> [flags]
```

Additional flag:
| Flag | Description |
|------|-------------|
| `--signed` | Signed artifact ref (alternative to positional) |

### image download

Downloads artifacts from a completed build.

```bash
bin/caib image download <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-o`, `--output` | (required) | Destination file or directory for downloaded artifact |

### image list

Lists existing builds.

```bash
bin/caib image list [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |

### image show

Shows detailed information for a single build, including current status and resolved build parameters.

```bash
bin/caib image show <build-name> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$CAIB_SERVER` | Build API server URL |
| `--token` | `$CAIB_TOKEN` | Bearer token |
| `-o`, `--output` | `table` | Output format: `table`, `json`, `yaml` |

**Examples:**

```bash
# Human-friendly detail view
bin/caib image show my-build

# Machine-readable output
bin/caib image show my-build -o json
bin/caib image show my-build -o yaml
```

## Bootc vs Dev Builds

| Aspect | `build` (bootc) | `build-dev` |
|--------|-----------------|-------------|
| Output | Container image (+ optional disk) | Disk image only |
| Update mechanism | `bootc switch/upgrade` | Requires re-imaging |
| Use case | OTA-updatable systems | Development/standalone disk images |
| Mode | Always `bootc` | `image` or `package` |

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
bin/caib --version
```

## License

Apache-2.0
