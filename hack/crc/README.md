# CRC Setup & Operator Deployment

Automated scripts to install [OpenShift Local (CRC)](https://developers.redhat.com/products/openshift-local/overview), deploy the Automotive Dev Operator, and validate the deployment on **Linux** and **macOS**.

CRC version: **2.58.0** (configurable via `CRC_VERSION`)

## Prerequisites

1. **Pull secret** -- download from [console.redhat.com/openshift/create/local](https://console.redhat.com/openshift/create/local).
2. **Hardware virtualisation** -- VT-x / AMD-V (Linux) or Hypervisor.framework (macOS).
3. **CRC minimum resources** ([OpenShift preset](https://crc.dev/docs/installing/#_for_openshift_container_platform)):

| Resource | CRC minimum | This project |
|----------|-------------|--------------|
| CPU | 4 physical cores | 4 cores (`CRC_CPUS=4`) |
| Memory | 10.5 GB free | 12 GB (`CRC_MEMORY=12288`) |
| Disk | 35 GB | 90 GB (`DISK_SIZE=90`) |

The higher memory and disk values are needed for in-cluster operator builds and automotive image builds.

## Scripts

| Script | Run as | Purpose |
|--------|--------|---------|
| `setup-crc.sh` | root (Linux) / user (macOS) | All-in-one: runs 01, 02, 03 in sequence with correct user switching |
| `01-prep-host.sh` | root (Linux) / user (macOS) | System prep: packages, libvirt, Go, kubectl, CRC install, `crc setup`, `crc start` |
| `02-deploy-operator.sh` | non-root (e.g. `developer`) | Build operator in-cluster, deploy via `make deploy`, configure OperatorConfig |
| `03-crc-operator-sanity.sh` | non-root | Sanity checks: cluster, operator, Build API, Tekton tasks, pipelines. `--sanity` for build test |
| `crc-cleanup.sh` | root (Linux) / user (macOS) | Stop and delete CRC VM. `--full` removes binary, user, home directory, cache |

## Quick Start

### One command (recommended)

**Linux:**
```bash
sudo bash hack/crc/setup-crc.sh /path/to/pull-secret.txt
```

**macOS:**
```bash
bash hack/crc/setup-crc.sh /path/to/pull-secret.txt
```

With end-to-end build test:
```bash
sudo bash hack/crc/setup-crc.sh /path/to/pull-secret.txt --sanity    # Linux
bash hack/crc/setup-crc.sh /path/to/pull-secret.txt --sanity         # macOS
```

This runs all three phases:
1. System prep and CRC startup (as root on Linux)
2. Operator build and deploy (as `developer` on Linux)
3. Validation checks (+ e2e build test if `--sanity`)

### Step by step

**Linux:**
```bash
# Phase 1: System prep (as root)
sudo bash hack/crc/01-prep-host.sh /path/to/pull-secret.txt

# Phase 2: Deploy operator (as developer)
su - developer
cd ~/automotive-dev-operator
bash hack/crc/02-deploy-operator.sh ~/pull-secret.txt

# Phase 3: Validate
bash hack/crc/03-crc-operator-sanity.sh
bash hack/crc/03-crc-operator-sanity.sh --sanity   # with build test
```

**macOS:**
```bash
bash hack/crc/01-prep-host.sh /path/to/pull-secret.txt
bash hack/crc/02-deploy-operator.sh /path/to/pull-secret.txt
bash hack/crc/03-crc-operator-sanity.sh
```

## What each script does

### `01-prep-host.sh`

1. Install virtualisation packages (libvirt, qemu-kvm) -- Linux only
2. Install Go (for `make deploy` tooling)
3. Install kubectl
4. Verify hardware virtualisation support
5. Download and install CRC (or skip if already installed)
6. Create `developer` user with libvirt permissions -- Linux only
7. Configure CRC resources (memory, cpus, disk-size) and run `crc setup`
8. If CRC is already running with a smaller disk, stop and delete the VM first
9. Run `crc start`

After setup, use `eval $(crc oc-env)` to add `oc` to your PATH.

### `02-deploy-operator.sh`

1. Configure and start CRC (auto-detects disk size mismatch and recreates VM if needed)
2. Authenticate as kubeadmin
3. Install OpenShift Pipelines (Tekton) via OLM subscription and wait for CRDs
4. Build operator image in-cluster using OpenShift BuildConfig (no Podman/Docker needed)
5. Deploy operator via `make deploy` with internal registry image
6. Label nodes with `aib=true` for build pod scheduling
7. Apply OperatorConfig and patch `clusterRegistryRoute` to use internal registry

Pull secret path can be provided as:
- CLI argument: `./02-deploy-operator.sh /path/to/pull-secret.txt`
- Environment variable: `PULL_SECRET_PATH=/path/to/pull-secret.txt ./02-deploy-operator.sh`
- Default: `~/.crc/pull-secret.txt` (macOS) or `~/pull-secret.txt` (Linux)

### `03-crc-operator-sanity.sh`

Checks 23 items across 6 categories:

| Category | Checks |
|----------|--------|
| CRC Cluster | Reachable, logged in, node ready, `aib=true` label |
| Operator | Namespace, pod running, pod ready, OperatorConfig exists, OperatorConfig phase Ready |
| Build API | Pod running, pod ready, service, route, endpoint responds |
| Tekton Tasks | 7 tasks: build-automotive-image, push-artifact-registry, flash-image, prepare-reseal, reseal, extract-for-signing, inject-signed |
| Tekton Pipelines | automotive-build-pipeline exists |
| OpenShift Pipelines | Pipelines operator pod running |

With `--sanity`, additional checks:

| Check | Description |
|-------|-------------|
| Build caib CLI | Builds `bin/caib` if not present |
| Submit build | Runs `caib image build` with `test/config/test-manifest.aib.yml` |
| Build completed | Verifies build completes successfully |
| Build in list | Verifies build appears as Completed in `caib image list` |
| ImageStream | Verifies the `automotive` ImageStream was created |

## Building images after deployment

```bash
# Set the Build API server
export CAIB_SERVER=https://ado-build-api-automotive-dev-operator-system.apps-crc.testing

# Build an image (push to internal registry, use your platform arch)
./bin/caib image build <manifest.yml> \
  --arch amd64 \
  --push image-registry.openshift-image-registry.svc:5000/automotive-dev-operator-system/my-image:latest \
  --insecure

# List builds
./bin/caib image list --insecure

# Verify the image in the registry
oc get imagestream -n automotive-dev-operator-system
```

Use `--arch arm64` on Apple Silicon Macs, `--arch amd64` on Intel/Linux x86_64.

## Environment Variables

### `01-prep-host.sh`

| Variable | Default | Description |
|----------|---------|-------------|
| `CRC_VERSION` | `2.58.0` | CRC release version |
| `CRC_TARBALL` | auto | Path to local CRC tarball (Linux, skips download) |
| `CRC_PKG` | auto | Path to local `.pkg` installer (macOS, skips download) |
| `PULL_SECRET` | `pull-secret.txt` or `$1` | Path to pull secret file |
| `CRC_MEMORY` | `12288` | CRC VM memory in MiB |
| `CRC_CPUS` | `4` | CRC VM CPU count |
| `DISK_SIZE` | `90` | CRC VM disk size in GB |

### `02-deploy-operator.sh`

| Variable | Default | Description |
|----------|---------|-------------|
| `PULL_SECRET_PATH` | OS-dependent | Path to pull secret file (also accepts `$1`) |
| `CRC_MEMORY` | `12288` | CRC VM memory in MiB |
| `CRC_CPUS` | `4` | CRC VM CPU count |
| `DISK_SIZE` | `90` | CRC VM disk size in GB |

## Cleanup

```bash
# Stop and delete CRC VM
sudo bash hack/crc/crc-cleanup.sh        # Linux
bash hack/crc/crc-cleanup.sh             # macOS

# Full removal (binary, user, home directory, cache)
sudo bash hack/crc/crc-cleanup.sh --full  # Linux
bash hack/crc/crc-cleanup.sh --full      # macOS
```

What `--full` removes on Linux:
- Kills all processes owned by `developer` user
- Removes `developer` user and home directory (`/home/developer`)
- Cleans `/etc/subuid` and `/etc/subgid` entries
- Removes sudoers files (`crc-temp`, `crc-deploy`)
- Removes CRC binary from `/usr/local/bin/crc`, `~/bin/crc`, `/usr/bin/crc`
- Removes `/root/.crc` cache

What `--full` removes on macOS:
- Uninstalls Homebrew cask (if installed via brew)
- Removes CRC binary from `/usr/local/bin/crc`, `~/bin/crc`
- Removes `~/.crc` cache

## Troubleshooting

### Tekton CRDs not ready (operator crash-loops)

If the operator logs show `no matches for kind "PipelineRun" in version "tekton.dev/v1"`, the Tekton CRDs haven't been installed yet. The deploy script now waits for CRDs, but if it happens:

```bash
# Check if CRDs exist
oc get crd | grep tekton

# Restart the operator after CRDs are available
oc rollout restart deployment/ado-operator -n automotive-dev-operator-system
```

### Disk pressure / build eviction

If in-cluster builds fail with "low on resource: ephemeral-storage", the CRC VM disk is too small. Both `01-prep-host.sh` and `02-deploy-operator.sh` auto-detect this, but if needed manually:

```bash
# Clean up the existing VM
bash hack/crc/crc-cleanup.sh        # stops CRC, deletes VM, runs crc cleanup

# Or manually:
crc stop
crc delete -f

# Set the larger disk and recreate
crc config set disk-size 90
crc start --pull-secret-file ~/pull-secret.txt
```

Or for a full reset (removes binary, user, cache):
```bash
bash hack/crc/crc-cleanup.sh --full
```

`crc delete -f` is required -- `disk-size` only applies when creating a new VM.

### Port 6443 already in use

```bash
sudo lsof -i :6443        # macOS
sudo ss -tlnp | grep 6443 # Linux
sudo kill -9 <PID>
crc start --pull-secret-file pull-secret.txt
```

### Node selector mismatch (build pods stuck Pending)

Ensure nodes are labeled:
```bash
oc label nodes --all aib=true
```

### Architecture mismatch (macOS Apple Silicon)

Use `--arch arm64` (not `amd64`) when building images on Apple Silicon Macs.

### TLS errors with internal registry

The deploy script patches OperatorConfig to use the internal registry (`image-registry.openshift-image-registry.svc:5000`) which avoids TLS issues. If you see certificate errors, verify the patch:
```bash
oc get operatorconfig config -n automotive-dev-operator-system -o jsonpath='{.spec.osBuilds.clusterRegistryRoute}'
```

### Podman VM can't reach CRC registry (macOS)

On macOS, the Podman machine VM and CRC VM are network-isolated. The deploy script uses in-cluster OpenShift builds to avoid this entirely -- no Podman/Docker push is needed.

## Tested Platforms

| | macOS | Linux |
|---|---|---|
| **Arch** | arm64 (Apple Silicon) | x86_64 |
| **Distro** | Darwin | Fedora 43 |
| **CRC runs as** | current user | `developer` user |
| **Virtualisation** | vfkit (Hypervisor.framework) | libvirt/KVM |

### Execution Benchmarks

Times for `setup-crc.sh --sanity` (full setup + sanity build test):

| Scenario | macOS arm64 | Linux x86_64 |
|----------|-------------|--------------|
| After full cleanup | ~16 min | ~50 min |
| CRC already running | ~4 min | TBD |
