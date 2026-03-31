# CRC Setup & Operator Deployment

Automated scripts to install [OpenShift Local (CRC)](https://developers.redhat.com/products/openshift-local/overview), deploy the Automotive Dev Operator, and validate the deployment on **Linux** and **macOS**.

CRC version: **2.58.0** (configurable via `CRC_VERSION`)

## Prerequisites

### Hardware

| Resource | CRC minimum | This project |
|----------|-------------|--------------|
| CPU | 4 physical cores | 4 cores |
| Memory | 10.5 GB free | 12 GB (12288 MiB) |
| Disk | 35 GB | 50 GB |
| Virtualisation | VT-x / AMD-V (Linux), Hypervisor.framework (macOS) | Required |


### Software & Access

1. **Pull secret** -- download from [console.redhat.com/openshift/create/local](https://console.redhat.com/openshift/create/local).
2. **sudo access** (Linux only) -- the invoking user must be able to run `sudo`. The script uses `SUDO_USER` to identify the developer account and runs CRC under that user. One-time setup if sudo is not yet configured:
   ```bash
   # Run as root (e.g. su - root):
   echo "<username> ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/<username>
   chmod 0440 /etc/sudoers.d/<username>
   exit
   # Then from your user, sudo sets SUDO_USER automatically:
   sudo bash hack/crc/setup-crc.sh hack/crc/pull-secret.txt
   ```

## Quick Start

### One command (recommended)

```bash
# Linux
sudo bash hack/crc/setup-crc.sh /path/to/pull-secret.txt

# macOS
bash hack/crc/setup-crc.sh /path/to/pull-secret.txt
```

With end-to-end build test:
```bash
sudo bash hack/crc/setup-crc.sh /path/to/pull-secret.txt --sanity    # Linux
bash hack/crc/setup-crc.sh /path/to/pull-secret.txt --sanity         # macOS
```

This runs three phases:
1. System prep and CRC startup (root privileges, CRC runs as `SUDO_USER`)
2. Expose external registry route, then build and deploy operator (as `SUDO_USER`)
3. Validation checks (+ `caib` image build for system sanity `--sanity`)

### Step by step

**Linux** (run as the CRC user, use `sudo` where indicated):
```bash
sudo bash hack/crc/01-prep-host.sh /path/to/pull-secret.txt
sudo bash hack/crc/04-expose-default-registry.sh
eval "$(crc oc-env)" && export PATH=$PATH:/usr/local/go/bin
bash hack/crc/02-deploy-operator.sh
bash hack/crc/03-crc-operator-sanity.sh            # validate
bash hack/crc/03-crc-operator-sanity.sh --sanity   # + build test
```

**macOS** (requires `podman machine start` before expose/deploy):
```bash
bash hack/crc/01-prep-host.sh /path/to/pull-secret.txt
podman machine start
bash hack/crc/04-expose-default-registry.sh
eval "$(crc oc-env)"
bash hack/crc/02-deploy-operator.sh
bash hack/crc/03-crc-operator-sanity.sh
```

## Scripts

| Script | Run as | Purpose |
|--------|--------|---------|
| `setup-crc.sh` | `sudo` (Linux) / user (macOS) | All-in-one: runs 01, 04, 02, 03. Uses `SUDO_USER` as the CRC user |
| `01-prep-host.sh` | `sudo` (Linux) / user (macOS) | System prep, CRC install, `crc setup`, `crc start` |
| `02-deploy-operator.sh` | non-root | Deploy operator via OLM catalog, configure OperatorConfig |
| `03-crc-operator-sanity.sh` | non-root | Validate cluster, operator, Build API, Tekton. `--sanity` for build test |
| `04-expose-default-registry.sh` | `sudo` (Linux) / user (macOS) | Expose internal registry via external route for podman push/pull |
| `crc-cleanup.sh` | `sudo` (Linux) / user (macOS) | Stop and delete CRC VM. `--full` removes binary, cache, sudoers |

### `01-prep-host.sh`

1. Install virtualisation packages (libvirt, qemu-kvm), podman -- Linux only
2. Install Go
3. Verify hardware virtualisation and AVX2 support
4. Download and install CRC (or skip if already installed)
5. Configure invoking user with libvirt permissions -- Linux only
6. Run `crc setup` and `crc start`
7. Auto-detect disk size mismatch and recreate VM if needed

After setup, run `eval $(crc oc-env)` to add `oc` to your PATH.

### `02-deploy-operator.sh`

Requires CRC already running (via `01-prep-host.sh`) and external registry route exposed (via `04-expose-default-registry.sh`).

1. Authenticate as kubeadmin
2. Install OpenShift Pipelines (Tekton) via OLM subscription, wait for CSV + CRDs
3. Build, push, and deploy operator via `deploy-catalog.sh` (OLM catalog)
4. Label nodes with `aib=true` for build pod scheduling
5. Patch OperatorConfig `clusterRegistryRoute` and wait for Ready

### `03-crc-operator-sanity.sh`

Checks 23 items across 6 categories:

| Category | Checks |
|----------|--------|
| CRC Cluster | Reachable, logged in, node ready, `aib=true` label |
| Operator | Namespace, pod running, pod ready, OperatorConfig exists, phase Ready |
| Build API | Pod running, pod ready, service, route, endpoint responds |
| Tekton Tasks | build-automotive-image, push-artifact-registry, flash-image, prepare-reseal, reseal, extract-for-signing, inject-signed |
| Tekton Pipelines | automotive-build-pipeline exists |
| OpenShift Pipelines | Pipelines operator CSV succeeded |

With `--sanity`, additional checks:

| Check | Description |
|-------|-------------|
| Build caib CLI | Builds `bin/caib` if not present |
| Submit build | Runs `caib image build` with `test/config/test-manifest.aib.yml` |
| Build completed | Verifies build completes successfully |
| Build in list | Verifies build appears as Completed in `caib image list` |
| ImageStream | Verifies the `automotive` ImageStream was created |

## Building images

```bash
export CAIB_SERVER=https://ado-build-api-automotive-dev-operator-system.apps-crc.testing

./bin/caib image build <manifest.yml> \
  --arch amd64 \
  --push image-registry.openshift-image-registry.svc:5000/automotive-dev-operator-system/my-image:latest \
  --insecure

./bin/caib image list --insecure
oc get imagestream -n automotive-dev-operator-system
```

Use `--arch arm64` on Apple Silicon Macs, `--arch amd64` on Intel/Linux x86_64.

## Deploying via deploy-catalog.sh

`02-deploy-operator.sh` uses `deploy-catalog.sh` under the hood to build images locally with podman and push via the external registry route. You can also run `deploy-catalog.sh` directly:

**Step 1 -- Expose the external registry (one-time):**
```bash
sudo bash hack/crc/04-expose-default-registry.sh     # Linux
bash hack/crc/04-expose-default-registry.sh           # macOS
```

**Step 2 -- Deploy:**
```bash
REGISTRY_TLS_VERIFY=false ./hack/deploy-catalog.sh -y --keep-config
```

Requires `podman` on the host (installed automatically by `01-prep-host.sh` on Linux).

## Pulling built images to host

The internal registry (`image-registry.openshift-image-registry.svc:5000`) is only reachable inside the cluster. To pull images from your host, expose the external registry route first.

**Step 1 -- Expose the registry (one-time):**
```bash
bash hack/crc/04-expose-default-registry.sh          # macOS
sudo bash hack/crc/04-expose-default-registry.sh     # Linux
```

**Step 2 -- Pull:**
```bash
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
podman login -u kubeadmin -p "$(oc whoami -t)" "$HOST" --tls-verify=false
podman pull --tls-verify=false "$HOST/<namespace>/<image>:<tag>"
```

For example, if `caib` reports `image-registry.openshift-image-registry.svc:5000/automotive-dev-operator-system/my-build:bootc`, pull with:
```bash
podman pull --tls-verify=false "$HOST/automotive-dev-operator-system/my-build:bootc"
```

## Configuration

### Performance tuning

The defaults are conservative. For faster builds, allocate more resources to CRC:

```bash
# Check available resources
nproc && free -g                  # Linux
sysctl -n hw.ncpu && sysctl -n hw.memsize | awk '{printf "%.0f GB\n", $1/1073741824}'  # macOS
```

Give CRC roughly **half the CPUs** and **~60% of RAM**:

| Host resources | Recommended `CRC_CUSTOM_ARGS` |
|----------------|-------------------------------|
| 8 cores / 16 GB | `--cpus 4 --memory 12288 --disk-size 50` (default) |
| 16 cores / 32 GB | `--cpus 8 --memory 20480 --disk-size 90` |
| 32 cores / 64 GB | `--cpus 16 --memory 40960 --disk-size 100` |

Use `--disk-size 90` or larger when building the operator image via `deploy-catalog.sh`, as the Go build cache requires significant disk space.

Override via environment (on Linux, pass variables **inline with `sudo`** so they reach the root shell):
```bash
sudo CRC_CUSTOM_ARGS="--cpus 8 --memory 20480 --disk-size 80" bash hack/crc/setup-crc.sh /path/to/pull-secret.txt   # Linux
CRC_CUSTOM_ARGS="--cpus 8 --memory 20480 --disk-size 80" bash hack/crc/setup-crc.sh /path/to/pull-secret.txt        # macOS
```

Changing resources after CRC is running requires recreating the VM:
```bash
crc stop && crc delete -f
# Then re-run with the new values
```

### Environment variables

#### `01-prep-host.sh`

| Variable | Default | Description |
|----------|---------|-------------|
| `CRC_VERSION` | `2.58.0` | CRC release version |
| `CRC_TARBALL` | auto | Path to local CRC tarball (Linux, skips download) |
| `CRC_PKG` | auto | Path to local `.pkg` installer (macOS, skips download) |
| `PULL_SECRET` | `pull-secret.txt` or `$1` | Path to pull secret file |
| `CRC_CUSTOM_ARGS` | `--cpus 4 --memory 12288 --disk-size 50` | Arguments passed to `crc start` |

#### `04-expose-default-registry.sh`

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY_TLS_VERIFY` | `false` | TLS verification for podman login |
| `DISABLE_REDIRECT` | `true` | Disable registry redirect (avoids blob reuse issues) |

### Cleanup

```bash
sudo bash hack/crc/crc-cleanup.sh        # Linux: stop + delete VM
bash hack/crc/crc-cleanup.sh             # macOS: stop + delete VM

sudo bash hack/crc/crc-cleanup.sh --full  # Linux: full removal
bash hack/crc/crc-cleanup.sh --full      # macOS: full removal
```

`--full` additionally removes:
- **Linux:** `~/.crc` cache, `~/.crc_env`, `/etc/subuid` & `/etc/subgid` entries, sudoers files, CRC binary, user lingering
- **macOS:** Homebrew cask (if used), CRC binary, `~/.crc` cache

## Troubleshooting

### Tekton CRDs not ready (operator crash-loops)

If logs show `no matches for kind "PipelineRun" in version "tekton.dev/v1"`:
```bash
oc get crd | grep tekton
oc rollout restart deployment/ado-operator -n automotive-dev-operator-system
```

### Disk pressure / build eviction

If builds fail with "low on resource: ephemeral-storage":
```bash
crc stop && crc delete -f
sudo CRC_CUSTOM_ARGS="--cpus 4 --memory 12288 --disk-size 90" bash hack/crc/setup-crc.sh /path/to/pull-secret.txt  # Linux
CRC_CUSTOM_ARGS="--cpus 4 --memory 12288 --disk-size 90" bash hack/crc/setup-crc.sh /path/to/pull-secret.txt       # macOS
```


### Build pods stuck Pending (node selector)

```bash
oc label nodes --all aib=true
```

### TLS errors with internal registry

Verify the OperatorConfig patch:
```bash
oc get operatorconfig config -n automotive-dev-operator-system -o jsonpath='{.spec.osBuilds.clusterRegistryRoute}'
```

### Repo under /root: Permission denied (Linux)

If you cloned the repo as root (e.g. into `/root/`), Phase 2 switches to `SUDO_USER` who can't access `/root/`. The script auto-copies the repo, but it's better to clone somewhere accessible:
```bash
git clone <repo-url> /opt/automotive-dev-operator
cd /opt/automotive-dev-operator
sudo bash hack/crc/setup-crc.sh hack/crc/pull-secret.txt
```

### CPU does not support x86-64-v3

If builds fail with `Fatal glibc error: CPU does not support x86-64-v3`, the host CPU lacks AVX2. Verify:
```bash
grep -o 'avx2' /proc/cpuinfo | head -1
```
If empty, image builds require a newer machine (Haswell / 2013+). The operator itself runs fine.

## Tested Platforms

| | macOS | Linux |
|---|---|---|
| **Arch** | arm64 (Apple Silicon) | x86_64 |
| **Distro** | Darwin | Fedora 43 |
| **CRC runs as** | current user | `SUDO_USER` (invoking user) |
| **Virtualisation** | vfkit (Hypervisor.framework) | libvirt/KVM |

### Benchmarks

Times for `setup-crc.sh --sanity` (full setup + sanity build test):

| Scenario | macOS arm64 | Linux x86_64 |
|----------|-------------|--------------|
| After full cleanup | ~16 min | ~50 min |
| CRC already running | ~4 min | ~20 min |

Linux takes longer due to CRC VM provisioning via libvirt/KVM. The bulk of the time is `crc start` downloading and booting the OpenShift VM for the first time.
