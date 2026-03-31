#!/bin/bash
set -euo pipefail

# Unified CRC (OpenShift Local) Setup & Start — Linux & macOS
# Supports x86_64/amd64 and aarch64/arm64 — detected at runtime.
#
# Linux (Fedora / RHEL / CentOS):
#   sudo bash 01-prep-host.sh [/path/to/pull-secret.txt]
#
# macOS (Intel & Apple Silicon):
#   bash 01-prep-host.sh [/path/to/pull-secret.txt]
#
# Environment variables (override defaults):
#   CRC_VERSION  — release version       (default: 2.58.0)
#   CRC_TARBALL  — local tarball path    (Linux; skips download if set)
#   CRC_PKG      — local .pkg installer  (macOS; skips download if set)
#   PULL_SECRET  — path to pull-secret   (default: pull-secret.txt, or $1)

###############################################################################
# Configuration
###############################################################################
CRC_PRESET="openshift"          # [ openshift | microshift | okd ]
CRC_VERSION="${CRC_VERSION:-2.58.0}"
CRC_BASE_URL="https://mirror.openshift.com/pub/openshift-v4/clients/crc/${CRC_VERSION}"
TELEMETRY="no"
PULL_SECRET="${PULL_SECRET:-${1:-pull-secret.txt}}"
CRC_CUSTOM_ARGS="${CRC_CUSTOM_ARGS:---cpus 4 --memory 12288 --disk-size 50}"

OS="$(uname -s)"
ARCH="$(uname -m)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}✅  $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️   $*${NC}"; }
fail()  { echo -e "${RED}❌  $*${NC}"; exit 1; }
line()  { echo "========================================="; }

if [[ "$OS" == "Linux" && $EUID -eq 0 ]]; then
    CRC_USER="${CRC_USER:-${SUDO_USER:-}}"
    [[ -n "$CRC_USER" ]] || fail "Cannot determine non-root user. Either run with sudo or set CRC_USER=<username>."
    id "$CRC_USER" &>/dev/null || fail "User '$CRC_USER' does not exist."
fi


if [[ ! "$CRC_CUSTOM_ARGS" =~ ^[a-zA-Z0-9\ \-]+$ ]]; then
    fail "ERROR: CRC_CUSTOM_ARGS contains invalid characters. Only alphanumeric, spaces, and hyphens are allowed."
fi

STEP=0
step()  { STEP=$((STEP + 1)); info "[Step ${STEP}] $*"; }

###############################################################################
# Resolve architecture
###############################################################################
case "$ARCH" in
    x86_64)  CRC_ARCH="amd64" ;;
    aarch64) CRC_ARCH="arm64" ;;
    arm64)   CRC_ARCH="arm64" ;;
    *)       fail "Unsupported architecture: $ARCH" ;;
esac

###############################################################################
# Resolve OS-specific artifact names
###############################################################################
case "$OS" in
    Linux)
        CRC_FILENAME="crc-linux-${CRC_ARCH}.tar.xz"
        CRC_ARTIFACT="${CRC_TARBALL:-${CRC_FILENAME}}"
        CHECKSUM_CMD="sha256sum"
        ;;
    Darwin)
        CRC_FILENAME="crc-macos-installer.pkg"
        CRC_ARTIFACT="${CRC_PKG:-${CRC_FILENAME}}"
        CHECKSUM_CMD="shasum -a 256"
        ;;
    *)  fail "Unsupported OS: $OS (expected Linux or Darwin)" ;;
esac

###############################################################################
# Pre-flight checks
###############################################################################
line
echo "   Automated CRC Setup — ${OS} ${ARCH} (${CRC_ARCH})"
line

if [[ "$OS" == "Linux" ]]; then
    [[ $EUID -eq 0 ]] || fail "On Linux this script must be run as root."
elif [[ "$OS" == "Darwin" ]]; then
    [[ $EUID -ne 0 ]] || fail "On macOS do NOT run as root — use your normal user."
fi

[[ -f "$PULL_SECRET" ]] || \
    fail "Pull-secret not found at '$PULL_SECRET'.\nUsage: $0 /path/to/pull-secret.txt"
PULL_SECRET=$(realpath "$PULL_SECRET")

###############################################################################
# Linux — Install packages & enable services
###############################################################################
if [[ "$OS" == "Linux" ]]; then
    step "Installing virtualisation stack..."
    dnf install -y --best --allowerasing \
        libvirt libvirt-daemon-kvm qemu-kvm virt-install \
        wget curl tar xz NetworkManager podman
    ok "Packages installed."

    step "Enabling services..."
    systemctl enable --now NetworkManager
    systemctl enable --now libvirtd
    ok "libvirtd & NetworkManager running."
fi

###############################################################################
# Install Go (needed by deploy-catalog.sh for controller-gen / kustomize)
###############################################################################
GO_VERSION="1.24.4"
step "Checking Go installation..."
if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
elif [[ "$OS" == "Linux" ]]; then
    info "Installing Go ${GO_VERSION}..."
    curl -sSfL "https://go.dev/dl/go${GO_VERSION}.linux-${CRC_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    export PATH="$PATH:/usr/local/go/bin"
    ok "Go installed: $(/usr/local/go/bin/go version)"
elif [[ "$OS" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
        info "Installing Go via Homebrew..."
        brew install go
        ok "Go installed: $(go version)"
    else
        fail "Go is not installed. Install it with: brew install go"
    fi
fi

###############################################################################
# Verify virtualisation support
###############################################################################
step "Verifying virtualisation support..."
if [[ "$OS" == "Linux" ]]; then
    if lscpu | grep -q "Virtualization:.*VT-x\|Virtualization:.*AMD-V"; then
        ok "Hardware virtualisation (VT-x / AMD-V) is active."
    else
        fail "Hardware virtualisation not detected — enable it in BIOS."
    fi
    if grep -q 'avx2' /proc/cpuinfo; then
        ok "CPU supports x86-64-v3 (AVX2 present)."
    else
        warn "CPU does NOT support x86-64-v3 (no AVX2). Image builds will fail — the caib tool requires Haswell+ (2013) or newer CPUs."
    fi
elif [[ "$OS" == "Darwin" ]]; then
    if sysctl -n kern.hv_support 2>/dev/null | grep -q 1; then
        ok "Hypervisor framework supported."
    else
        fail "Hypervisor framework not available on this Mac."
    fi
fi

###############################################################################
# Download CRC (skip if already present / installed)
###############################################################################
SKIP_INSTALL=false

step "Obtaining CRC..."
if command -v crc &>/dev/null; then
    ok "CRC already installed: $(crc version 2>/dev/null | head -1)"
    SKIP_INSTALL=true
elif [[ -f "$CRC_ARTIFACT" ]]; then
    ok "Using existing artifact: $CRC_ARTIFACT"
else
    info "Downloading ${CRC_FILENAME} (v${CRC_VERSION})..."
    curl -L --fail --progress-bar -o "$CRC_FILENAME" \
        "${CRC_BASE_URL}/${CRC_FILENAME}" \
        || fail "Download failed. Check version/URL:\n  ${CRC_BASE_URL}/${CRC_FILENAME}"
    CRC_ARTIFACT="$CRC_FILENAME"
    ok "Downloaded $CRC_FILENAME"
fi

if [[ "$SKIP_INSTALL" == false ]]; then
    info "Verifying SHA256 checksum..."
    curl -sSfL -o sha256sum.txt "${CRC_BASE_URL}/sha256sum.txt" 2>/dev/null \
        || warn "Could not download sha256sum.txt — skipping verification."
    if [[ -f sha256sum.txt ]]; then
        EXPECTED=$(grep "$CRC_FILENAME" sha256sum.txt | awk '{print $1}')
        if [[ -n "$EXPECTED" ]]; then
            ACTUAL=$($CHECKSUM_CMD "$CRC_ARTIFACT" | awk '{print $1}')
            if [[ "$EXPECTED" == "$ACTUAL" ]]; then
                ok "SHA256 checksum verified."
            else
                fail "Checksum mismatch!\n  Expected: $EXPECTED\n  Got:      $ACTUAL"
            fi
        else
            warn "Filename not found in sha256sum.txt — skipping verification."
        fi
        rm -f sha256sum.txt
    fi
fi

###############################################################################
# Install CRC
###############################################################################
step "Installing CRC..."
if [[ "$SKIP_INSTALL" == true ]]; then
    ok "Skipped — already installed."
elif [[ "$OS" == "Linux" ]]; then
    tar -xf "$CRC_ARTIFACT"
    CRC_DIR=$(ls -d crc-linux-*-${CRC_ARCH} 2>/dev/null | head -1)
    [[ -n "$CRC_DIR" ]] || fail "Could not locate extracted CRC directory."
    install -m 0755 "$CRC_DIR/crc" /usr/local/bin/crc
    rm -rf "$CRC_DIR"
    ok "CRC $(crc version 2>/dev/null | head -1 || echo 'installed') → /usr/local/bin/crc"
elif [[ "$OS" == "Darwin" ]]; then
    info "Installing $CRC_ARTIFACT (requires sudo)..."
    sudo installer -pkg "$CRC_ARTIFACT" -target /
    ok "CRC installed via .pkg installer."
fi

###############################################################################
# Linux — Prepare user environment for CRC
###############################################################################
if [[ "$OS" == "Linux" ]]; then
    step "Preparing user '$CRC_USER' for CRC..."
    groupadd -f libvirt
    usermod -aG libvirt "$CRC_USER"

    if ! grep -q "^${CRC_USER}:" /etc/subuid 2>/dev/null; then
        echo "${CRC_USER}:100000:65536" >> /etc/subuid
    fi
    if ! grep -q "^${CRC_USER}:" /etc/subgid 2>/dev/null; then
        echo "${CRC_USER}:100000:65536" >> /etc/subgid
    fi

    TARGET_UID=$(id -u "$CRC_USER")
    USER_HOME=$(getent passwd "$CRC_USER" | cut -d: -f6)
    loginctl enable-linger "$CRC_USER"
    systemctl start "user@${TARGET_UID}.service" || true

    cat > "$USER_HOME/.crc_env" <<ENVEOF
export XDG_RUNTIME_DIR=/run/user/${TARGET_UID}
export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus
ENVEOF

    if [[ ! -e "$USER_HOME/.bashrc" ]]; then
        install -o "$CRC_USER" -g "$CRC_USER" -m 0644 /dev/null "$USER_HOME/.bashrc"
    fi
    if ! grep -q "source ~/.crc_env" "$USER_HOME/.bashrc" 2>/dev/null; then
        echo "source ~/.crc_env" >> "$USER_HOME/.bashrc"
    fi
    chown "${CRC_USER}:${CRC_USER}" "$USER_HOME/.crc_env" "$USER_HOME/.bashrc"

    cp "$PULL_SECRET" "$USER_HOME/pull-secret.txt"
    chown "${CRC_USER}:${CRC_USER}" "$USER_HOME/pull-secret.txt"
    chmod 600 "$USER_HOME/pull-secret.txt"
    ok "User '$CRC_USER' ready (UID $TARGET_UID)."
fi

###############################################################################
# crc setup
###############################################################################
step "Configuring CRC..."

apply_crc_config() {
    if [[ "$OS" == "Linux" ]]; then
        su - "$CRC_USER" -c "
            source ~/.crc_env
            crc config set consent-telemetry \"${TELEMETRY}\"
            crc config set preset \"${CRC_PRESET}\"
        "
    else
        crc config set consent-telemetry "$TELEMETRY"
        crc config set preset "$CRC_PRESET"
    fi
}

CRC_ALREADY_RUNNING=false
if command -v crc &>/dev/null; then
    CRC_PRE_STATUS=$(if [[ "$OS" == "Linux" ]]; then su - "$CRC_USER" -c "source ~/.crc_env; crc status -o json 2>/dev/null"; else crc status -o json 2>/dev/null; fi || echo '{}')
    echo "$CRC_PRE_STATUS" | grep -q '"crcStatus":"Running"' && CRC_ALREADY_RUNNING=true
fi

apply_crc_config

if [[ "$OS" == "Linux" ]]; then
    echo "${CRC_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/crc-temp
    chmod 0440 /etc/sudoers.d/crc-temp
    trap 'rm -f /etc/sudoers.d/crc-temp' EXIT
fi

if [[ "$CRC_ALREADY_RUNNING" == true ]]; then
    info "CRC is already running — skipping 'crc setup'."
else
    info "Running 'crc setup'..."
    if [[ "$OS" == "Linux" ]]; then
        su - "$CRC_USER" -c "source ~/.crc_env; crc setup"
    else
        crc setup
    fi
fi
ok "CRC configured (${CRC_CUSTOM_ARGS})."

###############################################################################
# crc start — delete existing VM if disk size is too small
###############################################################################
step "Starting CRC cluster (this takes 5-15 min)..."

run_crc_cmd() { # INTERNAL: only pass trusted, hardcoded command strings
    if [[ "$OS" == "Linux" ]]; then
        su - "$CRC_USER" -c "source ~/.crc_env; $1"
    else
        eval "$1"
    fi
}

CRC_STATUS=$(run_crc_cmd "crc status -o json 2>/dev/null" || echo '{}')
CRC_RUNNING=$(echo "$CRC_STATUS" | grep -o '"crcStatus":"Running"' || true)
OCP_RUNNING=$(echo "$CRC_STATUS" | grep -o '"openshiftStatus":"Running' || true)

REQUIRED_DISK=$(echo "$CRC_CUSTOM_ARGS" | sed -n 's/.*--disk-size  *\([0-9]*\).*/\1/p')
REQUIRED_DISK="${REQUIRED_DISK:-50}"

if [[ -n "$CRC_RUNNING" && -n "$OCP_RUNNING" ]]; then
    info "CRC is already running. Checking disk size..."
    DISK_TOTAL=$(echo "$CRC_STATUS" | sed -n 's/.*"diskSize":\([0-9]*\).*/\1/p' | head -1)
    CURRENT_DISK=$(( ${DISK_TOTAL:-0} / 1073741824 ))
    if [[ "$CURRENT_DISK" -lt "$REQUIRED_DISK" ]]; then
        warn "Existing VM disk (${CURRENT_DISK}GB) < required (${REQUIRED_DISK}GB). Recreating..."
        run_crc_cmd "crc stop" || true
        run_crc_cmd "crc delete -f"
        info "Starting CRC with ${REQUIRED_DISK}GB disk..."
    else
        ok "Disk size OK (${CURRENT_DISK}GB). Skipping start — already running."
    fi
fi

CRC_STATUS_AFTER=$(run_crc_cmd "crc status -o json 2>/dev/null" || echo '{}')
CRC_RUNNING_AFTER=$(echo "$CRC_STATUS_AFTER" | grep -o '"crcStatus":"Running"' || true)
OCP_RUNNING_AFTER=$(echo "$CRC_STATUS_AFTER" | grep -o '"openshiftStatus":"Running' || true)

if [[ -z "$CRC_RUNNING_AFTER" || -z "$OCP_RUNNING_AFTER" ]]; then
    if [[ "$OS" == "Linux" ]]; then
        su - "$CRC_USER" -c "
            source ~/.crc_env
            crc start --pull-secret-file ~/pull-secret.txt ${CRC_CUSTOM_ARGS}
        "
    else
        crc start --pull-secret-file "$PULL_SECRET" ${CRC_CUSTOM_ARGS}
    fi
fi
ok "CRC cluster is running!"

if [[ "$OS" == "Linux" ]]; then
    rm -f /etc/sudoers.d/crc-temp
fi

###############################################################################
# Done
###############################################################################
line
echo ""
ok "OpenShift Local is up and running."
echo ""
if [[ "$OS" == "Linux" ]]; then
    echo "  Switch to the CRC user:"
    echo "    su - $CRC_USER"
    echo ""
fi
echo "  Useful commands:"
echo "    crc console                # open the web console URL"
echo "    crc console --credentials  # show kubeadmin password"
echo "    eval \$(crc oc-env)         # configure oc CLI"
echo "    oc login -u kubeadmin -p \$(crc console --credentials | grep kubeadmin | awk -F\"'\" '{print \$2}') https://api.crc.testing:6443"
echo ""
line
