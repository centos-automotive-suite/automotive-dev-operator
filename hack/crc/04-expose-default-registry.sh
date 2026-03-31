#!/usr/bin/env bash
set -euo pipefail

# 04-expose-default-registry.sh
# Prepares CRC external image registry route access for podman.
# Works on both macOS (podman machine VM) and Linux (native podman).
# Run this after CRC is ready and before deploy-catalog.sh.
#
# Linux:  sudo bash hack/crc/04-expose-default-registry.sh
# macOS:  bash hack/crc/04-expose-default-registry.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}✓ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠ $*${NC}"; }
fail()  { echo -e "${RED}✗ $*${NC}"; exit 1; }

OS="$(uname -s)"

CRC_USER_HOME="$HOME"
if [[ "$OS" == "Linux" && $EUID -eq 0 ]]; then
    CRC_USER="${CRC_USER:-${SUDO_USER:-}}"
    if [[ -n "$CRC_USER" ]]; then
        CRC_USER_HOME=$(getent passwd "$CRC_USER" | cut -d: -f6)
    fi
fi

if [[ -f "$CRC_USER_HOME/.crc_env" ]]; then
    source "$CRC_USER_HOME/.crc_env"
fi

export PATH="${CRC_USER_HOME}/.crc/bin/oc:$PATH"

if [[ -z "${KUBECONFIG:-}" && -f "$CRC_USER_HOME/.crc/machines/crc/kubeconfig" ]]; then
    export KUBECONFIG="$CRC_USER_HOME/.crc/machines/crc/kubeconfig"
fi

command -v oc >/dev/null 2>&1 || fail "Missing required command: oc"
if [[ "$OS" == "Darwin" ]]; then
    command -v podman >/dev/null 2>&1 || fail "Missing required command: podman"
fi

if ! oc whoami >/dev/null 2>&1; then
    fail "Not logged into OpenShift. Run: oc login ..."
fi

if [[ "$OS" == "Darwin" ]]; then
    PM_STATE=$(podman machine inspect --format '{{.State}}' 2>/dev/null || echo "unknown")
    [[ "$PM_STATE" == "running" ]] || fail "Podman machine is not running (state: $PM_STATE). Run: podman machine start"
fi

TLS_VERIFY="${REGISTRY_TLS_VERIFY:-false}"
DISABLE_REDIRECT="${DISABLE_REDIRECT:-true}"

run_as_user() {
    if [[ "$OS" == "Linux" && $EUID -eq 0 && -n "${CRC_USER:-}" ]]; then
        su - "$CRC_USER" -c "source ~/.crc_env 2>/dev/null; $1"
    else
        eval "$1"
    fi
}

###############################################################################
# Expose default registry route
###############################################################################
info "Ensuring default registry route is exposed..."
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --type=merge \
  -p '{"spec":{"defaultRoute":true}}' >/dev/null
ok "Default route enabled."

if [[ "$DISABLE_REDIRECT" == "true" ]]; then
    info "Disabling registry redirect to avoid blob reuse route issues..."
    oc patch configs.imageregistry.operator.openshift.io/cluster \
      --type=merge \
      -p '{"spec":{"disableRedirect":true}}' >/dev/null
    ok "disableRedirect=true applied."
fi

sleep 3
HOST="$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')"
[[ -n "$HOST" ]] || fail "Could not resolve default registry route host."
ok "Registry host: $HOST"

###############################################################################
# Extract ingress certificate
###############################################################################
CERT_DIR="/tmp/registry-certs"
mkdir -p "$CERT_DIR"

CERT_SECRET="$(oc get ingresscontroller -n openshift-ingress-operator default -o jsonpath='{.spec.defaultCertificate.name}')"
CERT_SECRET="${CERT_SECRET:-router-certs-default}"
info "Extracting ingress cert from secret/$CERT_SECRET..."
oc extract "secret/${CERT_SECRET}" -n openshift-ingress --to="$CERT_DIR" --confirm >/dev/null
[[ -f "$CERT_DIR/tls.crt" ]] || fail "Certificate extraction failed: $CERT_DIR/tls.crt not found."
ok "Certificate extracted to $CERT_DIR/tls.crt"

###############################################################################
# Install cert & configure DNS
###############################################################################
install_cert_and_dns_vm() {
    info "Installing cert in podman VM trust store..."
    cat "$CERT_DIR/tls.crt" | podman machine ssh "sudo tee /tmp/registry-crc.crt >/dev/null"
    podman machine ssh "sudo mkdir -p /etc/pki/ca-trust/source/anchors \
        && sudo cp /tmp/registry-crc.crt /etc/pki/ca-trust/source/anchors/registry-crc.crt \
        && sudo update-ca-trust"
    podman machine ssh "sudo mkdir -p /etc/containers/certs.d/$HOST \
        && sudo cp /tmp/registry-crc.crt /etc/containers/certs.d/$HOST/ca.crt"
    ok "Podman VM cert trust configured."

    local pm_host_ip
    pm_host_ip="$(podman machine ssh "getent hosts host.containers.internal | awk 'NR==1{print \$1}'")"
    [[ -n "$pm_host_ip" ]] || fail "Unable to resolve host.containers.internal inside podman VM."

    info "Updating podman VM /etc/hosts mapping for $HOST..."
    podman machine ssh "sudo sed -i '/${HOST//./\\.}/d' /etc/hosts"
    podman machine ssh "echo '$pm_host_ip $HOST' | sudo tee -a /etc/hosts >/dev/null"
    local resolved
    resolved="$(podman machine ssh "getent hosts $HOST | awk 'NR==1{print \$1}'")"
    [[ -n "$resolved" ]] || fail "Failed to resolve $HOST in podman VM."
    ok "$HOST resolves inside podman VM to $resolved"

    info "Checking registry endpoint from podman VM..."
    podman machine ssh "curl -sSk -o /dev/null -w '%{http_code}' https://$HOST/v2/" | grep -Eq '^(200|401)$' \
      || fail "Registry /v2 endpoint check failed from podman VM."
    ok "Registry endpoint reachable from podman VM."
}

install_cert_and_dns_host() {
    info "Installing cert in host trust store..."
    sudo cp "$CERT_DIR/tls.crt" /etc/pki/ca-trust/source/anchors/registry-crc.crt
    sudo chmod 644 /etc/pki/ca-trust/source/anchors/registry-crc.crt
    sudo update-ca-trust
    sudo mkdir -p "/etc/containers/certs.d/$HOST"
    sudo cp "$CERT_DIR/tls.crt" "/etc/containers/certs.d/$HOST/ca.crt"
    sudo chmod 644 "/etc/containers/certs.d/$HOST/ca.crt"
    ok "Host cert trust configured."

    if ! getent hosts "$HOST" >/dev/null 2>&1; then
        local crc_ip
        crc_ip="$(run_as_user "crc ip 2>/dev/null" 2>/dev/null || true)"
        [[ -n "$crc_ip" ]] || fail "Cannot resolve $HOST and crc ip is unknown."
        info "Adding /etc/hosts entry: $crc_ip $HOST"
        sudo sed -i "/${HOST//./\\.}/d" /etc/hosts
        echo "$crc_ip $HOST" | sudo tee -a /etc/hosts >/dev/null
    fi
    local resolved
    resolved="$(getent hosts "$HOST" | awk 'NR==1{print $1}')"
    [[ -n "$resolved" ]] || fail "Failed to resolve $HOST on host."
    ok "$HOST resolves to $resolved"

    info "Checking registry endpoint..."
    curl -sSk -o /dev/null -w '%{http_code}' "https://$HOST/v2/" | grep -Eq '^(200|401)$' \
      || fail "Registry /v2 endpoint check failed."
    ok "Registry endpoint reachable."
}

if [[ "$OS" == "Darwin" ]]; then
    install_cert_and_dns_vm
else
    install_cert_and_dns_host
fi

###############################################################################
# Podman login
###############################################################################
if command -v podman >/dev/null 2>&1; then
    info "Logging into registry with podman..."
    if ! OC_TOKEN="$(oc whoami -t 2>/dev/null)"; then
        info "No active token. Logging in as kubeadmin to obtain one..."
        KUBE_PASS=$(run_as_user "crc console --credentials -o json 2>/dev/null" | grep -o '"password":"[^"]*' | cut -d'"' -f4 || true)
        if [[ -z "$KUBE_PASS" ]]; then
            KUBE_PASS=$(run_as_user "crc console --credentials 2>/dev/null" | grep kubeadmin | sed "s/.*-p \([^ ]*\) .*/\1/" | head -1)
        fi
        [[ -n "$KUBE_PASS" ]] || fail "Cannot obtain kubeadmin password from 'crc console --credentials'."
        oc login -u kubeadmin -p "$KUBE_PASS" "https://api.crc.testing:6443" --insecure-skip-tls-verify >/dev/null
        OC_TOKEN="$(oc whoami -t)"
    fi
    SAFE_TOKEN=$(printf '%q' "$OC_TOKEN")
    run_as_user "podman login -u kubeadmin -p $SAFE_TOKEN '$HOST' --tls-verify='$TLS_VERIFY'" >/dev/null
    ok "Podman login succeeded."
else
    warn "podman not found -- skipping podman login. Install podman to push/pull images."
fi

echo ""
ok "External registry route exposed: $HOST"
echo ""
echo "To push/pull images:"
echo "  podman login -u kubeadmin -p \"\$(oc whoami -t)\" $HOST --tls-verify=${TLS_VERIFY}"
echo "  podman pull --tls-verify=${TLS_VERIFY} $HOST/<namespace>/<image>:<tag>"
echo ""
echo "To deploy operator via catalog:"
echo "  REGISTRY_TLS_VERIFY=${TLS_VERIFY} ./hack/deploy-catalog.sh -y --keep-config"
