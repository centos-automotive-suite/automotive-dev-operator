#!/usr/bin/env bash
set -euo pipefail

# 02-deploy-operator.sh
# Cross-platform: Runs on both macOS and Linux
# Run as the unprivileged developer user inside the Git repository
#
# Usage:
#   ./hack/crc/02-deploy-operator.sh
#
# Prerequisites:
#   - CRC installed, configured, and running via 01-prep-host.sh
#   - hack/deploy-catalog.sh and hack/crc/04-expose-default-registry.sh available

###############################################################################
# Configuration
###############################################################################
NAMESPACE="automotive-dev-operator-system"
IMAGE_NAME="automotive-dev-operator"

OS="$(uname -s)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}✅  $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️   $*${NC}"; }
fail()  { echo -e "${RED}❌  $*${NC}"; exit 1; }
line()  { echo "========================================="; }

STEP=0
TOTAL_STEPS=6
step()  { STEP=$((STEP + 1)); info "[Step ${STEP}/${TOTAL_STEPS}] $*"; }

###############################################################################
# Pre-flight checks
###############################################################################
line
echo "   Automotive Dev Operator — Deploy (${OS})"
line

if [[ -f "$HOME/.crc_env" ]]; then
    info "Sourcing CRC environment from ~/.crc_env"
    source "$HOME/.crc_env"
fi

if [[ "$OS" == "Linux" && "$(id -u)" -eq 0 ]]; then
    fail "CRC must not run as root on Linux. Switch to a non-root user (e.g. 'developer')."
fi

command -v crc &>/dev/null || fail "'crc' not found in PATH. Run 01-prep-host.sh first."

get_kubeadmin_pass() {
    local pass=""
    local json
    json=$(crc console --credentials -o json 2>/dev/null || true)
    if [[ -n "$json" ]]; then
        pass=$(echo "$json" | sed -n '/"adminCredentials"/,/}/s/.*"password"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi
    if [[ -z "$pass" ]]; then
        pass=$(crc console --credentials 2>/dev/null | grep kubeadmin | sed "s/.*-p \([^ ]*\) .*/\1/" | head -1)
    fi
    echo "$pass"
}

###############################################################################
# Step 1 — Authenticate with cluster
###############################################################################
step "Authenticating with the cluster..."
eval "$(crc oc-env)" || fail "Failed to configure oc CLI. Is CRC running? Try 'crc status'."
command -v oc &>/dev/null || fail "'oc' not found in PATH after 'crc oc-env'. Check CRC installation."

CRC_KUBECONFIG="$(crc oc-env | sed -n "s/.*KUBECONFIG='\([^']*\)'.*/\1/p")"
if [[ -z "$CRC_KUBECONFIG" ]]; then
    CRC_KUBECONFIG="$HOME/.crc/machines/crc/kubeconfig"
fi
export KUBECONFIG="$CRC_KUBECONFIG"

KUBE_PASS=$(get_kubeadmin_pass)
[[ -n "$KUBE_PASS" ]] || fail "Could not extract kubeadmin password from 'crc console --credentials'."
oc login -u kubeadmin -p "$KUBE_PASS" https://api.crc.testing:6443 || fail "Failed to login to cluster."
ok "Logged in as kubeadmin (KUBECONFIG=$KUBECONFIG)."

###############################################################################
# Step 2 — Install OpenShift Pipelines (Tekton)
###############################################################################
step "Installing OpenShift Pipelines (Tekton)..."

TEKTON_READY=true
for crd in tasks.tekton.dev pipelines.tekton.dev pipelineruns.tekton.dev taskruns.tekton.dev; do
    if ! oc get crd "$crd" &>/dev/null; then
        TEKTON_READY=false
        break
    fi
done

if [[ "$TEKTON_READY" == true ]]; then
    ok "OpenShift Pipelines already installed (Tekton CRDs present)."
else
    cat <<EOF | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: openshift-pipelines-operator-rh
  namespace: openshift-operators
spec:
  channel: latest
  name: openshift-pipelines-operator-rh
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

    info "Waiting for OpenShift Pipelines CSV to succeed..."
    CSV_PHASE=""
    for _ in {1..90}; do
        CSV_PHASE=$(oc get csv -n openshift-operators \
            -l operators.coreos.com/openshift-pipelines-operator-rh.openshift-operators= \
            -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)
        [[ "$CSV_PHASE" == "Succeeded" ]] && break
        sleep 10
    done
    [[ "$CSV_PHASE" == "Succeeded" ]] \
        || fail "OpenShift Pipelines CSV not ready after 15 minutes (phase: ${CSV_PHASE:-unknown})."

    info "Waiting for Tekton CRDs to be available..."
    for crd in tasks.tekton.dev pipelines.tekton.dev pipelineruns.tekton.dev taskruns.tekton.dev; do
        for _ in {1..60}; do
            oc get crd "$crd" &>/dev/null && break
            sleep 5
        done
        oc get crd "$crd" &>/dev/null || fail "Tekton CRD $crd not found after 5 minutes."
    done
    ok "OpenShift Pipelines ready (CRDs installed)."
fi

###############################################################################
# Step 3 — Build & deploy the operator via OLM catalog
###############################################################################
step "Building and deploying the operator..."

INTERNAL_REGISTRY="image-registry.openshift-image-registry.svc:5000"
IMG="${INTERNAL_REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:latest"

REGISTRY_HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null || echo "")
if [[ -z "$REGISTRY_HOST" ]]; then
    fail "External registry route not found. Run first: sudo bash hack/crc/04-expose-default-registry.sh"
fi
ok "External registry route: $REGISTRY_HOST"

info "Running deploy-catalog.sh..."
REGISTRY_TLS_VERIFY=false ./hack/deploy-catalog.sh -y --keep-config || fail "deploy-catalog.sh failed."
ok "Operator deployed via OLM catalog."

info "Ensuring image pull permissions for operator service account..."
if ! oc policy add-role-to-user system:image-puller "system:serviceaccount:${NAMESPACE}:ado-operator" -n "$NAMESPACE" 2>/dev/null; then
    warn "Failed to grant image-puller role to ado-operator SA. Pods may fail to pull images."
fi

###############################################################################
# Step 4 — Label nodes for build scheduling
###############################################################################
step "Labeling nodes for build pod scheduling..."
oc label nodes --all aib=true --overwrite || fail "Failed to label nodes."
ok "Nodes labeled with aib=true."

###############################################################################
# Step 5 — Patch OperatorConfig and wait for Ready
###############################################################################
step "Patching OperatorConfig to use internal registry..."
oc patch operatorconfig config -n "$NAMESPACE" --type=merge \
    -p "{\"spec\":{\"osBuilds\":{\"clusterRegistryRoute\":\"${INTERNAL_REGISTRY}\"}}}" \
    || fail "Failed to patch OperatorConfig."

info "Waiting for operator to reconcile..."
for _ in {1..30}; do
    PHASE=$(oc get operatorconfig config -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    if [ "$PHASE" = "Ready" ]; then
        break
    fi
    sleep 5
done
[ "$PHASE" = "Ready" ] || fail "OperatorConfig did not reach Ready phase (current: ${PHASE})"
ok "OperatorConfig reconciled (phase: Ready)."

###############################################################################
# Step 6 — Verify
###############################################################################
step "Verifying deployment..."
BUILD_API_ROUTE=$(oc get route ado-build-api -n "$NAMESPACE" -o jsonpath='{.spec.host}' 2>/dev/null || echo "")

case "$(uname -m)" in
    x86_64)        QUICKSTART_ARCH="amd64" ;;
    aarch64|arm64) QUICKSTART_ARCH="arm64" ;;
    *)             QUICKSTART_ARCH="amd64" ;;
esac

ok "All components running."

###############################################################################
# Done
###############################################################################
line
echo ""
ok "Automotive Dev Operator is up and running!"
echo ""
echo "  Namespace:  $NAMESPACE"
echo "  Image:      $IMG"
if [ -n "$BUILD_API_ROUTE" ]; then
    echo "  Build API:  https://${BUILD_API_ROUTE}"
fi
echo ""
echo "  Cluster credentials:"
echo "    Admin:     kubeadmin / $(get_kubeadmin_pass)"
echo "    Developer: developer / developer"
echo "    Console:   https://console-openshift-console.apps-crc.testing"
echo ""
echo "  Quick start:"
if [ -n "$BUILD_API_ROUTE" ]; then
    echo "    export CAIB_SERVER=https://${BUILD_API_ROUTE}"
else
    warn "Build API route not available yet; run 'oc get route ado-build-api -n $NAMESPACE' to check."
fi
echo "    ./bin/caib image build <manifest.yml> --arch ${QUICKSTART_ARCH} --push ${INTERNAL_REGISTRY}/${NAMESPACE}/my-image:latest --insecure"
echo ""
echo "  Useful commands:"
echo "    oc get pods -n $NAMESPACE"
echo "    oc get operatorconfig -n $NAMESPACE"
echo "    oc get tasks,pipelines -n $NAMESPACE"
echo "    ./bin/caib image list --insecure"
echo "    crc console"
echo ""
line
