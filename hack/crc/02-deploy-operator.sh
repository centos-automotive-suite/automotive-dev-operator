#!/usr/bin/env bash
set -euo pipefail

# 02-deploy-operator.sh
# Cross-platform: Runs on both macOS and Linux
# Run as the unprivileged developer user inside the Git repository
#
# Usage:
#   ./hack/crc/02-deploy-operator.sh <pull-secret-path>
#   PULL_SECRET_PATH=/path/to/pull-secret.txt ./hack/crc/02-deploy-operator.sh
#
# Prerequisites:
#   - CRC installed and set up via 01-prep-host.sh
#   - Pull secret file (passed as argument or PULL_SECRET_PATH env var)
#   - Project Makefile with docker-build / docker-push / deploy targets

###############################################################################
# Configuration
###############################################################################
NAMESPACE="automotive-dev-operator-system"
IMAGE_NAME="automotive-dev-operator"
CRC_MEMORY=12288    # 12GB
CRC_CPUS=4          # 4 CPUs
DISK_SIZE=90        # 90GB

OS="$(uname -s)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}✅  $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️   $*${NC}"; }
fail()  { echo -e "${RED}❌  $*${NC}"; exit 1; }
line()  { echo "========================================="; }

STEP=0
TOTAL_STEPS=7
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

if [[ -n "${1:-}" ]]; then
    PULL_SECRET_PATH="$1"
elif [[ -z "${PULL_SECRET_PATH:-}" ]]; then
    if [[ "$OS" == "Darwin" ]]; then
        PULL_SECRET_PATH="$HOME/.crc/pull-secret.txt"
    else
        PULL_SECRET_PATH="$HOME/pull-secret.txt"
    fi
fi

[[ -f "$PULL_SECRET_PATH" ]] || \
    fail "Pull secret not found at $PULL_SECRET_PATH. Run 01-prep-host.sh first."

if [[ "$OS" == "Linux" && "$(id -u)" -eq 0 ]]; then
    fail "CRC must not run as root on Linux. Switch to a non-root user (e.g. 'developer')."
fi

command -v crc &>/dev/null || fail "'crc' not found in PATH. Run 01-prep-host.sh first."

###############################################################################
# Step 1 — Configure & start CRC
###############################################################################
step "Configuring and starting OpenShift Local (CRC)..."
crc config set memory "$CRC_MEMORY"
crc config set cpus "$CRC_CPUS"
crc config set disk-size "$DISK_SIZE"
info "Resources: ${CRC_CPUS} CPUs, ${CRC_MEMORY} MiB memory, ${DISK_SIZE}GB disk"

CRC_STATUS=$(crc status -o json 2>/dev/null || echo '{}')
CRC_RUNNING=$(echo "$CRC_STATUS" | grep -o '"crcStatus":"Running"' || true)

if [[ -n "$CRC_RUNNING" ]]; then
    info "CRC is already running. Checking disk size..."
    eval "$(crc oc-env)" 2>/dev/null || true
    KUBE_PASS_TMP=$(crc console --credentials -o json 2>/dev/null | grep -o '"password":"[^"]*' | cut -d'"' -f4)
    if [[ -z "$KUBE_PASS_TMP" ]]; then
        KUBE_PASS_TMP=$(crc console --credentials 2>/dev/null | grep kubeadmin | sed "s/.*-p \([^ ]*\) .*/\1/" | head -1)
    fi
    if ! oc login -u kubeadmin -p "$KUBE_PASS_TMP" https://api.crc.testing:6443 &>/dev/null; then
        warn "Could not authenticate with running cluster -- skipping disk check."
        ACTUAL_GB="$DISK_SIZE"
    else
        RAW_STORAGE=$(oc get nodes -o jsonpath='{.items[0].status.allocatable.ephemeral-storage}' 2>/dev/null || echo "")
        ACTUAL_BYTES=""
        case "$RAW_STORAGE" in
            *Ki) ACTUAL_BYTES=$(( ${RAW_STORAGE%Ki} * 1024 )) ;;
            *Mi) ACTUAL_BYTES=$(( ${RAW_STORAGE%Mi} * 1024 * 1024 )) ;;
            *Gi) ACTUAL_BYTES=$(( ${RAW_STORAGE%Gi} * 1024 * 1024 * 1024 )) ;;
            *Ti) ACTUAL_BYTES=$(( ${RAW_STORAGE%Ti} * 1024 * 1024 * 1024 * 1024 )) ;;
            *[!0-9]*|"") ACTUAL_BYTES="" ;;
            *) ACTUAL_BYTES="$RAW_STORAGE" ;;
        esac
        if [[ -z "$ACTUAL_BYTES" || "$ACTUAL_BYTES" == "0" ]]; then
            warn "Could not query node storage -- skipping disk check."
            ACTUAL_GB="$DISK_SIZE"
        else
            ACTUAL_GB=$(( ACTUAL_BYTES / 1073741824 ))
        fi
    fi
    REQUIRED_GB=$(( DISK_SIZE * 9 / 10 ))

    if [[ "$ACTUAL_GB" -lt "$REQUIRED_GB" ]]; then
        warn "Disk mismatch: node has ${ACTUAL_GB}GB but ${DISK_SIZE}GB configured."
        info "Recreating CRC VM with ${DISK_SIZE}GB disk..."
        crc stop || true
        crc delete -f
        crc start --pull-secret-file "$PULL_SECRET_PATH"
    else
        info "Disk size OK (${ACTUAL_GB}GB allocatable)."
    fi
else
    crc start --pull-secret-file "$PULL_SECRET_PATH"
fi
ok "CRC cluster is running."

###############################################################################
# Step 2 — Authenticate with cluster
###############################################################################
step "Authenticating with the cluster..."
eval "$(crc oc-env)" || fail "Failed to configure oc CLI. Is CRC running? Try 'crc status'."
command -v oc &>/dev/null || fail "'oc' not found in PATH after 'crc oc-env'. Check CRC installation."

get_kubeadmin_pass() {
    local pass=""
    pass=$(crc console --credentials -o json 2>/dev/null | grep -o '"password":"[^"]*' | cut -d'"' -f4)
    if [[ -z "$pass" ]]; then
        pass=$(crc console --credentials 2>/dev/null | grep kubeadmin | sed "s/.*-p \([^ ]*\) .*/\1/" | head -1)
    fi
    echo "$pass"
}

KUBE_PASS=$(get_kubeadmin_pass)
[[ -n "$KUBE_PASS" ]] || fail "Could not extract kubeadmin password from 'crc console --credentials'."
oc login -u kubeadmin -p "$KUBE_PASS" https://api.crc.testing:6443 || fail "Failed to login to cluster."
ok "Logged in as kubeadmin."

###############################################################################
# Step 3 — Install OpenShift Pipelines (Tekton)
###############################################################################
step "Installing OpenShift Pipelines (Tekton)..."
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

info "Waiting for OpenShift Pipelines operator pod to appear..."
for i in {1..60}; do
    if oc get pods -n openshift-operators -l name=openshift-pipelines-operator --no-headers 2>/dev/null | grep -q .; then
        break
    fi
    sleep 5
done
oc get pods -n openshift-operators -l name=openshift-pipelines-operator --no-headers 2>/dev/null | grep -q . \
    || fail "OpenShift Pipelines operator pod not found after 5 minutes."

info "Waiting for OpenShift Pipelines operator pod to be ready..."
oc wait --for=condition=Ready pods \
    -l name=openshift-pipelines-operator \
    -n openshift-operators \
    --timeout=300s || fail "OpenShift Pipelines operator pod not ready after 5 minutes."

info "Waiting for Tekton CRDs to be available..."
for crd in tasks.tekton.dev pipelines.tekton.dev pipelineruns.tekton.dev taskruns.tekton.dev; do
    for i in {1..60}; do
        if oc get crd "$crd" &>/dev/null; then
            break
        fi
        sleep 5
    done
    oc get crd "$crd" &>/dev/null || fail "Tekton CRD $crd not found after 5 minutes."
done
ok "OpenShift Pipelines ready (CRDs installed)."

###############################################################################
# Step 4 — Build & deploy the operator
###############################################################################
step "Building and deploying the operator..."

if oc get namespace "$NAMESPACE" &>/dev/null; then
    info "Namespace '$NAMESPACE' already exists."
else
    oc create namespace "$NAMESPACE" || fail "Failed to create namespace '$NAMESPACE'."
    ok "Namespace '$NAMESPACE' created."
fi

INTERNAL_REGISTRY="image-registry.openshift-image-registry.svc:5000"
IMG="${INTERNAL_REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:latest"
info "Image: $IMG"

info "Creating BuildConfig for in-cluster Docker build..."
oc -n "$NAMESPACE" apply -f - <<EOF
apiVersion: image.openshift.io/v1
kind: ImageStream
metadata:
  name: ${IMAGE_NAME}
---
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: ${IMAGE_NAME}
spec:
  source:
    type: Binary
  strategy:
    type: Docker
    dockerStrategy: {}
  output:
    to:
      kind: ImageStreamTag
      name: "${IMAGE_NAME}:latest"
EOF
ok "BuildConfig created."

info "Starting in-cluster build (uploading source)..."
oc start-build "$IMAGE_NAME" \
    --from-dir=. \
    -n "$NAMESPACE" \
    --follow \
    --wait || fail "In-cluster build failed."
ok "Image built and pushed to internal registry."

info "Running: make deploy..."
make deploy IMG="$IMG" || fail "make deploy failed."
ok "Operator deployed."

###############################################################################
# Step 5 — Label nodes for build scheduling
###############################################################################
step "Labeling nodes for build pod scheduling..."
oc label nodes --all aib=true --overwrite || fail "Failed to label nodes."
ok "Nodes labeled with aib=true."

###############################################################################
# Step 6 — Apply OperatorConfig
###############################################################################
step "Applying OperatorConfig..."
oc apply -f config/samples/automotive_v1_operatorconfig.yaml || fail "Failed to apply OperatorConfig."

info "Patching OperatorConfig to use internal registry..."
oc patch operatorconfig config -n "$NAMESPACE" --type=merge \
    -p "{\"spec\":{\"osBuilds\":{\"clusterRegistryRoute\":\"${INTERNAL_REGISTRY}\"}}}" \
    || fail "Failed to patch OperatorConfig."

info "Waiting for operator to reconcile..."
for i in {1..30}; do
    PHASE=$(oc get operatorconfig config -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    if [ "$PHASE" = "Ready" ]; then
        break
    fi
    sleep 5
done
[ "$PHASE" = "Ready" ] || fail "OperatorConfig did not reach Ready phase (current: ${PHASE})"
ok "OperatorConfig reconciled (phase: Ready)."

###############################################################################
# Step 7 — Wait for all pods and verify
###############################################################################
step "Verifying deployment..."
info "Waiting for operator deployment..."
oc wait --for=condition=Available deployment/ado-operator -n "$NAMESPACE" --timeout=120s \
    || fail "Operator deployment not available after 2 minutes."

info "Waiting for build-api deployment..."
oc wait --for=condition=Available deployment/ado-build-api -n "$NAMESPACE" --timeout=120s \
    || fail "Build API deployment not available after 2 minutes."

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
