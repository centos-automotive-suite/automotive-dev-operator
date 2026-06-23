#!/usr/bin/env bash
set -euo pipefail

CRC_API_URL="https://api.crc.testing:6443"
REGISTRY_HOST="image-registry.openshift-image-registry.svc"
CONTAINER_TOOL="${CONTAINER_TOOL:-podman}"
REGISTRY_TLS_VERIFY="${REGISTRY_TLS_VERIFY:-false}"
SCRIPT_PATH="$(realpath "$0")"
REPO_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"

# Accept an optional lane name as the first argument.
# Supported values: operator, bootc, auth (maps to make test-e2e-<lane>).
# Default: run all tests via "make test-e2e".
usage() {
  printf 'Usage: %s [OPTIONS] [LANE]\n\n' "$(basename "$0")"
  printf 'Run e2e tests against a local CRC/OpenShift cluster.\n\n'
  printf 'Lanes:\n'
  printf '  smoke         - quick smoke tests (CRDs, OperatorConfig, Build API, CR lifecycle)\n'
  printf '  operator      - operator health, Tekton tasks, Build API\n'
  printf '  bootc         - bootc container build via caib\n'
  printf '  container-build - Shipwright container build via caib\n'
  printf '  auth          - OIDC authentication (OpenShift or Kind+Dex)\n'
  printf '  package-mode  - package mode builds\n'
  printf '  features      - TTL, image propagation, Build API logs\n'
  printf '  all           - run all tests (default)\n\n'
  printf 'Options:\n'
  printf '  -h, --help    Show this help message and exit\n\n'
  printf 'Environment variables:\n'
  printf '  E2E_NAMESPACE          Override the test namespace (default: e2e-<lane> or e2e-test-all)\n'
  printf '  CONTAINER_TOOL         Container runtime (default: podman)\n'
  printf '  REGISTRY_TLS_VERIFY    TLS verification for registry (default: false)\n'
  printf '  REGISTRY_HOST          Registry host (default: image-registry.openshift-image-registry.svc)\n'
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

E2E_LANE="${1:-}"
case "$E2E_LANE" in
  smoke|operator|bootc|container-build|auth|package-mode|features)
    E2E_MAKE_TARGET="test-e2e-${E2E_LANE}"
    ;;
  ""|all)
    E2E_LANE="all"
    E2E_MAKE_TARGET="test-e2e"
    ;;
  *)
    printf 'Error: unknown lane %q\n\n' "$E2E_LANE" >&2
    usage >&2
    exit 1
    ;;
esac

info() {
  printf '[INFO] %s\n' "$*"
}

fail() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

get_kubeadmin_pass() {
  local pass=""
  local json=""

  json="$(crc console --credentials -o json 2>/dev/null || true)"
  if [[ -n "$json" ]]; then
    pass="$(jq -r '.adminCredentials.password // empty' <<<"$json" 2>/dev/null || true)"
  fi
  if [[ -z "$pass" ]]; then
    pass="$(crc console --credentials 2>/dev/null | sed -n 's/.*-p \([^ ]*\) .*/\1/p' | head -1)"
  fi
  printf '%s' "$pass"
}

ensure_crc_login() {
  local server=""
  local user=""
  server="$(oc whoami --show-server 2>/dev/null || true)"
  user="$(oc whoami 2>/dev/null || true)"
  if [[ "$server" == "$CRC_API_URL" ]] && [[ "$user" == "kubeadmin" ]]; then
    return
  fi

  local kube_pass
  kube_pass="$(get_kubeadmin_pass)"
  [[ -n "$kube_pass" ]] || fail "Could not determine kubeadmin password from CRC."

  info "Logging into CRC as kubeadmin..."
  oc login -u kubeadmin -p "$kube_pass" "$CRC_API_URL" --insecure-skip-tls-verify >/dev/null
}

ensure_tekton() {
  local crds_ready=true
  local crd

  for crd in tasks.tekton.dev pipelines.tekton.dev pipelineruns.tekton.dev taskruns.tekton.dev; do
    if ! oc get crd "$crd" >/dev/null 2>&1; then
      crds_ready=false
      break
    fi
  done

  if [[ "$crds_ready" == "false" ]]; then
    info "Installing OpenShift Pipelines subscription..."
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
  fi

  # Always verify the CSV is Succeeded — CRDs can exist while the operator
  # is still rolling out or in a degraded state.
  info "Waiting for OpenShift Pipelines CSV to be Succeeded..."
  local csv_name=""
  local csv_phase=""
  local csv_snapshot=""
  for _ in {1..90}; do
    csv_name="$(oc get csv -n openshift-operators \
      -o jsonpath='{range .items[?(@.status.phase=="Succeeded")]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
      | awk '/^openshift-pipelines-operator-rh/{print; exit}' || true)"
    if [[ -n "$csv_name" ]]; then
      csv_phase="Succeeded"
      break
    fi

    csv_snapshot="$(oc get csv -n openshift-operators \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\n"}{end}' 2>/dev/null || true)"
    csv_name="$(printf '%s\n' "$csv_snapshot" | awk -F'\t' '$1 ~ /^openshift-pipelines-operator-rh/ {print $1; exit}')"
    csv_phase="$(printf '%s\n' "$csv_snapshot" | awk -F'\t' '$1 ~ /^openshift-pipelines-operator-rh/ {print $2; exit}')"
    [[ "$csv_phase" == "Succeeded" ]] && break
    sleep 10
  done
  [[ "$csv_phase" == "Succeeded" ]] || fail "OpenShift Pipelines CSV not ready (csv: ${csv_name:-unknown}, phase: ${csv_phase:-unknown})."
  info "OpenShift Pipelines is ready."
}

ensure_shipwright() {
  local crds_ready=true
  local crd

  for crd in builds.shipwright.io buildruns.shipwright.io; do
    if ! oc get crd "$crd" >/dev/null 2>&1; then
      crds_ready=false
      break
    fi
  done

  if [[ "$crds_ready" == "true" ]]; then
    info "OpenShift Builds (Shipwright) already installed."
    return
  fi

  info "Installing OpenShift Builds (Shipwright)..."

  cat <<EOF | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: openshift-builds-operator
  namespace: openshift-operators
spec:
  channel: latest
  name: openshift-builds-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

  info "Waiting for OpenShift Builds CSV to be Succeeded..."
  local csv_name=""
  local csv_phase=""
  local csv_snapshot=""
  for _ in {1..90}; do
    csv_name="$(oc get csv -n openshift-operators \
      -o jsonpath='{range .items[?(@.status.phase=="Succeeded")]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
      | awk '/^openshift-builds-operator/{print; exit}' || true)"
    if [[ -n "$csv_name" ]]; then
      csv_phase="Succeeded"
      break
    fi

    csv_snapshot="$(oc get csv -n openshift-operators \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\n"}{end}' 2>/dev/null || true)"
    csv_name="$(printf '%s\n' "$csv_snapshot" | awk -F'\t' '$1 ~ /^openshift-builds-operator/ {print $1; exit}')"
    csv_phase="$(printf '%s\n' "$csv_snapshot" | awk -F'\t' '$1 ~ /^openshift-builds-operator/ {print $2; exit}')"
    [[ "$csv_phase" == "Succeeded" ]] && break
    sleep 10
  done
  [[ "$csv_phase" == "Succeeded" ]] || fail "OpenShift Builds CSV not ready (csv: ${csv_name:-unknown}, phase: ${csv_phase:-unknown})."

  info "Creating ShipwrightBuild CR..."
  cat <<EOF | oc apply -f -
apiVersion: operator.shipwright.io/v1alpha1
kind: ShipwrightBuild
metadata:
  name: openshift-builds
spec:
  targetNamespace: openshift-builds
EOF

  info "Waiting for Shipwright CRDs to be available..."
  for crd in builds.shipwright.io buildruns.shipwright.io; do
    for _ in {1..60}; do
      oc get crd "$crd" >/dev/null 2>&1 && break
      sleep 5
    done
    oc get crd "$crd" >/dev/null 2>&1 || fail "Shipwright CRD $crd not found after 5 minutes."
  done
  info "OpenShift Builds (Shipwright) is ready."
}

set_build_platform() {
  local cluster_arch
  cluster_arch="$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}')"

  case "$cluster_arch" in
    amd64|arm64)
      export BUILD_PLATFORM="linux/${cluster_arch}"
      export ARCH="${cluster_arch}"
      ;;
    *)
      fail "Unsupported cluster architecture: ${cluster_arch}"
      ;;
  esac
}

printf '=========================================\n'
printf '   Running local e2e on CRC/OpenShift    \n'
printf '=========================================\n'

# CRC machines are owned by the user who started them.
# Running as root would use /root as HOME and miss ~/.crc_env / oc / kubeconfig.
# If invoked via sudo, re-exec transparently as the original user.
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    info "Detected root via sudo. Re-executing as '${SUDO_USER}'..."
    exec sudo -H -u "$SUDO_USER" bash -lc 'cd "$1" && shift && exec bash "$@"' bash "$REPO_ROOT" "$SCRIPT_PATH" "$@"
  else
    fail "Do not run this script as root. Run it directly as the CRC user, e.g.:
      bash hack/run-e2e-local.sh"
  fi
fi

cd "$REPO_ROOT"

for bin in crc jq make "$CONTAINER_TOOL"; do
  command -v "$bin" >/dev/null 2>&1 || fail "Missing required dependency: $bin"
done

if [[ -f "$HOME/.crc_env" ]]; then
  # shellcheck disable=SC1090,SC1091
  source "$HOME/.crc_env"
fi

eval "$(crc oc-env)" >/dev/null
export KUBECONFIG="${CRC_KUBECONFIG:-$HOME/.crc/machines/crc/kubeconfig}"

for bin in oc kubectl; do
  command -v "$bin" >/dev/null 2>&1 || fail "Missing required dependency: $bin"
done

crc status >/dev/null 2>&1 || fail "CRC is not running. Start it with 'crc start'."
ensure_crc_login

info "Checking cluster connectivity..."
oc cluster-info >/dev/null
oc wait --for=condition=Ready nodes --all --timeout=60s >/dev/null

info "Labeling nodes for e2e scheduling..."
oc label nodes --all aib=true --overwrite >/dev/null
oc get nodes --show-labels

info "Ensuring external registry route and client trust are configured..."
bash hack/crc/04-expose-default-registry.sh

ensure_tekton
ensure_shipwright
set_build_platform

info "Building caib CLI..."
make build-caib

info "Running e2e lane: ${E2E_LANE} (make ${E2E_MAKE_TARGET})..."
export CONTAINER_TOOL
export REGISTRY_TLS_VERIFY
export REGISTRY_HOST
export OPENSHIFT_INTERNAL_REGISTRY="${OPENSHIFT_INTERNAL_REGISTRY:-image-registry.openshift-image-registry.svc:5000}"
export OPENSHIFT_CLUSTER=true
export CAIB_INSECURE=true
if [ "$E2E_LANE" = "all" ]; then
  export E2E_NAMESPACE="${E2E_NAMESPACE:-e2e-test-all}"
else
  export E2E_NAMESPACE="${E2E_NAMESPACE:-e2e-${E2E_LANE}}"
fi
unset KIND_CLUSTER
make "${E2E_MAKE_TARGET}"

printf '\n=========================================\n'
printf ' Local CRC e2e (%s) completed successfully \n' "${E2E_LANE}"
printf '=========================================\n'

