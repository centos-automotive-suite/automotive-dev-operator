#!/bin/bash
set -e

# Configuration
CLUSTER_NAME="automotive-dev-e2e"
REGISTRY_NAME="kind-registry"
REGISTRY_PORT="5001"
REGISTRY_HOST="image-registry.openshift-image-registry.svc"
KIND_NETWORK="kind"
TEKTON_VERSION="v1.9.1"
INGRESS_NGINX_VERSION="v1.14.3"

# Ownership flags: only tear down resources this invocation created
CREATED_REGISTRY=false
CREATED_HOSTS_ENTRY=false
CREATED_REGISTRIES_CONF=false
REGISTRIES_CONF_BACKUP=""

# Diagnostics and Cleanup
cleanup() {
  local exit_code=$?
  local CONF_FILE="${HOME}/.config/containers/registries.conf.d/kind-e2e-registry.conf"
  if [ $exit_code -ne 0 ]; then
    echo ""
    echo "!!! Script exited/failed. Keeping cluster for debugging. !!!"
    echo "To clean up, run:"
    echo "  kind delete cluster --name $CLUSTER_NAME"
    [ "$CREATED_REGISTRY" = "true" ] && echo "  docker rm -f $REGISTRY_NAME"
    [ "$CREATED_HOSTS_ENTRY" = "true" ] && echo "  sudo sed -i '/${REGISTRY_HOST}/d' /etc/hosts"
    [ "$CREATED_REGISTRIES_CONF" = "true" ] && echo "  rm -f $CONF_FILE"
    [ -n "$REGISTRIES_CONF_BACKUP" ] && echo "  mv $REGISTRIES_CONF_BACKUP $CONF_FILE  # restore original"
  else
    echo ""
    echo "Cleaning up..."
    kind delete cluster --name "$CLUSTER_NAME"
    [ "$CREATED_REGISTRY" = "true" ] && docker rm -f "$REGISTRY_NAME"
    [ "$CREATED_HOSTS_ENTRY" = "true" ] && sudo sed -i "/${REGISTRY_HOST}/d" /etc/hosts 2>/dev/null || true
    if [ "$CREATED_REGISTRIES_CONF" = "true" ]; then
      rm -f "$CONF_FILE"
    elif [ -n "$REGISTRIES_CONF_BACKUP" ]; then
      mv "$REGISTRIES_CONF_BACKUP" "$CONF_FILE"
    fi
    echo "Cleanup complete."
  fi
}
trap cleanup EXIT

set_build_platform() {
  local host_arch
  host_arch=$(uname -m)
  case "$host_arch" in
    x86_64)
      export BUILD_PLATFORM=linux/amd64
      export ARCH=amd64
      ;;
    arm64|aarch64)
      export BUILD_PLATFORM=linux/arm64
      export ARCH=arm64
      ;;
    *)
      echo "Unsupported architecture: $host_arch (supported: x86_64, arm64, aarch64)"
      exit 1
      ;;
  esac
}

echo "========================================="
echo "   Initializing Local Dev Environment    "
echo "========================================="

for bin in docker kind kubectl jq make; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "Missing required dependency: $bin" >&2
    exit 1
  }
done

# ------------------------------------------------------------------
# [1/5] Ensure Local Registry Exists (Docker Container)
# ------------------------------------------------------------------
echo "[1/5] Setting up local registry..."
verify_registry_ports() {
  docker inspect -f '{{json .NetworkSettings.Ports}}' "${REGISTRY_NAME}" 2>/dev/null |
    jq -e --arg rp "${REGISTRY_PORT}" '
      (."5000/tcp" // []) |
      (any(.[]; .HostIp == "127.0.0.1" and .HostPort == $rp)) and
      (any(.[]; .HostIp == "127.0.0.1" and .HostPort == "5000"))
    ' >/dev/null 2>&1
}

create_registry() {
  CREATED_REGISTRY=true
  docker run \
    -d --restart=always \
    -p "127.0.0.1:${REGISTRY_PORT}:5000" \
    -p "127.0.0.1:5000:5000" \
    --name "${REGISTRY_NAME}" \
    registry:2
}

REGISTRY_STATE="$(docker inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || echo "missing")"
if [ "$REGISTRY_STATE" = "true" ]; then
  if verify_registry_ports; then
    echo "Registry container '${REGISTRY_NAME}' is already running with correct ports."
  else
    echo "Registry container '${REGISTRY_NAME}' has wrong port bindings. Recreating..."
    docker rm -f "${REGISTRY_NAME}"
    create_registry
  fi
elif [ "$REGISTRY_STATE" = "false" ]; then
  if verify_registry_ports; then
    echo "Registry container '${REGISTRY_NAME}' exists but is stopped. Starting..."
    docker start "${REGISTRY_NAME}"
  else
    echo "Registry container '${REGISTRY_NAME}' has wrong port bindings. Recreating..."
    docker rm -f "${REGISTRY_NAME}"
    create_registry
  fi
else
  create_registry
fi

# Make the in-cluster registry hostname resolvable from the host.
# This allows caib (running on the host) to pull artifacts using the same
# URL that the in-cluster builds push to.
if ! grep -q "${REGISTRY_HOST}" /etc/hosts; then
  echo "127.0.0.1 ${REGISTRY_HOST}" | sudo tee -a /etc/hosts >/dev/null
  echo "Added ${REGISTRY_HOST} to /etc/hosts"
  CREATED_HOSTS_ENTRY=true
fi

# Configure containers/image (used by caib) to use HTTP for the local registry.
# Per-user config avoids requiring sudo for system-wide /etc/containers paths.
REGISTRIES_CONF_DIR="${HOME}/.config/containers/registries.conf.d"
REGISTRIES_CONF_FILE="${REGISTRIES_CONF_DIR}/kind-e2e-registry.conf"
EXPECTED_CONF="[[registry]]
location = \"${REGISTRY_HOST}:5000\"
insecure = true"
if [ -e "$REGISTRIES_CONF_FILE" ] && [ "$(cat "$REGISTRIES_CONF_FILE")" = "$EXPECTED_CONF" ]; then
  echo "Registries config already matches, skipping write."
else
  if [ ! -e "$REGISTRIES_CONF_FILE" ]; then
    CREATED_REGISTRIES_CONF=true
  else
    REGISTRIES_CONF_BACKUP="$(mktemp)"
    cp "$REGISTRIES_CONF_FILE" "$REGISTRIES_CONF_BACKUP"
    echo "Backed up existing registries config to $REGISTRIES_CONF_BACKUP"
  fi
  mkdir -p "$REGISTRIES_CONF_DIR"
  tee "$REGISTRIES_CONF_FILE" >/dev/null <<EOF
[[registry]]
location = "${REGISTRY_HOST}:5000"
insecure = true
EOF
fi

# ------------------------------------------------------------------
# [2/5] Create Kind Cluster with Registry Config
# ------------------------------------------------------------------
echo "[2/5] Creating Kind cluster..."

# Check if cluster exists
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Found existing cluster, deleting..."
  kind delete cluster --name "$CLUSTER_NAME"
fi

kind create cluster --name "$CLUSTER_NAME" --wait 5m
echo "Verifying cluster is up..."
kubectl cluster-info --context "kind-$CLUSTER_NAME"
# Label node for OperatorConfig nodeSelector
kubectl label nodes --all aib=true
kubectl get nodes --show-labels



# Connect the registry to the cluster network if not already connected
echo "Connecting registry to Kind network..."
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.'"${KIND_NETWORK}"'}}' "${REGISTRY_NAME}")" = 'null' ]; then
  docker network connect "${KIND_NETWORK}" "${REGISTRY_NAME}"
fi

# Map the registry in the nodes to the docker container
for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
  kubectl annotate node "${node}" "kind.x-k8s.io/registry=localhost:${REGISTRY_PORT}" --overwrite
done

echo "Waiting for node ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=60s

# ------------------------------------------------------------------
# [3/5] Setup Internal DNS for Registry (The OpenShift spoof)
# ------------------------------------------------------------------
echo "[3/5] Configuring internal registry DNS..."

# 1. Document the local registry (standard Kind practice)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REGISTRY_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

# 2. Create the Namespace
kubectl create namespace openshift-image-registry --dry-run=client -o yaml | kubectl apply -f -

# 3. ROBUST IP FETCHING
# Wait until the registry has an IP on the 'kind' network
echo "Waiting for registry IP assignment..."
REGISTRY_IP=""
for i in $(seq 1 30); do
  REGISTRY_IP=$(docker inspect -f '{{.NetworkSettings.Networks.'"${KIND_NETWORK}"'.IPAddress}}' "${REGISTRY_NAME}" 2>/dev/null || true)
  if [ -n "$REGISTRY_IP" ]; then
    echo "Registry Internal IP found: $REGISTRY_IP"
    break
  fi
  echo "Waiting for IP... (attempt $i/30)"
  sleep 1
done
if [ -z "$REGISTRY_IP" ]; then
  echo "Failed to discover a Kind-network IP for '${REGISTRY_NAME}' after 30 attempts" >&2
  exit 1
fi

# 4. Create Service and Endpoints manually
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: image-registry
  namespace: openshift-image-registry
spec:
  ports:
  - port: 5000
    protocol: TCP
    targetPort: 5000
  clusterIP: None
---
apiVersion: v1
kind: Endpoints
metadata:
  name: image-registry
  namespace: openshift-image-registry
subsets:
- addresses:
  - ip: ${REGISTRY_IP}
  ports:
  - port: 5000
    name: registry
    protocol: TCP
EOF

# ------------------------------------------------------------------
# [4/5] Install Infrastructure (Tekton & Ingress)
# ------------------------------------------------------------------
echo "[4/5] Installing Infrastructure..."

# Tekton
kubectl apply --filename "https://infra.tekton.dev/tekton-releases/pipeline/previous/${TEKTON_VERSION}/release.yaml"
# Ingress NGINX
kubectl apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-${INGRESS_NGINX_VERSION}/deploy/static/provider/kind/deploy.yaml"

echo "Waiting for Infrastructure..."
kubectl wait --for=condition=ready pod --all -n tekton-pipelines --timeout=5m
kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=3m
make build-caib
# ------------------------------------------------------------------
# [5/5] Run E2E Tests (self-contained: deploys operator, tests, tears down)
# ------------------------------------------------------------------
echo "[5/5] Running E2E Tests..."
set_build_platform
export CONTAINER_TOOL=docker
export KIND_CLUSTER="$CLUSTER_NAME"
export CAIB_SERVER=http://localhost:8080
export REGISTRY_USERNAME=kind
export REGISTRY_PASSWORD=kind
export REGISTRY_HOST
export CLUSTER_NAME
make test-e2e


echo ""
echo "========================================="
echo "[5/5] All Tests Complete!"
echo "========================================="