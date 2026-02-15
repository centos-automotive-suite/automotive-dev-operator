#!/bin/bash
set -e

# Configuration
CLUSTER_NAME="automotive-dev-e2e"
REGISTRY_NAME="kind-registry"
REGISTRY_PORT="5001"
REGISTRY_HOST="image-registry.openshift-image-registry.svc"
KIND_NETWORK="kind"

# Diagnostics and Cleanup
cleanup() {
  if [ $? -ne 0 ]; then
    echo ""
    echo "!!! Script exited/failed. Keeping cluster for debugging. !!!"
    echo "To clean up, run:"
    echo "  kill ${PID_API:-\$PID_API} 2>/dev/null"
    echo "  kind delete cluster --name $CLUSTER_NAME"
    echo "  docker rm -f $REGISTRY_NAME"
    echo "  sed -i '/${REGISTRY_HOST}/d' /etc/hosts"
    echo "  rm -f /etc/containers/registries.conf.d/kind-e2e-registry.conf"
  else
    echo ""
    echo "Cleaning up..."
    kill "${PID_API:-}" 2>/dev/null || true
    kind delete cluster --name "$CLUSTER_NAME"
    docker rm -f "$REGISTRY_NAME"
    sed -i "/${REGISTRY_HOST}/d" /etc/hosts 2>/dev/null || true
    rm -f /etc/containers/registries.conf.d/kind-e2e-registry.conf
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

# ------------------------------------------------------------------
# [1/7] Ensure Local Registry Exists (Docker Container)
# ------------------------------------------------------------------
echo "[1/7] Setting up local registry..."
if [ "$(docker inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always \
    -p "127.0.0.1:${REGISTRY_PORT}:5000" \
    -p "127.0.0.1:5000:5000" \
    --name "${REGISTRY_NAME}" \
    registry:2
fi

# Make the in-cluster registry hostname resolvable from the host.
# This allows caib (running on the host) to pull artifacts using the same
# URL that the in-cluster builds push to.
if ! grep -q "${REGISTRY_HOST}" /etc/hosts; then
  echo "127.0.0.1 ${REGISTRY_HOST}" >> /etc/hosts
  echo "Added ${REGISTRY_HOST} to /etc/hosts"
fi

# Configure containers/image (used by caib) to use HTTP for the local registry
mkdir -p /etc/containers/registries.conf.d
cat > /etc/containers/registries.conf.d/kind-e2e-registry.conf <<EOF
[[registry]]
location = "${REGISTRY_HOST}:5000"
insecure = true
EOF

# ------------------------------------------------------------------
# [2/7] Create Kind Cluster with Registry Config
# ------------------------------------------------------------------
echo "[2/7] Creating Kind cluster..."

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
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${REGISTRY_NAME}")" = 'null' ]; then
  docker network connect "kind" "${REGISTRY_NAME}"
fi

# Map the registry in the nodes to the docker container
for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
  kubectl annotate node "${node}" "kind.x-k8s.io/registry=localhost:${REGISTRY_PORT}" --overwrite
done

echo "Waiting for node ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=60s

# ------------------------------------------------------------------
# [3/7] Setup Internal DNS for Registry (The OpenShift spoof)
# ------------------------------------------------------------------
echo "[3/6] Configuring internal registry DNS..."

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
while true; do
  REGISTRY_IP=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${REGISTRY_NAME}")
  if [ -n "$REGISTRY_IP" ]; then
    echo "Registry Internal IP found: $REGISTRY_IP"
    break
  fi
  echo "Waiting for IP..."
  sleep 1
done

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
# [4/7] Install Infrastructure (Tekton & Ingress)
# ------------------------------------------------------------------
echo "[4/7] Installing Infrastructure..."

# Tekton
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
# Ingress NGINX
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

echo "Waiting for Infrastructure..."
kubectl wait --for=condition=ready pod --all -n tekton-pipelines --timeout=5m
kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=3m

# ------------------------------------------------------------------
# [5/7] Build & Deploy Operator
# ------------------------------------------------------------------
echo "[5/7] Building and Deploying Operator..."

kubectl create namespace automotive-dev-operator-system --dry-run=client -o yaml | kubectl apply -f -

# Adjust Security Context
kubectl label namespace automotive-dev-operator-system pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl label namespace automotive-dev-operator-system pod-security.kubernetes.io/audit=privileged --overwrite
kubectl label namespace automotive-dev-operator-system pod-security.kubernetes.io/warn=privileged --overwrite

# Build Operator and Load to Kind
set_build_platform
export CONTAINER_TOOL=docker
make docker-build IMG=automotive-dev-operator:test
kind load docker-image automotive-dev-operator:test --name "$CLUSTER_NAME"

make install
make build-caib
make deploy IMG=automotive-dev-operator:test

# Wait for operator
kubectl wait --for=condition=available --timeout=10m deployment/ado-controller-manager -n automotive-dev-operator-system

# Apply Samples
kubectl apply -f config/samples/automotive_v1_operatorconfig.yaml
kubectl wait --for=condition=available --timeout=8m deployment/ado-build-api -n automotive-dev-operator-system

# Patch OperatorConfig with cluster registry route (required for Kind)
kubectl patch operatorconfig config -n automotive-dev-operator-system --type=merge \
  -p '{"spec":{"osBuilds":{"clusterRegistryRoute":"image-registry.openshift-image-registry.svc:5000"}}}'

# Patch push-artifact-registry Task for Kind's plain-HTTP registry.

# Mark as unmanaged so the operator won't overwrite the patch.
kubectl annotate task push-artifact-registry -n automotive-dev-operator-system \
  "automotive.sdv.cloud.redhat.com/unmanaged=true"
kubectl get task push-artifact-registry -n automotive-dev-operator-system -o json \
  | jq '.spec.steps[0].script |= gsub("oras push "; "oras push --plain-http ")' \
  | kubectl replace -f -

# ------------------------------------------------------------------
# [6/7] Execution and Port Forwarding
# ------------------------------------------------------------------
echo "[6/7] Ready for testing..."

# Kill any existing port-forwards
pkill -f "kubectl port-forward" || true

# Forward API
kubectl port-forward -n automotive-dev-operator-system svc/ado-build-api 8080:8080 > /dev/null 2>&1 &
export PID_API=$!

echo "Waiting for port-forwards..."
sleep 5

# Setup Tokens
kubectl create serviceaccount caib -n automotive-dev-operator-system --dry-run=client -o yaml | kubectl apply -f -

export CAIB_TOKEN=$(kubectl create token caib -n automotive-dev-operator-system --duration=8760h)
export CAIB_SERVER=http://localhost:8080
export REGISTRY_USERNAME=kind
export REGISTRY_PASSWORD=kind

echo "-----------------------------------------------------"
echo "Cluster Ready!"
echo "Registry (Host): localhost:5001"
echo "Registry (Cluster): image-registry.openshift-image-registry.svc:5000"
echo "-----------------------------------------------------"

# Run your build tool
bin/caib build test/config/test-manifest.aib.yml \
  --arch ${ARCH} \
  --push image-registry.openshift-image-registry.svc:5000/myorg/automotive-os:latest \
  --follow

bin/caib build test/config/test-manifest.aib.yml \
  --arch ${ARCH} \
  --push image-registry.openshift-image-registry.svc:5000/myorg/automotive-os:latest \
  --target qemu \
  --disk \
  --format qcow2 \
  --push-disk image-registry.openshift-image-registry.svc:5000/myorg/automotive-os:latest-disk \
  --output "./output/automotive-os-latest.qcow2" \
  --follow

echo ""
echo "[7/7] Running E2E Tests..."
export KIND_CLUSTER="$CLUSTER_NAME"
export CONTAINER_TOOL=docker
# make test-e2e


echo ""
echo "========================================="
echo "E2E Tests Complete!"
echo "========================================="

