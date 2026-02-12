#!/bin/bash
set -e

CLUSTER_NAME="automotive-dev-e2e"

cleanup() {
  echo ""
  echo "Cleaning up..."
  kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
}

trap cleanup EXIT

echo "========================================="
echo "Running E2E Tests Locally"
echo "========================================="

echo ""
echo "Checking for existing cluster..."
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Found existing cluster, deleting..."
  kind delete cluster --name "$CLUSTER_NAME"
fi

echo ""
echo "[1/5] Creating Kind cluster..."
kind create cluster --name "$CLUSTER_NAME" --wait 5m
echo "Verifying cluster is up..."
kubectl cluster-info --context "kind-$CLUSTER_NAME"
# Label node for OperatorConfig nodeSelector
kubectl label nodes --all aib=true
kubectl get nodes --show-labels

echo ""
echo "[2/5] Installing Tekton Pipelines..."
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
echo "Waiting for Tekton Pipelines to be ready..."
kubectl wait --for=condition=ready pod --all -n tekton-pipelines --timeout=5m

echo ""
echo "[3/5] Installing NGINX Ingress Controller..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
echo "Waiting for NGINX Ingress Controller to be ready..."
kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=3m

echo ""
echo "[4/5] Running E2E tests..."
export KIND_CLUSTER="$CLUSTER_NAME"
export CONTAINER_TOOL=docker
make test-e2e

echo ""
echo "========================================="
echo "E2E Tests Complete!"
echo "========================================="

