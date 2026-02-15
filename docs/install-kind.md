# Install CentOS Automotive Suite on local Kind Kubernetes

This describes how to run the **CentOS Automotive Suite** operator (automotive-dev-operator) on a local **Kind** (Kubernetes in Docker) cluster. The operator provides ImageBuild CRs, Tekton-based OS image builds, and an optional Build API used by the `caib` CLI.

> **Automated script:** All steps below are automated by `hack/run-e2e-new.sh`. Run it from the repo root for a fully working setup. This document explains each step for manual setup or troubleshooting.

## Prerequisites

- **Go** 1.22+
- **Docker** (or Podman with `CONTAINER_TOOL=podman`)
- **kubectl**
- **Kind**: [install Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- **jq** (for patching Tekton Tasks)
- **Make** (for `make install`, `make deploy`, etc.)

## 1. Set up local registry

Start a Docker registry container with two port mappings:
- Port `5001` for general host access
- Port `5000` so the in-cluster URL `image-registry.openshift-image-registry.svc:5000` is reachable from the host (used by `caib --output` to download artifacts)

```bash
REGISTRY_NAME="kind-registry"
REGISTRY_HOST="image-registry.openshift-image-registry.svc"

docker run -d --restart=always \
  -p "127.0.0.1:5001:5000" \
  -p "127.0.0.1:5000:5000" \
  --name "${REGISTRY_NAME}" \
  registry:2
```

### 1a. Make the registry hostname resolvable from the host

Add an `/etc/hosts` entry so `caib` (running on the host) can reach the registry using the same URL the in-cluster builds use:

```bash
echo "127.0.0.1 ${REGISTRY_HOST}" >> /etc/hosts
```

### 1b. Configure insecure registry for caib

The `containers/image` library (used by `caib`) tries HTTPS by default. Create a drop-in config so it uses HTTP for this registry:

```bash
mkdir -p /etc/containers/registries.conf.d
cat > /etc/containers/registries.conf.d/kind-e2e-registry.conf <<EOF
[[registry]]
location = "${REGISTRY_HOST}:5000"
insecure = true
EOF
```

## 2. Create Kind cluster

```bash
CLUSTER_NAME="automotive-dev-e2e"

kind create cluster --name "$CLUSTER_NAME" --wait 5m
kubectl cluster-info --context "kind-$CLUSTER_NAME"
```

Label nodes so build pods can schedule (matches sample OperatorConfig `nodeSelector`):

```bash
kubectl label nodes --all aib=true
```

### 2a. Connect registry to Kind network

```bash
docker network connect kind "${REGISTRY_NAME}"
```

Annotate nodes (standard Kind registry practice):

```bash
for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
  kubectl annotate node "${node}" "kind.x-k8s.io/registry=localhost:5001" --overwrite
done
```

## 3. Set up internal DNS for registry (OpenShift spoof)

The operator's build scripts use `image-registry.openshift-image-registry.svc:5000` (the OpenShift internal registry URL). On Kind, we create a headless Service and Endpoints pointing at the Docker registry container's IP on the Kind network.

```bash
# Document the local registry (standard Kind practice)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:5001"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

# Create the namespace
kubectl create namespace openshift-image-registry --dry-run=client -o yaml | kubectl apply -f -

# Get the registry container's IP on the Kind network
REGISTRY_IP=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${REGISTRY_NAME}")
echo "Registry IP: $REGISTRY_IP"

# Create Service and Endpoints
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
```

After this, `image-registry.openshift-image-registry.svc:5000` resolves inside the cluster to your Docker registry.

## 4. Install infrastructure (Tekton and Ingress)

```bash
# Tekton Pipelines
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
kubectl wait --for=condition=ready pod --all -n tekton-pipelines --timeout=5m

# NGINX Ingress (Kind variant)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=3m
```

## 5. Create namespace and allow privileged pods

```bash
kubectl create namespace automotive-dev-operator-system --dry-run=client -o yaml | kubectl apply -f -
```

### 5a. Pod Security Admission (required for Kind)

The build-image Tekton step runs with `privileged: true` and `seLinuxOptions.type: unconfined_t` (required for AIB/osbuild). On Kubernetes 1.23+ with Pod Security Admission, the namespace must allow privileged pods:

```bash
kubectl label namespace automotive-dev-operator-system pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl label namespace automotive-dev-operator-system pod-security.kubernetes.io/audit=privileged --overwrite
kubectl label namespace automotive-dev-operator-system pod-security.kubernetes.io/warn=privileged --overwrite
```

## 6. Build and deploy the operator

Detect the host architecture and build:

```bash
# Set BUILD_PLATFORM based on host arch
case "$(uname -m)" in
  x86_64)       export BUILD_PLATFORM=linux/amd64; export ARCH=amd64 ;;
  arm64|aarch64) export BUILD_PLATFORM=linux/arm64; export ARCH=arm64 ;;
esac

export CONTAINER_TOOL=docker
make docker-build IMG=automotive-dev-operator:test
kind load docker-image automotive-dev-operator:test --name "$CLUSTER_NAME"

make install
make build-caib
make deploy IMG=automotive-dev-operator:test
```

Wait for the controller:

```bash
kubectl wait --for=condition=available --timeout=10m deployment/ado-controller-manager -n automotive-dev-operator-system
```

## 7. Apply OperatorConfig and patch for Kind

### 7a. Apply OperatorConfig

```bash
kubectl apply -f config/samples/automotive_v1_operatorconfig.yaml
kubectl wait --for=condition=available --timeout=8m deployment/ado-build-api -n automotive-dev-operator-system
```

### 7b. Patch OperatorConfig with cluster registry route

The `clusterRegistryRoute` tells the build pipeline where to find the cluster registry. Without this, the `build-image` step cannot pull the builder image and fails with `connection refused` on `localhost`.

```bash
kubectl patch operatorconfig config -n automotive-dev-operator-system --type=merge \
  -p '{"spec":{"osBuilds":{"clusterRegistryRoute":"image-registry.openshift-image-registry.svc:5000"}}}'
```

### 7c. Patch push-artifact-registry Task for plain HTTP

The `push-artifact-registry` Tekton Task uses `oras push` which defaults to HTTPS. On Kind the registry is HTTP-only. Patch the Task in-cluster (no product code change) and mark it as unmanaged so the operator won't overwrite it:

```bash
kubectl annotate task push-artifact-registry -n automotive-dev-operator-system \
  "automotive.sdv.cloud.redhat.com/unmanaged=true"

kubectl get task push-artifact-registry -n automotive-dev-operator-system -o json \
  | jq '.spec.steps[0].script |= gsub("oras push "; "oras push --plain-http ")' \
  | kubectl replace -f -
```

## 8. Set up Build API access

### 8a. Port-forward the Build API

```bash
kubectl port-forward -n automotive-dev-operator-system svc/ado-build-api 8080:8080 &
sleep 3
```

### 8b. Create a service account token

Kind has no OIDC; the Build API requires a bearer token:

```bash
kubectl create serviceaccount caib -n automotive-dev-operator-system --dry-run=client -o yaml | kubectl apply -f -
export CAIB_TOKEN=$(kubectl create token caib -n automotive-dev-operator-system --duration=8760h)
export CAIB_SERVER=http://localhost:8080
```

### 8c. Set registry credentials

The Build API requires registry credentials when a push target is set. Use dummy credentials for the local unauthenticated registry:

```bash
export REGISTRY_USERNAME=kind
export REGISTRY_PASSWORD=kind
```

## 9. Run builds

### Container-only build

```bash
bin/caib build config/samples/my-manifest.aib.yml \
  --arch ${ARCH} \
  --push image-registry.openshift-image-registry.svc:5000/myorg/automotive-os:latest \
  --follow
```

### Container + disk image build with download

```bash
bin/caib build config/samples/my-manifest.aib.yml \
  --arch ${ARCH} \
  --push image-registry.openshift-image-registry.svc:5000/myorg/automotive-os:latest \
  --target qemu \
  --disk \
  --format qcow2 \
  --push-disk image-registry.openshift-image-registry.svc:5000/myorg/automotive-os:latest-disk \
  --output "./output/automotive-os-latest.qcow2" \
  --follow
```

The `--output` flag downloads the disk artifact from the registry to a local file. This works because steps 1a and 1b made the in-cluster registry hostname resolvable and accessible over HTTP from the host.

## 10. Verify

```bash
kubectl get pods -n automotive-dev-operator-system
kubectl get operatorconfig -n automotive-dev-operator-system
kubectl get pipelinerun -n automotive-dev-operator-system
```

## Uninstall

```bash
# Kill port-forwards
pkill -f "kubectl port-forward" || true

# Remove operator and CRDs
kubectl delete -f config/samples/automotive_v1_operatorconfig.yaml --ignore-not-found
make undeploy
make uninstall

# Delete cluster and registry
kind delete cluster --name automotive-dev-e2e
docker rm -f kind-registry

# Clean up host-level configuration
sed -i "/image-registry.openshift-image-registry.svc/d" /etc/hosts 2>/dev/null || true
rm -f /etc/containers/registries.conf.d/kind-e2e-registry.conf
```

## Summary

| Step | Action |
|------|--------|
| 1 | Start local Docker registry with ports 5001+5000; add `/etc/hosts` entry; configure insecure registry |
| 2 | Create Kind cluster; label nodes with `aib=true`; connect registry to Kind network |
| 3 | Create OpenShift registry spoof (Service + Endpoints in `openshift-image-registry` namespace) |
| 4 | Install Tekton Pipelines and NGINX Ingress |
| 5 | Create operator namespace; label for Pod Security Admission (privileged) |
| 6 | Build operator image, load into Kind, install CRDs, deploy operator |
| 7 | Apply OperatorConfig; patch `clusterRegistryRoute`; patch `push-artifact-registry` Task for plain HTTP |
| 8 | Port-forward Build API; create service account token; set registry credentials |
| 9 | Run builds with `caib` |

All steps are automated by `hack/run-e2e-new.sh`.

## Troubleshooting

### Build fails with "connection refused" on localhost during build-image

The `clusterRegistryRoute` is not set in OperatorConfig. The build-image step tries to pull the builder image from `localhost` instead of the cluster registry. Fix with step 7b.

### Push fails with "server gave HTTP response to HTTPS client"

The `push-artifact-registry` Task needs `--plain-http` for `oras push`. Fix with step 7c.

### Download fails with "no such host" or "connection refused" on port 5000

The in-cluster registry hostname is not resolvable from the host, or port 5000 is not mapped. Verify:
- `/etc/hosts` contains `127.0.0.1 image-registry.openshift-image-registry.svc` (step 1a)
- Registry container has port 5000 mapped: `docker port kind-registry` should show `5000/tcp -> 127.0.0.1:5000` (step 1)
- Insecure registry config exists: `cat /etc/containers/registries.conf.d/kind-e2e-registry.conf` (step 1b)

### Download fails with "http: server gave HTTP response to HTTPS client"

The insecure registry config is missing. Create it per step 1b.

### Pod scheduling fails with "didn't match Pod's node affinity/selector"

Nodes are missing the `aib=true` label. Fix: `kubectl label nodes --all aib=true`

### "Fatal glibc error: CPU does not support x86-64-v3"

The host CPU is too old (pre-Haswell). Newer Fedora/CentOS container images require x86-64-v3 instruction set (Intel Haswell+ / AMD Excavator+).

### OpenShift security annotations (SCC) on Kind

The OpenShift API defines security annotations (e.g. `openshift.io/sa.scc.uid-range`). **This operator does not set or read those annotations.** They are only present in the vendored OpenShift API. On Kind:

- **Do not add** OpenShift SCC annotations; they have no effect (Kind has no SCC admission).
- **Pod security**: Use Pod Security Admission labels (step 5a) instead.
- RBAC for `security.openshift.io` and `route.openshift.io` is harmless on Kind (those APIs do not exist).
