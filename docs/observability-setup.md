# Observability Setup Guide

This guide deploys the OpenShift observability stack for the automotive-dev-operator:
log collection (Loki), distributed tracing (Tempo), and console integration (UIPlugins).

All components are optional. The operator functions normally without any of them.

## Prerequisites

- Cluster admin access
- S3-compatible object storage (this guide uses MinIO for dev/test)

## Architecture

```text
                ┌─────────────────────────────────────────┐
                │          OCP Console (UIPlugins)         │
                │  Logs │ Traces │ Dashboards │ Korrel8r  │
                └───┬───────┬────────┬──────────┬─────────┘
                    │       │        │          │
               ┌────▼──┐ ┌──▼───┐ ┌──▼──┐  ┌───▼────┐
               │ Loki  │ │Tempo │ │Prom.│  │Korrel8r│
               │Stack  │ │Stack │ │     │  │        │
               └───▲───┘ └──▲───┘ └──▲──┘  └────────┘
                   │        │        │
               ┌───┴───┐ ┌──┴────┐   │
               │Vector │ │ OTel  │   │ (scrape)
               │(DS)   │ │Collctr│   │
               └───▲───┘ └──▲────┘   │
                   │        │        │
          pod stdout    OTLP SDK   /metrics
          (AIB,oras)   (Go ctrl)  (gauges)
```

- **Vector → Loki**: Passive log collection from pod stdout. No code changes needed.
  Covers external tools (AIB, oras, jmp) and controller logs.
- **OTel → Tempo**: Active tracing from Go controller. Optional SDK instrumentation.
- **Prometheus**: Built into controller-runtime. Metrics scraped from `/metrics`.

## 1. Install Operators

```bash
# Loki Operator
cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: loki-operator
  namespace: openshift-operators-redhat
spec:
  channel: stable-6.4
  name: loki-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# Cluster Logging Operator
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: openshift-logging
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-logging
  namespace: openshift-logging
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: cluster-logging
  namespace: openshift-logging
spec:
  channel: stable-6.4
  name: cluster-logging
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# Cluster Observability Operator
cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: cluster-observability-operator
  namespace: openshift-operators
spec:
  channel: stable
  name: cluster-observability-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# Tempo Operator (optional — only needed for distributed tracing)
cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: tempo-product
  namespace: openshift-operators
spec:
  channel: stable
  name: tempo-product
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# OpenTelemetry Operator (optional — only needed for distributed tracing)
cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: opentelemetry-product
  namespace: openshift-operators
spec:
  channel: stable
  name: opentelemetry-product
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF
```

Wait for all operators to reach `Succeeded`:

```bash
oc get csv -n openshift-operators
oc get csv -n openshift-operators-redhat
oc get csv -n openshift-logging
```

## 2. Deploy MinIO (dev/test only)

For production, use AWS S3, Google Cloud Storage, Azure Blob, or OpenShift Data Foundation.

```bash
cat <<'EOF' | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
  namespace: openshift-logging
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minio
  template:
    metadata:
      labels:
        app: minio
    spec:
      containers:
        - name: minio
          image: quay.io/minio/minio:latest
          args: ["server", "/data", "--console-address", ":9001"]
          env:
            - name: MINIO_ROOT_USER
              value: minioadmin
            - name: MINIO_ROOT_PASSWORD
              value: minioadmin
          ports:
            - containerPort: 9000
            - containerPort: 9001
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: minio
  namespace: openshift-logging
spec:
  selector:
    app: minio
  ports:
    - name: api
      port: 9000
    - name: console
      port: 9001
EOF
```

Wait for the MinIO pod, then create buckets:

```bash
oc wait -n openshift-logging deployment/minio --for=condition=Available --timeout=60s

# Create buckets for Loki and Tempo
oc exec -n openshift-logging deployment/minio -- \
  mc alias set local http://localhost:9000 minioadmin minioadmin
oc exec -n openshift-logging deployment/minio -- mc mb local/loki --ignore-existing
oc exec -n openshift-logging deployment/minio -- mc mb local/tempo --ignore-existing
```

## 3. Deploy LokiStack

```bash
# Storage secret
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: logging-loki-s3
  namespace: openshift-logging
stringData:
  access_key_id: minioadmin
  access_key_secret: minioadmin
  bucketnames: loki
  endpoint: http://minio.openshift-logging.svc:9000
EOF

# LokiStack
cat <<'EOF' | oc apply -f -
apiVersion: loki.grafana.com/v1
kind: LokiStack
metadata:
  name: logging-loki
  namespace: openshift-logging
spec:
  size: 1x.extra-small
  storage:
    schemas:
      - effectiveDate: "2024-10-25"
        version: v13
    secret:
      name: logging-loki-s3
      type: s3
  storageClassName: efs-sc
  limits:
    global:
      retention:
        days: 1
  tenants:
    mode: openshift-logging
EOF
```

Wait for LokiStack to be ready:

```bash
oc wait -n openshift-logging lokistack/logging-loki \
  --for=condition=Ready --timeout=300s
```

## 4. Configure Log Collection

```bash
# Create collector service account
oc create sa collector -n openshift-logging

# Grant log collection and Loki write permissions
oc adm policy add-cluster-role-to-user collect-application-logs \
  -z collector -n openshift-logging
oc adm policy add-cluster-role-to-user collect-infrastructure-logs \
  -z collector -n openshift-logging
oc adm policy add-cluster-role-to-user cluster-logging-write-application-logs \
  -z collector -n openshift-logging
oc adm policy add-cluster-role-to-user cluster-logging-write-infrastructure-logs \
  -z collector -n openshift-logging
oc create clusterrolebinding logging-collector-logs-writer \
  --clusterrole=logging-collector-logs-writer \
  --serviceaccount=openshift-logging:collector

# Deploy ClusterLogForwarder (scoped to operator namespace only)
cat <<'EOF' | oc apply -f -
apiVersion: observability.openshift.io/v1
kind: ClusterLogForwarder
metadata:
  name: collector
  namespace: openshift-logging
spec:
  serviceAccount:
    name: collector
  inputs:
    - name: ado-app-logs
      type: application
      application:
        namespaces:
          - automotive-dev-operator-system
  outputs:
    - name: default-lokistack
      type: lokiStack
      lokiStack:
        target:
          name: logging-loki
          namespace: openshift-logging
        authentication:
          token:
            from: serviceAccount
        labelKeys:
          application:
            labelKeys:
              - kubernetes.labels.automotive_sdv_cloud_redhat_com_trace-id
      tls:
        ca:
          configMapName: openshift-service-ca.crt
          key: service-ca.crt
  pipelines:
    - name: ado-logs
      inputRefs:
        - ado-app-logs
      outputRefs:
        - default-lokistack
EOF
```

Only logs from `automotive-dev-operator-system` are collected. This covers the
operator, build-api, build task pods, OTEL collector, and workspace pods.

The `labelKeys` config promotes the build trace-id pod label to a Loki stream label,
enabling direct label queries instead of full-text search:

```logql
{kubernetes_labels_automotive_sdv_cloud_redhat_com_trace_id="<trace-id>"}
```

Verify Vector collectors are running:

```bash
oc get ds collector -n openshift-logging
# Should show READY = node count
```

## 5. Deploy TempoStack (optional)

Skip this section if you only need log collection.

```bash
# Storage secret (reuses the same MinIO, different bucket)
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: tracing-system
---
apiVersion: v1
kind: Secret
metadata:
  name: tempo-s3
  namespace: tracing-system
stringData:
  endpoint: http://minio.openshift-logging.svc:9000
  bucket: tempo
  access_key_id: minioadmin
  access_key_secret: minioadmin
EOF

# TempoStack
cat <<'EOF' | oc apply -f -
apiVersion: tempo.grafana.com/v1alpha1
kind: TempoStack
metadata:
  name: tempo
  namespace: tracing-system
spec:
  storageSize: 1Gi
  storage:
    secret:
      name: tempo-s3
      type: s3
  template:
    gateway:
      enabled: true
    queryFrontend:
      jaegerQuery:
        enabled: true
  tenants:
    mode: openshift
    authentication:
      - tenantName: dev
        tenantId: "1610b0c3-c509-4592-a256-a1871353dbfa"
  resources:
    total:
      limits:
        memory: 2Gi
        cpu: 2000m
EOF
```

## 6. Deploy OTel Collector (optional)

Receives OTLP traces from the operator and forwards to Tempo.
Only needed if TempoStack is deployed.

Tempo's distributor requires mTLS using Tempo's own CA (not the OpenShift service CA).
The collector must also send the `X-Scope-OrgID` header with the tenant **UUID**
(not the tenant name) — the gateway maps OAuth users to UUIDs on the read path,
so the write path must match.

### 6a. Extract Tempo CA and generate client certificate

The signing CA secret name depends on your TempoStack name and Tempo Operator version.
Verify with: `oc get secrets -n tracing-system | grep signing-ca`

```bash
# Extract Tempo's signing CA (adjust secret name if your TempoStack is not named "tempo")
oc get secret tempo-tempo-signing-ca -n tracing-system \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/tempo-ca.crt
oc get secret tempo-tempo-signing-ca -n tracing-system \
  -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/tempo-ca.key

# Generate a client cert signed by Tempo's CA
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /tmp/otel-client.key -out /tmp/otel-client.csr \
  -subj "/CN=otel-collector"
openssl x509 -req -in /tmp/otel-client.csr \
  -CA /tmp/tempo-ca.crt -CAkey /tmp/tempo-ca.key \
  -CAcreateserial -out /tmp/otel-client.crt -days 365

# Create secrets/configmaps in the operator namespace
oc create secret tls otel-tempo-client-tls \
  -n automotive-dev-operator-system \
  --cert=/tmp/otel-client.crt --key=/tmp/otel-client.key
oc create configmap tempo-ca \
  -n automotive-dev-operator-system \
  --from-file=ca.crt=/tmp/tempo-ca.crt

# Clean up local files
rm /tmp/tempo-ca.crt /tmp/tempo-ca.key /tmp/tempo-ca.srl /tmp/otel-client.*
```

### 6b. Allow cross-namespace traffic to Tempo distributor

The Tempo operator creates NetworkPolicies that block cross-namespace ingress.

```bash
cat <<'EOF' | oc apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-otel-to-distributor
  namespace: tracing-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: distributor
      app.kubernetes.io/instance: tempo
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: automotive-dev-operator-system
      ports:
        - port: 4317
          protocol: TCP
EOF
```

### 6c. Deploy the collector

Replace `<TENANT-UUID>` with the `tenantId` from your TempoStack spec.

```bash
TENANT_UUID="1610b0c3-c509-4592-a256-a1871353dbfa"  # from TempoStack .spec.tenants

cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: otel-collector
  namespace: automotive-dev-operator-system
---
apiVersion: opentelemetry.io/v1beta1
kind: OpenTelemetryCollector
metadata:
  name: otel
  namespace: automotive-dev-operator-system
spec:
  mode: deployment
  serviceAccount: otel-collector
  volumes:
    - name: tempo-client-tls
      secret:
        secretName: otel-tempo-client-tls
    - name: tempo-ca
      configMap:
        name: tempo-ca
  volumeMounts:
    - name: tempo-client-tls
      mountPath: /var/run/tempo-client-tls
      readOnly: true
    - name: tempo-ca
      mountPath: /var/run/tempo-ca
      readOnly: true
  config:
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318
    processors:
      batch:
        timeout: 5s
      resource:
        attributes:
          - key: service.name
            value: automotive-dev-operator
            action: upsert
    exporters:
      otlp/tempo:
        endpoint: tempo-tempo-distributor.tracing-system.svc:4317
        tls:
          ca_file: /var/run/tempo-ca/ca.crt
          cert_file: /var/run/tempo-client-tls/tls.crt
          key_file: /var/run/tempo-client-tls/tls.key
        headers:
          X-Scope-OrgID: "${TENANT_UUID}"
    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [batch, resource]
          exporters: [otlp/tempo]
EOF
```

### 6d. Enable tracing and monitoring in OperatorConfig

The operator reads tracing configuration from OperatorConfig at startup.
After patching, delete the operator pod to pick up the new config.

```bash
oc patch operatorconfig config -n automotive-dev-operator-system --type=merge -p '{
  "spec": {
    "monitoring": {
      "enabled": true
    },
    "tracing": {
      "enabled": true,
      "endpoint": "otel-collector.automotive-dev-operator-system.svc:4317"
    }
  }
}'

# Restart the operator and build controller pods to pick up tracing config (OLM
# manages the deployments, so oc rollout restart does not work)
oc delete pod -n automotive-dev-operator-system -l 'control-plane in (operator,build-controller)'
```

Optional tracing fields:
- `samplingRatio`: fraction of traces sampled, `"0"` to `"1"` (default `"1"` = 100%)
- `monitoring.interval`: Prometheus scrape interval (default `"30s"`)

The collector is available at:
- gRPC: `otel-collector.automotive-dev-operator-system.svc:4317`
- HTTP: `otel-collector.automotive-dev-operator-system.svc:4318`

## 7. Enable Console UIPlugins

```bash
cat <<'EOF' | oc apply -f -
apiVersion: observability.openshift.io/v1alpha1
kind: UIPlugin
metadata:
  name: logging
spec:
  type: Logging
  logging:
    lokiStack:
      name: logging-loki
    timeout: 30s
---
apiVersion: observability.openshift.io/v1alpha1
kind: UIPlugin
metadata:
  name: distributed-tracing
spec:
  type: DistributedTracing
---
apiVersion: observability.openshift.io/v1alpha1
kind: UIPlugin
metadata:
  name: dashboards
spec:
  type: Dashboards
---
apiVersion: observability.openshift.io/v1alpha1
kind: UIPlugin
metadata:
  name: troubleshooting-panel
spec:
  type: TroubleshootingPanel
EOF
```

After a console refresh, new pages appear under **Observe**:
- **Observe → Logs** — LogQL queries against Loki
- **Observe → Traces** — Distributed trace viewer (requires TempoStack)

## 8. Verify

### Check all components

```bash
oc get uiplugin
oc get lokistack -n openshift-logging
oc get tempostack -n tracing-system
oc get opentelemetrycollector -n automotive-dev-operator-system
oc get ds collector -n openshift-logging
```

### Query logs via LogQL

Run a build, then query by the enriched pod labels:

```logql
# All logs for a specific build
{kubernetes_namespace_name="automotive-dev-operator-system"} |= "imagebuild-name"

# Controller logs (JSON)
{kubernetes_namespace_name="automotive-dev-operator-system",
 kubernetes_container_name="manager"} | json | msg != ""

# Filter by distro and architecture (requires label-enriched build pods)
{kubernetes_namespace_name="automotive-dev-operator-system"} | json |
  kubernetes_labels_automotive_sdv_cloud_redhat_com_distro="autosd"
```

### Operator pod labels

Build pods created by the operator carry these labels for Loki stream selection:

| Label | Value |
|-------|-------|
| `automotive.sdv.cloud.redhat.com/imagebuild-name` | ImageBuild CR name |
| `automotive.sdv.cloud.redhat.com/distro` | Target distro (e.g. `autosd`) |
| `automotive.sdv.cloud.redhat.com/architecture` | Build arch (e.g. `x86_64`) |
| `automotive.sdv.cloud.redhat.com/target` | Target platform |
| `automotive.sdv.cloud.redhat.com/build-mode` | AIB mode: `image`, `bootc`, or `package` |
| `automotive.sdv.cloud.redhat.com/trace-id` | OTel trace ID for cross-pod correlation |
| `automotive.sdv.cloud.redhat.com/task-type` | Pipeline task: `build`, `push`, or `flash` |

Workspace pods carry `workspace-name`, `owner`, and `architecture`.

### Trace ID correlation

Each ImageBuild gets a trace ID on first reconciliation, stored as an
annotation and propagated as a pod label and `ADO_TRACE_ID` env var.
The trace ID is a 32-hex-char string matching the W3C/OTel trace ID format.

To find all logs for a build using the indexed stream label (fast, covers Tekton task pods):

```logql
{kubernetes_labels_automotive_sdv_cloud_redhat_com_trace_id="<trace-id>"}
```

To include operator and build-api logs (trace ID in JSON body, not pod label):

```logql
{kubernetes_labels_automotive_sdv_cloud_redhat_com_trace_id="<trace-id>"}
  or
{kubernetes_namespace_name="automotive-dev-operator-system"} | json | traceID="<trace-id>"
```

For a quick broad search across all log formats:

```logql
{kubernetes_namespace_name="automotive-dev-operator-system"} |= "<trace-id>"
```

### CLF filtering

The CLF config controls which logs reach Loki and how they are indexed.

**Namespace scoping**: By default the CLF collects only from the operator namespace.
Build task pods, the operator, build-api, workspace pods, and the OTel collector
all run in this namespace, so a single namespace scope captures everything.

**Trace ID as stream label**: The `labelKeys` config promotes the pod label
`automotive.sdv.cloud.redhat.com/trace-id` to a Loki stream label. This enables
fast indexed queries (`{kubernetes_labels_automotive_sdv_cloud_redhat_com_trace_id="..."}`)
instead of full-text search. Only Tekton task pods carry this label; operator and
build-api pod logs require `| json | traceID="..."` filter expressions.

**Reducing log volume**: Build task pods (especially `build-image`) produce large
volumes of osbuild output. If storage is a concern, you can exclude specific
containers or filter by content using CLF pipeline filters:

```yaml
# Example: drop osbuild debug output (keeps structured lines and errors)
pipelines:
  - name: ado-logs
    inputRefs:
      - ado-app-logs
    outputRefs:
      - default-lokistack
    filterRefs:
      - drop-osbuild-debug
filters:
  - name: drop-osbuild-debug
    type: drop
    drop:
      - test:
          - field: .message
            matches: "^osbuild\\.stages"
```

**Tradeoff**: Dropping raw build output means you cannot debug build failures
from Loki alone — you would need `oc logs <pod>` while the pod still exists.
For the "one trace, full picture" experience, keep all logs and accept the
storage cost.

## Teardown

```bash
# Remove UIPlugins
oc delete uiplugin logging distributed-tracing dashboards troubleshooting-panel

# Remove OTel collector and mTLS resources
oc delete opentelemetrycollector otel -n automotive-dev-operator-system
oc delete sa otel-collector -n automotive-dev-operator-system
oc delete secret otel-tempo-client-tls -n automotive-dev-operator-system
oc delete configmap tempo-ca -n automotive-dev-operator-system
oc delete networkpolicy allow-otel-to-distributor -n tracing-system

# Remove TempoStack
oc delete tempostack tempo -n tracing-system
oc delete ns tracing-system

# Remove log collection
oc delete clusterlogforwarder collector -n openshift-logging
oc delete clusterrolebinding logging-collector-logs-writer
oc delete lokistack logging-loki -n openshift-logging

# Remove MinIO
oc delete deployment minio -n openshift-logging
oc delete svc minio -n openshift-logging
oc delete secret logging-loki-s3 -n openshift-logging

# Remove operators (via OLM subscriptions)
oc delete subscription loki-operator -n openshift-operators-redhat
oc delete subscription cluster-logging -n openshift-logging
oc delete subscription cluster-observability-operator -n openshift-operators
oc delete subscription tempo-product -n openshift-operators
oc delete subscription opentelemetry-product -n openshift-operators
```
