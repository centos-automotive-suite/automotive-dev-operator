#!/usr/bin/env bash
# Deploy Dex as an OIDC provider on a Kind cluster for auth e2e tests.
# Generates TLS certificates, installs Dex via Helm, and stores the CA cert
# in a ConfigMap for test consumption.
#
# Usage: ./hack/e2e/setup-dex.sh
# Prerequisites: kubectl, helm, openssl, and a running Kind cluster.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERT_DIR="$REPO_ROOT/.e2e/dex-certs"

log_info()  { echo "[INFO]  $*"; }
log_error() { echo "[ERROR] $*" >&2; }

check_prerequisites() {
    local missing=()
    for cmd in kubectl helm openssl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

generate_certs() {
    if [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/server.pem" ] && [ -f "$CERT_DIR/server-key.pem" ]; then
        log_info "Certificates already exist in $CERT_DIR, reusing"
        return
    fi

    log_info "Generating TLS certificates..."
    mkdir -p "$CERT_DIR"

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca.pem" \
        -days 365 -nodes -subj "/CN=e2e-dex-ca" 2>/dev/null

    cat > "$CERT_DIR/san.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
CN = dex.dex.svc.cluster.local

[v3_req]
subjectAltName = DNS:dex.dex.svc.cluster.local

[v3_ext]
subjectAltName = DNS:dex.dex.svc.cluster.local
EOF

    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
        -nodes -config "$CERT_DIR/san.cnf" 2>/dev/null

    openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$CERT_DIR/server.pem" -days 365 \
        -extensions v3_ext -extfile "$CERT_DIR/san.cnf" 2>/dev/null

    log_info "Certificates generated in $CERT_DIR"
}

deploy_dex() {
    log_info "Deploying Dex..."

    kubectl create namespace dex --dry-run=client -o yaml | kubectl apply -f -

    kubectl -n dex create secret tls dex-tls \
        --cert="$CERT_DIR/server.pem" \
        --key="$CERT_DIR/server-key.pem" \
        --dry-run=client -o yaml | kubectl apply -f -

    kubectl create configmap dex-ca -n dex \
        --from-file=ca.crt="$CERT_DIR/ca.pem" \
        --dry-run=client -o yaml | kubectl apply -f -

    helm repo add dex https://charts.dexidp.io 2>/dev/null || true
    helm repo update dex
    helm upgrade --install --namespace dex --wait --timeout 5m0s --version 0.21.0 \
        -f "$SCRIPT_DIR/dex.values.yaml" dex dex/dex

    log_info "Waiting for Dex to be ready..."
    kubectl wait --namespace dex --for=condition=available \
        deployment/dex --timeout=5m

    log_info "Dex deployed successfully"
}

main() {
    log_info "=== Dex OIDC Setup for E2E Tests ==="

    check_prerequisites
    generate_certs
    deploy_dex

    log_info ""
    log_info "Dex is ready."
    log_info "  Issuer:  https://dex.dex.svc.cluster.local:5556"
    log_info "  CA cert: $CERT_DIR/ca.pem"
    log_info ""
    log_info "Run auth e2e tests:"
    log_info "  go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter=auth"
}

main "$@"
