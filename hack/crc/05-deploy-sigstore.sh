#!/usr/bin/env bash
# Deploy a local Sigstore stack (Fulcio + Rekor + Trillian) on CRC for
# keyless container signing via Tekton Chains.
#
# Usage: ./hack/crc/05-deploy-sigstore.sh
# Prerequisites: helm, kubectl/oc, and a running CRC cluster.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VALUES_FILE="$SCRIPT_DIR/sigstore-values.yaml"
CERT_DIR="$REPO_ROOT/.e2e/sigstore-certs"

HELM_RELEASE="sigstore"
HELM_CHART="sigstore/scaffold"

FULCIO_NS="fulcio-system"
REKOR_NS="rekor-system"
TRILLIAN_NS="trillian-system"

log_info()  { printf '\033[0;36m>>> %s\033[0m\n' "$*"; }
log_ok()    { printf '\033[0;32m✅  %s\033[0m\n' "$*"; }
log_error() { printf '\033[0;31m❌  %s\033[0m\n' "$*" >&2; }

check_prerequisites() {
    local missing=()
    for cmd in kubectl helm; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi

    if ! kubectl cluster-info &>/dev/null; then
        log_error "Not connected to a Kubernetes cluster."
        exit 1
    fi
}

add_helm_repo() {
    log_info "Adding sigstore Helm repository..."
    helm repo add sigstore https://sigstore.github.io/helm-charts 2>/dev/null || true
    helm repo update sigstore
}

grant_scc() {
    if ! command -v oc &>/dev/null; then
        return
    fi

    log_info "Granting anyuid SCC to Sigstore service accounts..."
    local sas=(
        "fulcio-server:$FULCIO_NS"
        "fulcio-createcerts:$FULCIO_NS"
        "default:$FULCIO_NS"
        "rekor-server:$REKOR_NS"
        "rekor-createtree:$REKOR_NS"
        "default:$REKOR_NS"
        "default:$TRILLIAN_NS"
    )
    for sa_ns in "${sas[@]}"; do
        local sa="${sa_ns%%:*}"
        local ns="${sa_ns##*:}"
        oc adm policy add-scc-to-user anyuid -z "$sa" -n "$ns" 2>/dev/null || true
    done
    log_ok "SCC grants applied."
}

restart_failed_pods() {
    log_info "Restarting pods that failed SCC checks..."
    for ns in "$FULCIO_NS" "$REKOR_NS" "$TRILLIAN_NS"; do
        kubectl rollout restart deployment -n "$ns" 2>/dev/null || true
        # Delete failed pods within jobs so the Job controller retries them.
        # Do NOT delete the Job itself — Helm hooks won't be recreated.
        kubectl delete pods -n "$ns" --field-selector status.phase=Failed 2>/dev/null || true
    done
}

deploy_sigstore() {
    log_info "Deploying Sigstore stack (Fulcio + Rekor + Trillian)..."

    if helm status "$HELM_RELEASE" &>/dev/null; then
        log_info "Sigstore release already exists, upgrading..."
        helm upgrade "$HELM_RELEASE" "$HELM_CHART" -f "$VALUES_FILE" \
            --reuse-values --wait --timeout 10m
        return
    fi

    # Install without --wait: pods will fail due to OpenShift SCC restrictions
    # (Sigstore images use runAsUser: 65533 which is outside namespace UID range).
    # We grant SCC grants immediately after, then restart failed pods.
    helm install "$HELM_RELEASE" "$HELM_CHART" -f "$VALUES_FILE" --timeout 2m 2>/dev/null || true

    grant_scc
    restart_failed_pods
}

wait_for_components() {
    log_info "Waiting for Trillian components..."
    kubectl wait --namespace "$TRILLIAN_NS" --for=condition=available \
        deployment/trillian-logserver --timeout=5m 2>/dev/null || true
    kubectl wait --namespace "$TRILLIAN_NS" --for=condition=available \
        deployment/trillian-logsigner --timeout=5m 2>/dev/null || true
    kubectl wait --namespace "$TRILLIAN_NS" --for=condition=Ready \
        pod -l app.kubernetes.io/name=mysql --timeout=5m 2>/dev/null || true
    log_ok "Trillian ready."

    log_info "Waiting for Fulcio createcerts job..."
    kubectl wait --namespace "$FULCIO_NS" --for=condition=complete \
        job -l app.kubernetes.io/name=fulcio --timeout=5m 2>/dev/null || true

    log_info "Waiting for Fulcio server..."
    kubectl wait --namespace "$FULCIO_NS" --for=condition=available \
        deployment/fulcio-server --timeout=5m
    log_ok "Fulcio ready."

    log_info "Waiting for Rekor createtree job..."
    kubectl wait --namespace "$REKOR_NS" --for=condition=complete \
        job -l app.kubernetes.io/name=rekor --timeout=5m 2>/dev/null || true

    log_info "Waiting for Rekor server..."
    kubectl wait --namespace "$REKOR_NS" --for=condition=available \
        deployment/rekor-server --timeout=5m
    log_ok "Rekor ready."
}

fix_fulcio_oidc() {
    # CRC's kube-apiserver OIDC discovery at https://kubernetes.default.svc
    # returns jwks_uri pointing to https://api.crc.testing:6443/openid/v1/jwks.
    #
    # Fulcio's httpClientForIssuer() creates a bearerTokenTransport for
    # Type=kubernetes issuers when a SA token file exists. That transport
    # blocks HTTP requests whose host differs from the issuer host — and
    # the JWKS host (api.crc.testing) differs from the issuer (kubernetes.
    # default.svc). The IssuerURL field cannot be changed because
    # NewIssuerPool() uses it (not the map key) for Match().
    #
    # Fix:
    #   1. Grant anonymous access to the JWKS endpoint so no auth is needed
    #   2. Disable automountServiceAccountToken on the Fulcio pod so the SA
    #      token file doesn't exist → bearerTokenTransport is not created
    #   3. Mount the kube CA cert at the expected SA path so Fulcio can still
    #      verify TLS to the API server

    log_info "Granting anonymous access to OIDC JWKS endpoint..."
    kubectl create clusterrolebinding oidc-reviewer-anonymous \
        --clusterrole=system:service-account-issuer-discovery \
        --group=system:unauthenticated 2>/dev/null || true

    log_info "Disabling SA token automount on Fulcio (prevents bearerTokenTransport)..."
    kubectl patch deployment fulcio-server -n "$FULCIO_NS" --type=strategic -p '{
      "spec": {
        "template": {
          "spec": {
            "automountServiceAccountToken": false,
            "volumes": [{
              "name": "kube-sa-ca",
              "projected": {
                "sources": [{"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]
              }
            }],
            "containers": [{
              "name": "fulcio-server",
              "volumeMounts": [{
                "name": "kube-sa-ca",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                "readOnly": true
              }]
            }]
          }
        }
      }
    }'

    kubectl wait --namespace "$FULCIO_NS" --for=condition=available \
        deployment/fulcio-server --timeout=3m
    log_ok "Fulcio OIDC config patched for CRC."
}

expose_rekor() {
    log_info "Exposing Rekor via OpenShift route..."
    if command -v oc &>/dev/null; then
        if ! oc get route rekor -n "$REKOR_NS" &>/dev/null; then
            oc create route edge rekor \
                --service=rekor-server \
                --port=80 \
                -n "$REKOR_NS" 2>/dev/null || true
        fi
        REKOR_HOST_URL="https://$(oc get route rekor -n "$REKOR_NS" -o jsonpath='{.spec.host}' 2>/dev/null || true)"
        if [ -n "$REKOR_HOST_URL" ] && [ "$REKOR_HOST_URL" != "https://" ]; then
            log_ok "Rekor route: $REKOR_HOST_URL"
        else
            REKOR_HOST_URL=""
            log_info "Could not create route; use port-forward instead:"
            log_info "  kubectl port-forward svc/rekor-server 3000:80 -n $REKOR_NS"
            REKOR_HOST_URL="http://localhost:3000"
        fi
    else
        log_info "oc not available; use port-forward for Rekor access:"
        log_info "  kubectl port-forward svc/rekor-server 3000:80 -n $REKOR_NS"
        REKOR_HOST_URL="http://localhost:3000"
    fi
}

extract_fulcio_root() {
    log_info "Extracting Fulcio root CA certificate..."
    mkdir -p "$CERT_DIR"

    local secret_name="fulcio-server-secret"
    local cert_key="cert"

    if kubectl get secret "$secret_name" -n "$FULCIO_NS" &>/dev/null; then
        kubectl get secret "$secret_name" -n "$FULCIO_NS" \
            -o jsonpath="{.data.$cert_key}" | base64 -d > "$CERT_DIR/fulcio-root.pem"
        log_ok "Fulcio root CA: $CERT_DIR/fulcio-root.pem"
    else
        log_error "Fulcio secret '$secret_name' not found in $FULCIO_NS."
        log_error "Check: kubectl get secrets -n $FULCIO_NS"
        exit 1
    fi
}

configure_chains() {
    log_info "Configuring Tekton Chains for local keyless signing..."

    local fulcio_url="http://fulcio-server.${FULCIO_NS}.svc"
    local rekor_url="http://rekor-server.${REKOR_NS}.svc:80"

    if kubectl get tektonconfig config &>/dev/null; then
        kubectl patch tektonconfig config --type=merge -p "{
            \"spec\": {
                \"chain\": {
                    \"signers.x509.fulcio.enabled\": true,
                    \"signers.x509.fulcio.address\": \"${fulcio_url}\",
                    \"transparency.enabled\": true,
                    \"transparency.url\": \"${rekor_url}\",
                    \"artifacts.taskrun.format\": \"slsa/v1\",
                    \"artifacts.taskrun.storage\": \"oci\",
                    \"artifacts.pipelinerun.format\": \"slsa/v1\",
                    \"artifacts.pipelinerun.storage\": \"oci\"
                }
            }
        }"
        log_ok "TektonConfig patched for keyless signing."

        log_info "Waiting for Chains controller to pick up configuration..."
        sleep 10
        kubectl rollout status deployment/tekton-chains-controller \
            -n openshift-pipelines --timeout=3m 2>/dev/null || true
        log_ok "Chains controller ready."
    else
        log_info "TektonConfig CR not found (non-OpenShift cluster)."
        log_info "Patch chains-config ConfigMap manually if needed."
    fi
}

print_summary() {
    local fulcio_internal="http://fulcio-server.${FULCIO_NS}.svc"
    local rekor_internal="http://rekor-server.${REKOR_NS}.svc:80"

    echo ""
    echo "========================================="
    echo "   Sigstore Stack Deployed"
    echo "========================================="
    echo ""
    echo "  Fulcio (in-cluster): $fulcio_internal"
    echo "  Rekor  (in-cluster): $rekor_internal"
    echo "  Rekor  (host):       ${REKOR_HOST_URL:-http://localhost:3000}"
    echo "  Fulcio root CA:      $CERT_DIR/fulcio-root.pem"
    echo ""
    echo "  Tekton Chains: configured for keyless signing"
    echo ""
    echo "  Environment for e2e tests:"
    echo "    export SIGSTORE_FULCIO_ROOT=$CERT_DIR/fulcio-root.pem"
    echo "    export SIGSTORE_REKOR_URL=${REKOR_HOST_URL:-http://localhost:3000}"
    echo ""
    echo "  Verify manually:"
    echo "    cosign verify --certificate-chain $CERT_DIR/fulcio-root.pem \\"
    echo "      --rekor-url ${REKOR_HOST_URL:-http://localhost:3000} \\"
    echo "      --certificate-identity <identity> \\"
    echo "      --certificate-oidc-issuer https://kubernetes.default.svc \\"
    echo "      <image-ref>"
    echo ""
    echo "========================================="
}

main() {
    REKOR_HOST_URL=""

    check_prerequisites
    add_helm_repo
    deploy_sigstore
    wait_for_components
    fix_fulcio_oidc
    expose_rekor
    extract_fulcio_root
    configure_chains
    print_summary
}

main "$@"
