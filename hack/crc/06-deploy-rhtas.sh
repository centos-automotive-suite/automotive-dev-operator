#!/usr/bin/env bash
# Deploy RHTAS (Red Hat Trusted Artifact Signer) on CRC for keyless
# container signing via Tekton Chains.
#
# This is an alternative to 05-deploy-sigstore.sh that deploys the
# full RHTAS operator stack including TUF, which enables operator-side
# keyless signature verification (the Helm-based setup lacks TUF).
#
# Usage: ./hack/crc/06-deploy-rhtas.sh
# Prerequisites: oc, a running CRC cluster with redhat-operators catalog.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERT_DIR="$REPO_ROOT/.e2e/sigstore-certs"

OPERATOR_NS="openshift-rhtas-operator"
SECURESIGN_NS="trusted-artifact-signer"
SECURESIGN_NAME="securesign-sample"

log_info()  { printf '\033[0;36m>>> %s\033[0m\n' "$*"; }
log_ok()    { printf '\033[0;32m✅  %s\033[0m\n' "$*"; }
log_error() { printf '\033[0;31m❌  %s\033[0m\n' "$*" >&2; }

check_prerequisites() {
    local missing=()
    for cmd in oc kubectl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi

    if ! oc cluster-info &>/dev/null; then
        log_error "Not connected to an OpenShift cluster."
        exit 1
    fi

    if ! oc get catalogsource redhat-operators -n openshift-marketplace &>/dev/null; then
        log_error "redhat-operators CatalogSource not found."
        log_error "RHTAS requires a Red Hat subscription. Use 05-deploy-sigstore.sh for community Sigstore."
        exit 1
    fi
}

install_operator() {
    log_info "Creating RHTAS operator namespace..."
    oc create namespace "$OPERATOR_NS" 2>/dev/null || true

    log_info "Creating OperatorGroup..."
    oc apply -f - <<'EOF'
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: rhtas-operator-group
  namespace: openshift-rhtas-operator
spec:
  targetNamespaces: []
EOF

    log_info "Creating Subscription for RHTAS operator..."
    oc apply -f - <<'EOF'
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: rhtas-operator
  namespace: openshift-rhtas-operator
spec:
  channel: stable
  installPlanApproval: Automatic
  name: rhtas-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

    log_info "Waiting for RHTAS operator to install..."
    local retries=90
    while [ $retries -gt 0 ]; do
        local csv
        csv=$(oc get subscription.operators.coreos.com rhtas-operator -n "$OPERATOR_NS" \
            -o jsonpath='{.status.installedCSV}' 2>/dev/null || true)
        if [ -n "$csv" ]; then
            local phase
            phase=$(oc get csv "$csv" -n "$OPERATOR_NS" \
                -o jsonpath='{.status.phase}' 2>/dev/null || true)
            if [ "$phase" = "Succeeded" ]; then
                log_ok "RHTAS operator installed: $csv"
                return
            fi
            if [ -n "$phase" ]; then
                printf '\r\033[0;36m>>> Operator CSV %s: %s (%d attempts left)\033[0m    ' "$csv" "$phase" "$retries"
            fi
        fi
        retries=$((retries - 1))
        sleep 10
    done
    echo ""
    log_error "RHTAS operator did not reach Succeeded phase within 15 minutes."
    exit 1
}

create_securesign() {
    log_info "Creating namespace for Securesign instance..."
    oc create namespace "$SECURESIGN_NS" 2>/dev/null || true

    log_info "Deploying Securesign CR..."
    oc apply -f - <<EOF
apiVersion: rhtas.redhat.com/v1alpha1
kind: Securesign
metadata:
  name: $SECURESIGN_NAME
  namespace: $SECURESIGN_NS
  labels:
    app.kubernetes.io/part-of: trusted-artifact-signer
spec:
  rekor:
    externalAccess:
      enabled: true
    monitoring:
      enabled: false
  trillian:
    database:
      create: true
    monitoring:
      enabled: false
  fulcio:
    externalAccess:
      enabled: true
    config:
      OIDCIssuers:
        - ClientID: "sigstore"
          IssuerURL: "https://kubernetes.default.svc"
          Issuer: "https://kubernetes.default.svc"
          Type: "kubernetes"
    certificate:
      organizationName: CRC Dev
      organizationEmail: dev@crc.testing
      commonName: fulcio.crc.testing
    monitoring:
      enabled: false
  tuf:
    externalAccess:
      enabled: true
    keys:
      - name: rekor.pub
      - name: ctfe.pub
      - name: fulcio_v1.crt.pem
  ctlog:
    monitoring:
      enabled: false
  tsa:
    externalAccess:
      enabled: false
    monitoring:
      enabled: false
    ntpMonitoring:
      enabled: false
    signer:
      certificateChain:
        rootCA:
          organizationName: CRC Dev
          organizationEmail: dev@crc.testing
          commonName: tsa.crc.testing
        intermediateCA:
          - organizationName: CRC Dev
            organizationEmail: dev@crc.testing
            commonName: tsa-intermediate.crc.testing
        leafCA:
          organizationName: CRC Dev
          organizationEmail: dev@crc.testing
          commonName: tsa-leaf.crc.testing
EOF
}

wait_for_components() {
    log_info "Waiting for Securesign components to become ready..."
    log_info "(this may take several minutes on first install)"

    local required_conditions="FulcioAvailable RekorAvailable TrillianAvailable CTlogAvailable TufAvailable"
    local retries=90
    while [ $retries -gt 0 ]; do
        local all_ready=true
        local summary=""
        for cond in $required_conditions; do
            local status
            status=$(oc get securesign "$SECURESIGN_NAME" -n "$SECURESIGN_NS" \
                -o jsonpath="{.status.conditions[?(@.type==\"$cond\")].status}" 2>/dev/null || true)
            if [ "$status" = "True" ]; then
                summary="${summary}${cond}=ok "
            else
                summary="${summary}${cond}=pending "
                all_ready=false
            fi
        done
        if [ "$all_ready" = true ]; then
            echo ""
            log_ok "Securesign stack is ready."
            return
        fi
        printf '\r\033[0;36m>>> %s (%d attempts left)\033[0m    ' "$summary" "$retries"
        retries=$((retries - 1))
        sleep 10
    done
    echo ""
    log_error "Securesign did not reach Ready within 15 minutes."
    log_error "Check: oc get securesign $SECURESIGN_NAME -n $SECURESIGN_NS -o yaml"
    exit 1
}

discover_endpoints() {
    log_info "Discovering service endpoints..."

    FULCIO_URL=$(oc get securesign "$SECURESIGN_NAME" -n "$SECURESIGN_NS" \
        -o jsonpath='{.status.fulcio.url}' 2>/dev/null || true)
    REKOR_URL=$(oc get securesign "$SECURESIGN_NAME" -n "$SECURESIGN_NS" \
        -o jsonpath='{.status.rekor.url}' 2>/dev/null || true)
    TUF_URL=$(oc get securesign "$SECURESIGN_NAME" -n "$SECURESIGN_NS" \
        -o jsonpath='{.status.tuf.url}' 2>/dev/null || true)

    if [ -z "$FULCIO_URL" ] || [ "$FULCIO_URL" = "https://" ]; then
        FULCIO_URL="https://$(oc get route fulcio-server -n "$SECURESIGN_NS" \
            -o jsonpath='{.spec.host}' 2>/dev/null || true)"
    fi
    if [ -z "$REKOR_URL" ] || [ "$REKOR_URL" = "https://" ]; then
        REKOR_URL="https://$(oc get route rekor-server -n "$SECURESIGN_NS" \
            -o jsonpath='{.spec.host}' 2>/dev/null || true)"
    fi
    if [ -z "$TUF_URL" ] || [ "$TUF_URL" = "https://" ]; then
        TUF_URL="https://$(oc get route tuf -n "$SECURESIGN_NS" \
            -o jsonpath='{.spec.host}' 2>/dev/null || true)"
    fi

    log_ok "Fulcio: $FULCIO_URL"
    log_ok "Rekor:  $REKOR_URL"
    log_ok "TUF:    $TUF_URL"
}

extract_fulcio_root() {
    log_info "Extracting Fulcio root CA certificate..."
    mkdir -p "$CERT_DIR"

    local secret_name
    secret_name=$(oc get secrets -n "$SECURESIGN_NS" --no-headers 2>/dev/null \
        | grep "^fulcio-cert-" | awk '{print $1}' | head -1)

    if [ -n "$secret_name" ]; then
        local data
        data=$(oc get secret "$secret_name" -n "$SECURESIGN_NS" \
            -o jsonpath='{.data.cert}' 2>/dev/null || true)
        if [ -n "$data" ]; then
            echo "$data" | base64 -d > "$CERT_DIR/fulcio-root.pem"
            log_ok "Fulcio root CA: $CERT_DIR/fulcio-root.pem"
            return
        fi
    fi

    log_info "Could not extract Fulcio root from secret, trying TUF..."
    if [ -n "$TUF_URL" ] && [ "$TUF_URL" != "https://" ]; then
        curl -sSk "$TUF_URL/targets/fulcio_v1.crt.pem" -o "$CERT_DIR/fulcio-root.pem" 2>/dev/null || true
        if [ -s "$CERT_DIR/fulcio-root.pem" ]; then
            log_ok "Fulcio root CA (from TUF): $CERT_DIR/fulcio-root.pem"
            return
        fi
    fi

    log_error "Could not extract Fulcio root CA."
    log_error "Check: oc get secrets -n $SECURESIGN_NS | grep fulcio-cert"
}

configure_chains() {
    log_info "Configuring Tekton Chains for RHTAS keyless signing..."

    local fulcio_svc="http://fulcio-server.${SECURESIGN_NS}.svc"
    local rekor_svc="http://rekor-server.${SECURESIGN_NS}.svc:80"

    if oc get tektonconfig config &>/dev/null; then
        oc patch tektonconfig config --type=merge -p "{
            \"spec\": {
                \"chain\": {
                    \"signers.x509.fulcio.enabled\": true,
                    \"signers.x509.fulcio.address\": \"${fulcio_svc}\",
                    \"transparency.enabled\": true,
                    \"transparency.url\": \"${rekor_svc}\",
                    \"artifacts.taskrun.format\": \"slsa/v1\",
                    \"artifacts.taskrun.storage\": \"oci\",
                    \"artifacts.pipelinerun.format\": \"slsa/v1\",
                    \"artifacts.pipelinerun.storage\": \"oci\"
                }
            }
        }"
        log_ok "TektonConfig patched for RHTAS keyless signing."

        log_info "Waiting for Chains controller to pick up configuration..."
        sleep 10
        oc rollout status deployment/tekton-chains-controller \
            -n openshift-pipelines --timeout=3m 2>/dev/null || true
        log_ok "Chains controller ready."
    else
        log_error "TektonConfig CR not found. Install OpenShift Pipelines first."
        exit 1
    fi
}

print_summary() {
    echo ""
    echo "========================================="
    echo "   RHTAS Stack Deployed"
    echo "========================================="
    echo ""
    echo "  Fulcio:  ${FULCIO_URL:-unknown}"
    echo "  Rekor:   ${REKOR_URL:-unknown}"
    echo "  TUF:     ${TUF_URL:-unknown}"
    echo ""
    echo "  Fulcio root CA: $CERT_DIR/fulcio-root.pem"
    echo ""
    echo "  Tekton Chains: configured for RHTAS keyless signing"
    echo ""
    echo "  Environment for e2e tests:"
    echo "    export SIGSTORE_FULCIO_ROOT=$CERT_DIR/fulcio-root.pem"
    echo "    export SIGSTORE_REKOR_URL=${REKOR_URL:-}"
    echo "    export SIGSTORE_TUF_URL=${TUF_URL:-}"
    echo ""
    echo "  Initialize cosign with RHTAS TUF root:"
    echo "    cosign initialize --mirror ${TUF_URL:-} --root ${TUF_URL:-}/root.json"
    echo ""
    echo "  Verify manually:"
    echo "    cosign verify \\"
    echo "      --rekor-url ${REKOR_URL:-} \\"
    echo "      --certificate-identity <identity> \\"
    echo "      --certificate-oidc-issuer https://kubernetes.default.svc \\"
    echo "      <image-ref>"
    echo ""
    echo "  Advantage over Helm Sigstore:"
    echo "    TUF server distributes local trust root, enabling"
    echo "    operator-side keyless verification (not just CLI)."
    echo ""
    echo "========================================="
}

main() {
    FULCIO_URL=""
    REKOR_URL=""
    TUF_URL=""

    check_prerequisites
    install_operator
    create_securesign
    wait_for_components
    discover_endpoints
    extract_fulcio_root
    configure_chains
    print_summary
}

main "$@"
