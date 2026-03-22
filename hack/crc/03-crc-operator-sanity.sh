#!/usr/bin/env bash

# 03-crc-operator-sanity.sh
# Validates that the CRC cluster and operator deployment are healthy.
# Run after 02-deploy-operator.sh to confirm everything is working.

NAMESPACE="automotive-dev-operator-system"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if "$@" &>/dev/null; then
        echo -e "  ${GREEN}PASS${NC}  $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}  $desc"
        FAIL=$((FAIL + 1))
    fi
}

check_output() {
    local desc="$1"
    local expected="$2"
    shift 2
    local output
    output=$("$@" 2>/dev/null)
    if echo "$output" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC}  $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}  $desc (expected: $expected, got: $output)"
        FAIL=$((FAIL + 1))
    fi
}

check_non_empty() {
    local desc="$1"
    shift
    local output rc=0
    output=$("$@" 2>/dev/null) || rc=$?
    if [[ $rc -eq 0 ]] && [[ -n "${output//[[:space:]]/}" ]] && [[ "$output" != "No resources found"* ]]; then
        echo -e "  ${GREEN}PASS${NC}  $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}  $desc (no matching resources)"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo -e "${CYAN}=== CRC Cluster ===${NC}"
check "Cluster reachable" oc cluster-info
check "Logged in as kubeadmin" test "$(oc whoami 2>/dev/null)" = "kubeadmin"
check "Node ready" oc wait --for=condition=Ready nodes --all --timeout=5s
check_non_empty "Node labeled aib=true" oc get nodes -l aib=true --no-headers

echo ""
echo -e "${CYAN}=== Operator ===${NC}"
check "Namespace exists" oc get namespace "$NAMESPACE"
check_non_empty "Operator pod running" oc get pods -n "$NAMESPACE" -l control-plane=operator --field-selector=status.phase=Running --no-headers
check_output "Operator pod ready" "1/1" oc get pods -n "$NAMESPACE" -l control-plane=operator --no-headers
check "OperatorConfig exists" oc get operatorconfig config -n "$NAMESPACE"
check_output "OperatorConfig phase Ready" "Ready" oc get operatorconfig config -n "$NAMESPACE" -o jsonpath='{.status.phase}'

echo ""
echo -e "${CYAN}=== Build API ===${NC}"
check_non_empty "Build API pod running" oc get pods -n "$NAMESPACE" -l app.kubernetes.io/component=build-api --field-selector=status.phase=Running --no-headers
check_output "Build API pod ready" "2/2" oc get pods -n "$NAMESPACE" -l app.kubernetes.io/component=build-api --no-headers
check "Build API service exists" oc get service ado-build-api -n "$NAMESPACE"
check "Build API route exists" oc get route ado-build-api -n "$NAMESPACE"

BUILD_API_URL=$(oc get route ado-build-api -n "$NAMESPACE" -o jsonpath='{.spec.host}' 2>/dev/null)
if [ -n "$BUILD_API_URL" ]; then
    check "Build API endpoint responds" curl -fsSk --max-time 10 "https://${BUILD_API_URL}/healthz"
fi

echo ""
echo -e "${CYAN}=== Tekton Tasks ===${NC}"
EXPECTED_TASKS="build-automotive-image push-artifact-registry flash-image prepare-reseal reseal extract-for-signing inject-signed"
for task in $EXPECTED_TASKS; do
    check "Task: $task" oc get task "$task" -n "$NAMESPACE"
done

echo ""
echo -e "${CYAN}=== Tekton Pipelines ===${NC}"
check "Pipeline: automotive-build-pipeline" oc get pipeline automotive-build-pipeline -n "$NAMESPACE"

echo ""
echo -e "${CYAN}=== OpenShift Pipelines Operator ===${NC}"
check_non_empty "Pipelines operator pod running" oc get pods -n openshift-operators -l name=openshift-pipelines-operator --field-selector=status.phase=Running --no-headers

###############################################################################
# End-to-end build test (optional, pass --sanity to enable)
###############################################################################
if [[ "${1:-}" == "--sanity" ]]; then
    echo ""
    echo -e "${CYAN}=== End-to-End Build Test ===${NC}"

    if [[ -z "${BUILD_API_URL:-}" ]]; then
        echo -e "  ${RED}FAIL${NC}  Build API route host is empty; cannot run --sanity build test"
        FAIL=$((FAIL + 1))
    else

    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
    CAIB_BIN="$REPO_DIR/bin/caib"
    TEST_MANIFEST="$REPO_DIR/test/config/test-manifest.aib.yml"
    INTERNAL_REGISTRY="image-registry.openshift-image-registry.svc:5000"
    TEST_IMAGE="${INTERNAL_REGISTRY}/${NAMESPACE}/automotive:validation-test"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  BUILD_ARCH="amd64" ;;
        aarch64|arm64) BUILD_ARCH="arm64" ;;
        *)       BUILD_ARCH="amd64" ;;
    esac

    if [[ ! -f "$CAIB_BIN" ]]; then
        echo -e "  ${CYAN}INFO${NC}  Building caib CLI..."
        make -C "$REPO_DIR" build-caib &>/dev/null || true
    fi

    if [[ ! -f "$CAIB_BIN" ]]; then
        echo -e "  ${RED}FAIL${NC}  caib binary not found at $CAIB_BIN"
        FAIL=$((FAIL + 1))
    elif [[ ! -f "$TEST_MANIFEST" ]]; then
        echo -e "  ${RED}FAIL${NC}  Test manifest not found at $TEST_MANIFEST"
        FAIL=$((FAIL + 1))
    else
        export CAIB_SERVER="https://${BUILD_API_URL}"

        echo -e "  ${CYAN}INFO${NC}  Submitting build: arch=${BUILD_ARCH}, push=${TEST_IMAGE}"
        BUILD_OUTPUT=$("$CAIB_BIN" image build "$TEST_MANIFEST" \
            --arch "$BUILD_ARCH" \
            --push "$TEST_IMAGE" \
            --insecure 2>&1)
        BUILD_EXIT=$?

        BUILD_NAME=$(echo "$BUILD_OUTPUT" | sed -n 's/.*Build \([^ ]*\) accepted.*/\1/p' | head -1)

        if [[ $BUILD_EXIT -eq 0 ]] && echo "$BUILD_OUTPUT" | grep -q "Build completed successfully"; then
            echo -e "  ${GREEN}PASS${NC}  Build completed successfully ($BUILD_NAME)"
            PASS=$((PASS + 1))
        else
            echo -e "  ${RED}FAIL${NC}  Build failed (exit=$BUILD_EXIT)"
            echo "$BUILD_OUTPUT" | tail -5
            FAIL=$((FAIL + 1))
        fi

        if [[ -n "$BUILD_NAME" ]]; then
            check_output "Build visible in caib image list" "$BUILD_NAME" \
                "$CAIB_BIN" image list --insecure
        else
            check_output "Build visible in caib image list" "Completed" \
                "$CAIB_BIN" image list --insecure
        fi

        check "ImageStream created" \
            oc get imagestream automotive -n "$NAMESPACE"
    fi

    fi
fi

echo ""
echo "========================================="
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "========================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
