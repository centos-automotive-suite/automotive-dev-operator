#!/bin/bash
set -euo pipefail

echo "=== Jumpstarter Flash Operation ==="
echo "Image: ${IMAGE_REF}"
echo "Exporter Selector: ${EXPORTER_SELECTOR}"

export JMP_CLIENT_CONFIG="${JMP_CLIENT_CONFIG:-/workspace/jumpstarter-client/client.yaml}"

if [[ ! -f "${JMP_CLIENT_CONFIG}" ]]; then
    echo "ERROR: Jumpstarter client config not found at ${JMP_CLIENT_CONFIG}"
    exit 1
fi

echo "Using client config: ${JMP_CLIENT_CONFIG}"

echo "refreshing jumpstarter token"
jmp login --client-config "${JMP_CLIENT_CONFIG}"

FLASH_CMD="${FLASH_CMD:-j storage flash \{image_uri\}}"
FLASH_CMD=$(echo "${FLASH_CMD}" | sed "s|{image_uri}|${IMAGE_REF}|g")


LEASE_DURATION="${LEASE_DURATION:-03:00:00}"

echo "Flash command: ${FLASH_CMD}"
echo "Lease duration: ${LEASE_DURATION}"
echo ""

echo "Creating lease on exporter matching: ${EXPORTER_SELECTOR}"

LEASE_NAME=$(jmp create lease --client-config "${JMP_CLIENT_CONFIG}" -l "${EXPORTER_SELECTOR}" --duration "${LEASE_DURATION}" -o name)

if [[ -z "${LEASE_NAME}" ]]; then
    echo "ERROR: Failed to create lease"
    exit 1
fi

echo ""
echo "Lease acquired: ${LEASE_NAME}"
echo "Duration: ${LEASE_DURATION}"
echo ""

# Write lease ID to Tekton result
if [[ -n "${RESULTS_LEASE_ID_PATH:-}" ]]; then
    echo -n "${LEASE_NAME}" > "${RESULTS_LEASE_ID_PATH}"
fi

FLASH_SUCCESS=false

cleanup() {
    if [[ "${FLASH_SUCCESS}" != "true" ]]; then
        echo ""
        echo "Releasing lease ${LEASE_NAME} due to failure..."
        jmp delete leases --client-config "${JMP_CLIENT_CONFIG}" "${LEASE_NAME}" || true
    fi
}
trap cleanup EXIT

echo "Starting flash operation..."
echo "Executing: ${FLASH_CMD}"

# Read OCI credentials from mounted secret workspace if available
OCI_USERNAME=""
OCI_PASSWORD=""
FLASH_OCI_AUTH_PATH="${FLASH_OCI_AUTH_PATH:-/workspace/flash-oci-auth}"
if [ -f "${FLASH_OCI_AUTH_PATH}/username" ] && [ -f "${FLASH_OCI_AUTH_PATH}/password" ]; then
    OCI_USERNAME=$(cat "${FLASH_OCI_AUTH_PATH}/username")
    OCI_PASSWORD=$(cat "${FLASH_OCI_AUTH_PATH}/password")
fi

# Build jmp shell command with optional OCI credentials written to file on exporter
JMP_SHELL_ARGS="--client-config ${JMP_CLIENT_CONFIG} --lease ${LEASE_NAME}"

if [ -n "${OCI_USERNAME}" ] && [ -n "${OCI_PASSWORD}" ]; then
    echo "OCI credentials provided, forwarding to exporter via environment variables"
    # Pass OCI credentials via environment variables that j storage expects
    # shellcheck disable=SC2086
    set +e  # Temporarily disable errexit to capture exit code
    jmp shell ${JMP_SHELL_ARGS} -- env \
        OCI_USERNAME="${OCI_USERNAME}" \
        OCI_PASSWORD="${OCI_PASSWORD}" \
        ${FLASH_CMD}
    FLASH_EXIT=$?
    set -e  # Restore errexit
else
    # No credentials, run flash command directly
    # shellcheck disable=SC2086
    set +e  # Temporarily disable errexit to capture exit code
    jmp shell ${JMP_SHELL_ARGS} -- ${FLASH_CMD}
    FLASH_EXIT=$?
    set -e  # Restore errexit
fi

if [ ${FLASH_EXIT} -ne 0 ]; then
    echo ""
    echo "ERROR: Flash command failed"
    exit 1
fi

FLASH_SUCCESS=true
