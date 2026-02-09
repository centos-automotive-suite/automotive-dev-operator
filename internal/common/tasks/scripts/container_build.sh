#!/usr/bin/env bash
set -euo pipefail

CONTEXT_DIR="${CONTEXT_DIR:-/workspace/source}"
DOCKERFILE="${DOCKERFILE:-Containerfile}"
OUTPUT_IMAGE="${OUTPUT_IMAGE:-}"
BUILD_ARGS="${BUILD_ARGS:-}"

if [ -z "${OUTPUT_IMAGE}" ]; then
  echo "ERROR: OUTPUT_IMAGE is required"
  exit 1
fi

echo "=== Container Build ==="
echo "Context:    ${CONTEXT_DIR}"
echo "Dockerfile: ${DOCKERFILE}"
echo "Output:     ${OUTPUT_IMAGE}"

# Build additional --build-arg flags
BUILD_ARG_FLAGS=""
if [ -n "${BUILD_ARGS}" ]; then
  IFS=',' read -ra ARGS <<< "${BUILD_ARGS}"
  for arg in "${ARGS[@]}"; do
    BUILD_ARG_FLAGS="${BUILD_ARG_FLAGS} --build-arg ${arg}"
  done
fi

echo "Building container image..."
# shellcheck disable=SC2086
buildah bud \
  --storage-driver=vfs \
  -f "${DOCKERFILE}" \
  -t "${OUTPUT_IMAGE}" \
  ${BUILD_ARG_FLAGS} \
  "${CONTEXT_DIR}"

echo "Pushing container image to ${OUTPUT_IMAGE}..."
buildah push \
  --storage-driver=vfs \
  "${OUTPUT_IMAGE}"

echo "=== Build complete ==="
