#!/bin/bash
set -euo pipefail

echo "=== Sealed operation: ${OPERATION} ==="
echo "Input ref: ${INPUT_REF}"

WORKSPACE="${WORKSPACE:-/workspace/shared}"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# Registry auth
if [[ -n "${REGISTRY_AUTH_PATH:-}" ]] && [[ -d "${REGISTRY_AUTH_PATH}" ]]; then
  if [[ -f "${REGISTRY_AUTH_PATH}/REGISTRY_URL" ]]; then
    REGISTRY_URL=$(cat "${REGISTRY_AUTH_PATH}/REGISTRY_URL")
    REGISTRY_USERNAME=$(cat "${REGISTRY_AUTH_PATH}/REGISTRY_USERNAME" 2>/dev/null || true)
    REGISTRY_PASSWORD=$(cat "${REGISTRY_AUTH_PATH}/REGISTRY_PASSWORD" 2>/dev/null || true)
    if [[ -n "$REGISTRY_USERNAME" ]] && [[ -n "$REGISTRY_PASSWORD" ]]; then
      export REGISTRY_AUTH_FILE="$HOME/.authjson"
      mkdir -p "$HOME/.config"
      AUTH=$(echo -n "${REGISTRY_USERNAME}:${REGISTRY_PASSWORD}" | base64 -w0)
      echo "{\"auths\":{\"${REGISTRY_URL}\":{\"auth\":\"${AUTH}\"}}}" > "$REGISTRY_AUTH_FILE"
    fi
  fi
fi

# Install oras if not present
if ! command -v oras >/dev/null 2>&1; then
  ORAS_VERSION="1.2.0"
  case "$(uname -m)" in
    x86_64) ORAS_ARCH="amd64" ;;
    aarch64|arm64) ORAS_ARCH="arm64" ;;
    *) echo "ERROR: Unsupported architecture $(uname -m)" >&2; exit 1 ;;
  esac
  ORAS_TARBALL="oras_${ORAS_VERSION}_linux_${ORAS_ARCH}.tar.gz"
  ORAS_BASE_URL="https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}"
  echo "Installing oras ${ORAS_VERSION}..."
  curl -sSLf "${ORAS_BASE_URL}/${ORAS_TARBALL}" | tar -xz -C /tmp oras
  mv /tmp/oras /usr/local/bin/oras
  chmod +x /usr/local/bin/oras
fi

# Pull input artifact
echo "Pulling input from ${INPUT_REF}..."
mkdir -p input_extract
oras pull "${INPUT_REF}" --output input_extract
INPUT_FILE=$(find input_extract -type f 2>/dev/null | head -1)
if [[ -z "$INPUT_FILE" ]]; then
  echo "ERROR: No file found in input artifact" >&2
  exit 1
fi
cp "$INPUT_FILE" input.disk
echo "Input disk ready: input.disk"

# For inject-signed: pull signed artifacts
if [[ "${OPERATION}" == "inject-signed" ]]; then
  if [[ -z "${SIGNED_REF:-}" ]]; then
    echo "ERROR: SIGNED_REF required for inject-signed" >&2
    exit 1
  fi
  echo "Pulling signed artifacts from ${SIGNED_REF}..."
  mkdir -p signed_extract
  oras pull "${SIGNED_REF}" --output signed_extract
  mkdir -p signed_dir
  find signed_extract -type f -exec cp {} signed_dir/ \;
  echo "Signed artifacts ready in signed_dir/"
fi

# Run aib
echo "Running: aib --verbose ${OPERATION} ..."
case "${OPERATION}" in
  prepare-reseal)
    aib --verbose prepare-reseal input.disk output.disk
    ;;
  reseal)
    aib --verbose reseal input.disk output.disk
    ;;
  extract-for-signing)
    mkdir -p output_dir
    aib --verbose extract-for-signing input.disk output_dir
    ;;
  inject-signed)
    aib --verbose inject-signed input.disk signed_dir output.disk
    ;;
  *)
    echo "ERROR: Unknown operation ${OPERATION}" >&2
    exit 1
    ;;
esac

# Push output (except extract-for-signing which outputs a dir; could push as tarball)
if [[ -n "${OUTPUT_REF:-}" ]]; then
  echo "Pushing result to ${OUTPUT_REF}..."
  if [[ "${OPERATION}" == "extract-for-signing" ]]; then
    tar -C output_dir -czf output.tar.gz .
    oras push "${OUTPUT_REF}" output.tar.gz
  else
    oras push "${OUTPUT_REF}" output.disk
  fi
  echo "Pushed to ${OUTPUT_REF}"
fi

echo "=== Sealed operation completed ==="
