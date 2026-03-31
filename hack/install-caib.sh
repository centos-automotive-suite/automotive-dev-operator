#!/bin/bash
set -euo pipefail

REPO="centos-automotive-suite/automotive-dev-operator"

# Determine version
VERSION="${1:-latest}"

if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" | grep -i '^location:' | sed 's|.*/||' | tr -d '\r')
    if [ -z "$VERSION" ]; then
        echo "Error: could not determine latest release version" >&2
        exit 1
    fi
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
    linux)
        case "${ARCH}" in
            x86_64)  SUFFIX="linux-amd64" ;;
            aarch64) SUFFIX="linux-arm64" ;;
            *) echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
        esac
        ;;
    darwin)
        case "${ARCH}" in
            arm64) SUFFIX="darwin-arm64" ;;
            *) echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: ${OS}" >&2
        exit 1
        ;;
esac

ARTIFACT="caib-${VERSION}-${SUFFIX}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
INSTALL_DIR="/usr/local/bin"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading caib ${VERSION} for ${OS}/${ARCH}..."
curl -fSL -o "${TMPDIR}/${ARTIFACT}" "$URL"

# Verify checksum
echo "Verifying checksum..."
curl -fSL -o "${TMPDIR}/checksums.txt" "$CHECKSUMS_URL"
if ! grep -q "${ARTIFACT}" "${TMPDIR}/checksums.txt"; then
    echo "Error: No checksum entry found for ${ARTIFACT}" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMPDIR" && grep "${ARTIFACT}" checksums.txt | sha256sum -c -)
else
    (cd "$TMPDIR" && grep "${ARTIFACT}" checksums.txt | shasum -a 256 -c -)
fi

# Extract
tar xzf "${TMPDIR}/${ARTIFACT}" -C "$TMPDIR"
chmod +x "${TMPDIR}/caib"

if [ -w "$INSTALL_DIR" ]; then
    mv "${TMPDIR}/caib" "${INSTALL_DIR}/caib"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "${TMPDIR}/caib" "${INSTALL_DIR}/caib"
fi

echo "caib ${VERSION} installed to ${INSTALL_DIR}/caib"
