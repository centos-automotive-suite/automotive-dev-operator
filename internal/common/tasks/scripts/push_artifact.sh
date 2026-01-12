#!/bin/sh
set -e

# Trim whitespace/newlines from the filename
exportFile=$(echo "$(params.artifact-filename)" | tr -d '[:space:]')

if [ -z "$exportFile" ]; then
  echo "ERROR: artifact-filename param is empty"
  echo "Available files in workspace:"
  ls -la /workspace/shared/
  exit 1
fi

if [ ! -f "$exportFile" ]; then
  echo "ERROR: Artifact file not found: $exportFile"
  echo "Available files in workspace:"
  ls -la /workspace/shared/
  exit 1
fi

case "$exportFile" in
  *.gz)
    mediaType="application/gzip"
    ;;
  *.lz4)
    mediaType="application/x-lz4"
    ;;
  *.xz)
    mediaType="application/x-xz"
    ;;
  *.qcow2)
    mediaType="application/x-qcow2"
    ;;
  *.raw|*.img)
    mediaType="application/x-raw-disk-image"
    ;;
  *)
    mediaType="application/octet-stream"
    ;;
esac

echo "Pushing artifact to $(params.repository-url)"
echo "File: ${exportFile}"
echo "Media type: ${mediaType}"

oras push --disable-path-validation \
  $(params.repository-url) \
  ${exportFile}:${mediaType}

echo "Artifact pushed successfully to registry"
