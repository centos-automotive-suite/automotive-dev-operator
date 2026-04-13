# NOTE: common.sh is prepended to this script at embed time.

set -euo pipefail

image_url="${IMAGE_URL}"
image_digest="${IMAGE_DIGEST}"
sbom_format="${SBOM_FORMAT}"
result_path="${RESULT_PATH}"

if [ -z "$image_url" ] || [ -z "$image_digest" ]; then
  echo "ERROR: IMAGE_URL and IMAGE_DIGEST are required" >&2
  exit 1
fi

image_ref="${image_url}@${image_digest}"

echo "=== SBOM Generation ==="
echo "  Image:  ${image_ref}"
echo "  Format: ${sbom_format}"

emit_progress "Generating SBOM" 0 2

# Generate SBOM from the OCI artifact
sbom_file="/tmp/sbom.json"
syft "${image_ref}" -o "${sbom_format}=${sbom_file}" 2>&1 || {
  echo "ERROR: SBOM generation failed" >&2
  exit 1
}

emit_progress "Generating SBOM" 1 2

sbom_size=$(wc -c < "$sbom_file" | tr -d '[:space:]')
echo "  SBOM generated: ${sbom_size} bytes"

# Determine SBOM media type based on format
case "${sbom_format}" in
  spdx-json)       sbom_media_type="application/spdx+json" ;;
  cyclonedx-json)  sbom_media_type="application/vnd.cyclonedx+json" ;;
  *)               sbom_media_type="application/json" ;;
esac

# Attach the SBOM as an OCI referrer to the original artifact
echo "Attaching SBOM to ${image_ref}..."

attach_output=$(DOCKER_CONFIG="${DOCKER_CONFIG:-}" oras attach \
  --artifact-type "${sbom_media_type}" \
  "${image_ref}" \
  "${sbom_file}:${sbom_media_type}" 2>&1) || {
  echo "ERROR: Failed to attach SBOM to artifact" >&2
  echo "$attach_output" >&2
  exit 1
}
echo "$attach_output"

# Extract SBOM referrer digest from oras attach output
sbom_digest=$(echo "$attach_output" | grep -i '^Digest:' | awk '{print $2}' | head -1)
if [ -z "$sbom_digest" ]; then
  echo "ERROR: Failed to parse SBOM digest from oras attach output" >&2
  exit 1
fi

sbom_ref="${image_url}@${sbom_digest}"
printf '%s' "${sbom_ref}" > "${result_path}"

emit_progress "Generating SBOM" 2 2

echo ""
echo "=== SBOM attached successfully ==="
echo "  SBOM_URI: ${sbom_ref}"

rm -f "$sbom_file"
