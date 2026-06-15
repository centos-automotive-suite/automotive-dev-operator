# NOTE: common.sh is prepended to this script at embed time.

ORAS_VERSION="1.2.0"
# Detect container architecture
case "$(uname -m)" in
  x86_64) ORAS_ARCH="amd64" ;;
  aarch64|arm64) ORAS_ARCH="arm64" ;;
  *)
    echo "ERROR: Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
ORAS_TARBALL="oras_${ORAS_VERSION}_linux_${ORAS_ARCH}.tar.gz"
ORAS_BASE_URL="https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}"
ORAS_CHECKSUMS="oras_${ORAS_VERSION}_checksums.txt"

cleanup_oras_files() {
  rm -f "$ORAS_TARBALL" "$ORAS_CHECKSUMS" oras
}

trap cleanup_oras_files EXIT

echo "Downloading ORAS ${ORAS_VERSION} with integrity verification..."

curl -LO "${ORAS_BASE_URL}/${ORAS_TARBALL}" || {
  echo "ERROR: Failed to download ORAS tarball" >&2
  exit 1
}

curl -LO "${ORAS_BASE_URL}/${ORAS_CHECKSUMS}" || {
  echo "ERROR: Failed to download ORAS checksums" >&2
  exit 1
}

expected_checksum=$(grep "${ORAS_TARBALL}" "${ORAS_CHECKSUMS}" | cut -d' ' -f1)
if [ -z "$expected_checksum" ]; then
  echo "ERROR: Could not find checksum for ${ORAS_TARBALL} in checksums file" >&2
  exit 1
fi

if command -v sha256sum >/dev/null; then
  actual_checksum=$(sha256sum "${ORAS_TARBALL}" | cut -d' ' -f1)
elif command -v shasum >/dev/null; then
  actual_checksum=$(shasum -a 256 "${ORAS_TARBALL}" | cut -d' ' -f1)
else
  echo "ERROR: Neither sha256sum nor shasum available for checksum verification" >&2
  exit 1
fi

if [ "$expected_checksum" != "$actual_checksum" ]; then
  echo "ERROR: Checksum verification failed for ${ORAS_TARBALL}" >&2
  echo "  Expected: $expected_checksum" >&2
  echo "  Actual:   $actual_checksum" >&2
  exit 1
fi

echo "Checksum verification passed: $expected_checksum"

tar -zxf "$ORAS_TARBALL" oras || {
  echo "ERROR: Failed to extract ORAS from tarball" >&2
  exit 1
}

mkdir -p "$HOME/bin"
mv oras "$HOME/bin/" || {
  echo "ERROR: Failed to install ORAS binary" >&2
  exit 1
}

if ! echo "$PATH" | grep -q "$HOME/bin"; then
  export PATH="$HOME/bin:$PATH"
fi

cleanup_oras_files
trap - EXIT

echo "ORAS ${ORAS_VERSION} installed successfully"

# Get media type based on file format and compression
get_media_type() {
  case "$1" in
    *.tar.gz)         echo "$OCI_MEDIA_LAYER_GZIP" ;;
    *.tar.lz4)        echo "$OCI_MEDIA_LAYER_LZ4" ;;
    *.tar.xz)         echo "$OCI_MEDIA_LAYER_XZ" ;;
    *.tar)            echo "$OCI_MEDIA_LAYER_BASE" ;;

    *.simg.gz)        echo "${OCI_MEDIA_DISK_SIMG}${OCI_COMPRESS_SUFFIX_GZIP}" ;;
    *.simg.lz4)       echo "${OCI_MEDIA_DISK_SIMG}${OCI_COMPRESS_SUFFIX_LZ4}" ;;
    *.simg.xz)        echo "${OCI_MEDIA_DISK_SIMG}${OCI_COMPRESS_SUFFIX_XZ}" ;;
    *.raw.gz|*.img.gz) echo "${OCI_MEDIA_DISK_RAW}${OCI_COMPRESS_SUFFIX_GZIP}" ;;
    *.raw.lz4|*.img.lz4) echo "${OCI_MEDIA_DISK_RAW}${OCI_COMPRESS_SUFFIX_LZ4}" ;;
    *.raw.xz|*.img.xz) echo "${OCI_MEDIA_DISK_RAW}${OCI_COMPRESS_SUFFIX_XZ}" ;;
    *.qcow2.gz)       echo "${OCI_MEDIA_DISK_QCOW2}${OCI_COMPRESS_SUFFIX_GZIP}" ;;
    *.qcow2.lz4)      echo "${OCI_MEDIA_DISK_QCOW2}${OCI_COMPRESS_SUFFIX_LZ4}" ;;
    *.qcow2.xz)       echo "${OCI_MEDIA_DISK_QCOW2}${OCI_COMPRESS_SUFFIX_XZ}" ;;

    *.simg)           echo "$OCI_MEDIA_DISK_SIMG" ;;
    *.raw|*.img)      echo "$OCI_MEDIA_DISK_RAW" ;;
    *.qcow2)          echo "$OCI_MEDIA_DISK_QCOW2" ;;

    *.gz)             echo "$OCI_MEDIA_GZIP" ;;
    *.lz4)            echo "$OCI_MEDIA_LZ4" ;;
    *.xz)             echo "$OCI_MEDIA_XZ" ;;

    *)                echo "$OCI_MEDIA_OCTETSTREAM" ;;
  esac
}

# Safely escape string for JSON (escape quotes, backslashes, control chars)
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g; s/\n/\\n/g; s/\r/\\r/g'
}

get_artifact_type() {
  case "$1" in
    *.simg.gz|*.simg.lz4|*.simg.xz|*.simg) echo "$OCI_MEDIA_DISK_SIMG" ;;
    *.qcow2.gz|*.qcow2.lz4|*.qcow2.xz|*.qcow2) echo "$OCI_MEDIA_DISK_QCOW2" ;;
    *.raw.gz|*.raw.lz4|*.raw.xz|*.raw|*.img.gz|*.img.lz4|*.img.xz|*.img) echo "$OCI_MEDIA_DISK_RAW" ;;
    *) echo "$OCI_MEDIA_OCTETSTREAM" ;;
  esac
}

get_partition_name() {
  # Strip base extension (.simg/.raw/.img), optional .tar, and optional compression (.gz/.lz4/.xz)
  # Examples: boot_a.simg.gz -> boot_a, foo.simg.tar.gz -> foo, system.raw.lz4 -> system
  basename "$1" | sed -E 's/\.(simg|raw|img)(\.tar)?(\.(gz|lz4|xz))?$//'
}

# Remap partition names for specific targets where AIB's logical names
# don't match the physical partition layout on the device.
# Args: $1 = partition name, $2 = target
remap_partition_for_target() {
  part_name="$1"
  target_name="$2"

  # ride4* and ridesx4* targets use system_b for qm_var content
  case "$target_name" in
    ride4*|ridesx4*)
      case "$part_name" in
        qm_var) echo "system_b" ; return ;;
      esac
      ;;
  esac

  echo "$part_name"
}


# Get decompressed file size from sidecar .size file (created by build_image.sh)
# Falls back to empty string if sidecar doesn't exist
get_decompressed_size() {
  file="$1"
  size_file="${file}.size"
  if [ -f "$size_file" ]; then
    cat "$size_file"
  else
    echo ""
  fi
}

exportFile=$(echo "$(params.artifact-filename)" | tr -d '[:space:]')

if [ -z "$exportFile" ]; then
  echo "ERROR: artifact-filename param is empty"
  ls -la /workspace/shared/
  exit 1
fi

repo_url="$(params.repository-url)"
parts_dir="${exportFile}-parts"
distro="$(params.distro)"
target="$(params.target)"
arch="$(params.arch)"
builder_image_used="$(params.builder-image)"
aib_version="$(params.aib-version)"
aib_image="$(params.automotive-image-builder)"
aib_command="$(params.aib-command)"
SECURE_BUILD="$(params.secure-build)"
insecure_registry="$(params.insecure-registry)"
REPRODUCIBLE="$(params.reproducible)"
TASK_BUNDLE_REF="$(params.task-bundle-ref)"
CUSTOM_DEFINES="$(params.custom-defines)"
AIB_EXTRA_ARGS="$(params.aib-extra-args)"
EXPORT_FORMAT="$(params.export-format)"

ORAS_EXTRA_ARGS=()
if [ "$insecure_registry" = "true" ]; then
  registry_host="${repo_url%%/*}"
  # shellcheck disable=SC2207
  ORAS_EXTRA_ARGS=($(detect_registry_protocol "$registry_host"))
fi

config_file="/etc/target-defaults/target-defaults.yaml"
default_partitions=""
if [ -f "$config_file" ]; then
  # Use yq to extract included partitions for target (using bracket notation for safety)
  default_partitions=$(yq eval ".targets[\"${target}\"].include[]" "$config_file" 2>/dev/null | tr '\n' ',' | sed 's/,$//')

  if [ -n "$default_partitions" ]; then
    echo "Default partitions for target '$target': $default_partitions"
  else
    echo "No default partitions configured for target '$target', skipping default-partitions annotation"
  fi
else
  echo "No partition configuration found, skipping default-partitions annotation"
fi

cd /workspace/shared

# Verify artifact integrity against the digest produced by the build task.
EXPECTED_DIGEST="$(params.expected-artifact-digest)"
if [ -n "$EXPECTED_DIGEST" ]; then
  echo "=== Artifact Integrity Verification ==="
  ACTUAL_DIGEST=$(compute_artifact_digest "${parts_dir}" "${exportFile}")
  if [ -z "$ACTUAL_DIGEST" ]; then
    echo "WARNING: Cannot verify integrity — artifact not found yet"
  fi
  if [ -n "$ACTUAL_DIGEST" ]; then
    if [ "$EXPECTED_DIGEST" != "$ACTUAL_DIGEST" ]; then
      echo "ERROR: Artifact integrity check failed!" >&2
      echo "  Expected: $EXPECTED_DIGEST" >&2
      echo "  Actual:   $ACTUAL_DIGEST" >&2
      exit 1
    fi
    echo "  Integrity verified: $ACTUAL_DIGEST"
  fi
else
  echo "No artifact integrity digest provided, skipping verification"
fi

echo "=== Artifact Push Configuration ==="
echo "  Working directory: $(pwd)"
echo "  Artifact file:     ${exportFile}"
echo "  Parts directory:   ${parts_dir}"
echo "  Repository URL:    ${repo_url}"
echo "  Distro: ${distro}, Target: ${target}, Arch: ${arch}"
echo ""

if [ -d "${parts_dir}" ] && [ -n "$(ls -A "${parts_dir}" 2>/dev/null)" ]; then
  echo "Found parts directory: ${parts_dir}"
  echo "Using multi-layer push for individual partition files"

  # For ride4/ridesx4 targets, ensure boot_b exists (normally created by build task;
  # kept here as idempotent fallback for backwards compatibility with older bundles)
  case "$target" in
    ride4*|ridesx4*)
      for boot_a_file in "${parts_dir}"/boot_a.*; do
        [ -f "$boot_a_file" ] || continue
        boot_b_file=$(echo "$boot_a_file" | sed 's/boot_a/boot_b/')
        if [ ! -f "$boot_b_file" ]; then
          echo "Duplicating $(basename "$boot_a_file") as $(basename "$boot_b_file") for target $target"
          cp "$boot_a_file" "$boot_b_file"
        fi
      done
      ;;
  esac

  ls -la "${parts_dir}/"

  cd "${parts_dir}"

  # Create annotations file in current directory (ORAS container may not have /tmp)
  annotations_file="./oras-annotations.json"
  trap 'rm -f "$annotations_file"' EXIT

  layer_args=""
  file_list=""

  layer_annotations_json=""

  for part_file in *; do
    # Skip .size sidecar files and aib-manifest.yml (added separately below)
    case "$part_file" in *.size|aib-manifest.yml) continue ;; esac

    if [ -f "$part_file" ]; then
      filename="$part_file"
      part_media_type=$(get_media_type "$filename")
      raw_partition_name=$(get_partition_name "$filename")
      partition_name=$(remap_partition_for_target "$raw_partition_name" "$target")
      decompressed_size=$(get_decompressed_size "$filename")


      echo "  Layer: ${filename} (partition: ${partition_name}, type: ${part_media_type}, decompressed: ${decompressed_size:-unknown})"

      # Build layer argument: file:media-type (no path prefix = flat extraction)
      layer_args="${layer_args} ${filename}:${part_media_type}"

      # Build comma-separated file list for parts annotation
      if [ -z "$file_list" ]; then
        file_list="${filename}"
      else
        file_list="${file_list},${filename}"
      fi

      # Build per-layer annotation JSON entry with safe escaping
      # Include partition name, decompressed size, and standard OCI title
      if [ -n "$layer_annotations_json" ]; then
        layer_annotations_json="${layer_annotations_json},"
      fi

      escaped_filename=$(json_escape "$filename")
      escaped_partition=$(json_escape "$partition_name")
      escaped_decompressed_size=$(json_escape "$decompressed_size")

      # Build JSON with properly escaped values
      if [ -n "$decompressed_size" ]; then
        layer_annotations_json="${layer_annotations_json}\"${escaped_filename}\":{\"${OCI_LAYER_ANN_PARTITION}\":\"${escaped_partition}\",\"${OCI_LAYER_ANN_ORG_OPENCONTAINERS_IMAGE_TITLE}\":\"${escaped_filename}\",\"${OCI_LAYER_ANN_DECOMPRESSED_SIZE}\":\"${escaped_decompressed_size}\"}"
      else
        layer_annotations_json="${layer_annotations_json}\"${escaped_filename}\":{\"${OCI_LAYER_ANN_PARTITION}\":\"${escaped_partition}\",\"${OCI_LAYER_ANN_ORG_OPENCONTAINERS_IMAGE_TITLE}\":\"${escaped_filename}\"}"
      fi
    fi
  done

  if [ -z "$file_list" ]; then
    echo "ERROR: No partition files found in ${parts_dir}" >&2
    echo "  Expected .simg, .raw, or .img files but directory appears empty or contains no regular files" >&2
    ls -la . >&2 || true
    exit 1
  fi

  # Get artifact type from first entry in filtered file_list
  first_filename=$(echo "$file_list" | cut -d',' -f1)
  artifact_type=$(get_artifact_type "$first_filename")

  manifest_annotations_json=$(python3 - \
      "$distro" "$target" "$arch" "$file_list" \
      "$default_partitions" "$builder_image_used" "$aib_version" "$aib_image" "$aib_command" "$TASK_BUNDLE_REF" \
      "$CUSTOM_DEFINES" "$AIB_EXTRA_ARGS" "$EXPORT_FORMAT" <<'PYEOF'
import json, os, sys
distro, target, arch, parts, default_parts, builder, aib_ver, aib_img, aib_cmd, task_bundle, custom_defs, extra_args, export_fmt = sys.argv[1:14]
e = os.environ
a = {
    e["OCI_ANN_MULTI_LAYER"]:  "true",
    e["OCI_ANN_PARTS"]:        parts,
    e["OCI_ANN_DISTRO"]:       distro,
    e["OCI_ANN_TARGET"]:       target,
    e["OCI_ANN_ARCH"]:         arch,
}
if default_parts: a[e["OCI_ANN_DEFAULT_PARTITIONS"]]      = default_parts
if builder:       a[e["OCI_ANN_BUILDER_IMAGE"]]            = builder
if aib_ver:       a[e["OCI_ANN_AIB_VERSION"]]              = aib_ver
if aib_img:       a[e["OCI_ANN_AUTOMOTIVE_IMAGE_BUILDER"]] = aib_img
if aib_cmd:       a[e["OCI_ANN_AIB_COMMAND"]]              = aib_cmd
if task_bundle:   a[e["OCI_ANN_TASK_BUNDLE_REF"]]          = task_bundle
if custom_defs:   a[e["OCI_ANN_CUSTOM_DEFINES"]]           = custom_defs
if extra_args:    a[e["OCI_ANN_AIB_EXTRA_ARGS"]]           = extra_args
if export_fmt:    a[e["OCI_ANN_EXPORT_FORMAT"]]            = export_fmt
print(json.dumps(a))
PYEOF
)

  cat > "$annotations_file" <<EOF
{
  "\$manifest": ${manifest_annotations_json},
  ${layer_annotations_json}
}
EOF

  emit_progress "Pushing artifact" 0 1

  echo ""
  echo "Pushing multi-layer artifact to ${repo_url}"
  echo "  Artifact type: ${artifact_type}"
  echo "  Parts: ${file_list}"
  echo "  Annotations file: ${annotations_file}"
  cat "$annotations_file"

  # Push with multi-layer manifest using annotation file
  # Files are pushed from current directory (parts_dir) so they extract flat
  set -o pipefail
  "$HOME/bin/oras" push "${ORAS_EXTRA_ARGS[@]}" --disable-path-validation \
    --image-spec v1.1 \
    --artifact-type "${artifact_type}" \
    --annotation-file "$annotations_file" \
    "${repo_url}" \
    ${layer_args} 2>&1 | tee /tmp/oras-push-output.txt
  set +o pipefail

  # Clean up annotation file (also handled by trap)
  rm -f "$annotations_file"

  emit_progress "Pushing artifact" 1 1

  echo ""
  echo "=== Multi-layer artifact pushed successfully ==="

else
  # Fallback to single-file push (original behavior)
  if [ ! -f "${exportFile}" ]; then
    echo "ERROR: Artifact file not found: ${exportFile}"
    ls -la /workspace/shared/
    exit 1
  fi

  media_type=$(get_media_type "${exportFile}")

  parts_list=""
  if echo "${exportFile}" | grep -q '\.tar'; then
    echo "Listing tar contents for annotation"
    parts_list=$(tar -tf "${exportFile}" 2>/dev/null | grep -v '/$' | xargs -I{} basename {} | sort | tr '\n' ',' | sed 's/,$//')
    [ -n "$parts_list" ] && echo "  Contents: ${parts_list}"
  fi

  single_annotations_file="./oras-single-annotations.json"
  trap 'rm -f "$single_annotations_file"' EXIT
  python3 - "$single_annotations_file" \
      "$distro" "$target" "$arch" \
      "$parts_list" "$builder_image_used" "$aib_version" "$aib_image" "$aib_command" "$TASK_BUNDLE_REF" \
      "$CUSTOM_DEFINES" "$AIB_EXTRA_ARGS" "$EXPORT_FORMAT" <<'PYEOF'
import json, os, sys
from pathlib import Path

out_file, distro, target, arch, parts, builder, aib_ver, aib_img, aib_cmd, task_bundle, custom_defs, extra_args, export_fmt = sys.argv[1:14]
e = os.environ
annotations = {
    e["OCI_ANN_DISTRO"]: distro,
    e["OCI_ANN_TARGET"]: target,
    e["OCI_ANN_ARCH"]:   arch,
}
if parts:         annotations[e["OCI_ANN_PARTS"]]                    = parts
if builder:       annotations[e["OCI_ANN_BUILDER_IMAGE"]]            = builder
if aib_ver:       annotations[e["OCI_ANN_AIB_VERSION"]]              = aib_ver
if aib_img:       annotations[e["OCI_ANN_AUTOMOTIVE_IMAGE_BUILDER"]] = aib_img
if aib_cmd:       annotations[e["OCI_ANN_AIB_COMMAND"]]              = aib_cmd
if task_bundle:   annotations[e["OCI_ANN_TASK_BUNDLE_REF"]]          = task_bundle
if custom_defs:   annotations[e["OCI_ANN_CUSTOM_DEFINES"]]           = custom_defs
if extra_args:    annotations[e["OCI_ANN_AIB_EXTRA_ARGS"]]           = extra_args
if export_fmt:    annotations[e["OCI_ANN_EXPORT_FORMAT"]]            = export_fmt
Path(out_file).write_text(json.dumps({"$manifest": annotations}))
PYEOF

  emit_progress "Pushing artifact" 0 1

  echo "Pushing single-file artifact to ${repo_url}"
  echo "  File: ${exportFile}"
  echo "  Media type: ${media_type}"
  echo "  Annotations: distro=${distro}, target=${target}, arch=${arch}"

  set -o pipefail
  "$HOME/bin/oras" push "${ORAS_EXTRA_ARGS[@]}" --disable-path-validation \
    --image-spec v1.1 \
    --artifact-type "${media_type}" \
    --annotation-file "$single_annotations_file" \
    "${repo_url}" \
    "${exportFile}:${media_type}" 2>&1 | tee /tmp/oras-push-output.txt
  set +o pipefail

  emit_progress "Pushing artifact" 1 1

  echo ""
  echo "=== Artifact pushed successfully ==="
fi

# Write Tekton Chains type hint results for disk artifact
DISK_DIGEST=$(sed -n 's/.*Digest: \(sha256:[a-f0-9]*\).*/\1/p' /tmp/oras-push-output.txt 2>/dev/null | head -1)
if [ -z "$DISK_DIGEST" ]; then
  echo "ERROR: Could not extract digest from oras push output." >&2
  echo "Push output was:" >&2
  cat /tmp/oras-push-output.txt >&2
  exit 1
fi
echo -n "${repo_url}" > /tekton/results/IMAGE_URL
echo -n "${DISK_DIGEST}" > /tekton/results/IMAGE_DIGEST
echo "Tekton Chains: IMAGE_URL=${repo_url} IMAGE_DIGEST=${DISK_DIGEST}"
# Write to workspace for cross-task access (avoids Tekton result-ref issues with skipped tasks)
mkdir -p /workspace/shared/.chains/disk
echo -n "${repo_url}" > /workspace/shared/.chains/disk/url
echo -n "${DISK_DIGEST}" > /workspace/shared/.chains/disk/digest

# Attach osbuild manifest as OCI referrer for supply chain verification.
# image.json is the fully-resolved osbuild manifest produced by AIB — it contains
# the complete build recipe (RPMs, stages, filesystem layout).
OSBUILD_MANIFEST="/workspace/shared/image.json"
if [ -f "$OSBUILD_MANIFEST" ] && [ -n "$DISK_DIGEST" ]; then
  echo "Attaching osbuild manifest to ${repo_url}@${DISK_DIGEST}"
  if ! "$HOME/bin/oras" attach --disable-path-validation "${ORAS_EXTRA_ARGS[@]}" \
    --artifact-type "$OCI_REFERRER_TYPE_OSBUILD_MANIFEST" \
    "${repo_url}@${DISK_DIGEST}" \
    "${OSBUILD_MANIFEST}:${OCI_REFERRER_TYPE_OSBUILD_MANIFEST}" 2>&1; then
    if [ "$SECURE_BUILD" = "true" ]; then
      echo "ERROR: Failed to attach osbuild manifest (fatal in secure build mode)"
      exit 1
    fi
    echo "WARNING: Failed to attach osbuild manifest — registry may not support OCI referrers (non-fatal)"
  fi
else
  echo "No osbuild manifest found or no digest available, skipping manifest attach"
fi

# attach_referrer FILE ARTIFACT_TYPE LABEL
# Attaches a file as an OCI referrer. Fatal on failure in reproducible mode.
attach_referrer() {
  local file="$1" artifact_type="$2" label="$3"
  if [ ! -f "$file" ]; then
    echo "ERROR: $label not found at $file (required for reproducible build)"
    exit 1
  fi
  echo "Attaching $label ($(du -sh "$file" | cut -f1)) to ${repo_url}@${DISK_DIGEST}"
  if ! "$HOME/bin/oras" attach "${ORAS_EXTRA_ARGS[@]}" \
    --artifact-type "$artifact_type" \
    "${repo_url}@${DISK_DIGEST}" \
    "${file}:${artifact_type}"; then
    echo "ERROR: Failed to attach $label (fatal in reproducible mode)"
    exit 1
  fi
}

if [ "$REPRODUCIBLE" = "true" ] && [ -n "$DISK_DIGEST" ]; then
  cd /workspace/shared || { echo "ERROR: cannot cd to /workspace/shared"; exit 1; }
  echo "=== Attaching reproducibility artifacts ==="
  attach_referrer "./aib-manifest.yml" \
    "$OCI_REFERRER_TYPE_AIB_MANIFEST" "AIB input manifest"
  attach_referrer "./build-sources.tar.gz" \
    "$OCI_REFERRER_TYPE_BUILD_SOURCES" "osbuild sources archive"
  echo "=== Reproducibility artifacts attached ==="
fi
