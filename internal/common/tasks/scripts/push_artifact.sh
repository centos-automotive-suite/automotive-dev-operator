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
    *.tar.gz)         echo "application/vnd.oci.image.layer.v1.tar+gzip" ;;
    *.tar.lz4)        echo "application/vnd.oci.image.layer.v1.tar+lz4" ;;
    *.tar.xz)         echo "application/vnd.oci.image.layer.v1.tar+xz" ;;
    *.tar)            echo "application/vnd.oci.image.layer.v1.tar" ;;

    *.simg.gz)        echo "application/vnd.automotive.disk.simg+gzip" ;;
    *.simg.lz4)       echo "application/vnd.automotive.disk.simg+lz4" ;;
    *.simg.xz)        echo "application/vnd.automotive.disk.simg+xz" ;;
    *.raw.gz|*.img.gz) echo "application/vnd.automotive.disk.raw+gzip" ;;
    *.raw.lz4|*.img.lz4) echo "application/vnd.automotive.disk.raw+lz4" ;;
    *.raw.xz|*.img.xz) echo "application/vnd.automotive.disk.raw+xz" ;;
    *.qcow2.gz)       echo "application/vnd.automotive.disk.qcow2+gzip" ;;
    *.qcow2.lz4)      echo "application/vnd.automotive.disk.qcow2+lz4" ;;
    *.qcow2.xz)       echo "application/vnd.automotive.disk.qcow2+xz" ;;

    *.simg)           echo "application/vnd.automotive.disk.simg" ;;
    *.raw|*.img)      echo "application/vnd.automotive.disk.raw" ;;
    *.qcow2)          echo "application/vnd.automotive.disk.qcow2" ;;

    *.gz)             echo "application/gzip" ;;
    *.lz4)            echo "application/x-lz4" ;;
    *.xz)             echo "application/x-xz" ;;

    # Default fallback
    *)                echo "application/octet-stream" ;;
  esac
}

# Safely escape string for JSON (escape quotes, backslashes, control chars)
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g; s/\n/\\n/g; s/\r/\\r/g'
}

get_artifact_type() {
  case "$1" in
    *.simg.gz|*.simg.lz4|*.simg) echo "application/vnd.automotive.disk.simg" ;;
    *.qcow2.gz|*.qcow2.lz4|*.qcow2.xz|*.qcow2) echo "application/vnd.automotive.disk.qcow2" ;;
    *.raw.gz|*.raw.lz4|*.raw.xz|*.raw|*.img.gz|*.img.lz4|*.img.xz|*.img) echo "application/vnd.automotive.disk.raw" ;;
    *) echo "application/octet-stream" ;;
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

  # For ride4/ridesx4 targets, duplicate boot_a as boot_b so both partitions get flashed
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
        layer_annotations_json="${layer_annotations_json}\"${escaped_filename}\":{\"automotive.sdv.cloud.redhat.com/partition\":\"${escaped_partition}\",\"org.opencontainers.image.title\":\"${escaped_filename}\",\"automotive.sdv.cloud.redhat.com/decompressed-size\":\"${escaped_decompressed_size}\"}"
      else
        layer_annotations_json="${layer_annotations_json}\"${escaped_filename}\":{\"automotive.sdv.cloud.redhat.com/partition\":\"${escaped_partition}\",\"org.opencontainers.image.title\":\"${escaped_filename}\"}"
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
      "$default_partitions" "$builder_image_used" "$aib_version" "$aib_image" "$aib_command" <<'PYEOF'
import json, sys
distro, target, arch, parts, default_parts, builder, aib_ver, aib_img, aib_cmd = sys.argv[1:10]
a = {
    "automotive.sdv.cloud.redhat.com/multi-layer": "true",
    "automotive.sdv.cloud.redhat.com/parts":       parts,
    "automotive.sdv.cloud.redhat.com/distro":      distro,
    "automotive.sdv.cloud.redhat.com/target":      target,
    "automotive.sdv.cloud.redhat.com/arch":        arch,
}
if default_parts: a["automotive.sdv.cloud.redhat.com/default-partitions"]      = default_parts
if builder:       a["automotive.sdv.cloud.redhat.com/builder-image"]            = builder
if aib_ver:       a["automotive.sdv.cloud.redhat.com/aib-version"]              = aib_ver
if aib_img:       a["automotive.sdv.cloud.redhat.com/automotive-image-builder"] = aib_img
if aib_cmd:       a["automotive.sdv.cloud.redhat.com/aib-command"]              = aib_cmd
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
  # shellcheck disable=SC2086
  "$HOME/bin/oras" push --disable-path-validation \
    --image-spec v1.1 \
    --artifact-type "${artifact_type}" \
    --annotation-file "$annotations_file" \
    "${repo_url}" \
    ${layer_args}

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
      "$parts_list" "$builder_image_used" "$aib_version" "$aib_image" "$aib_command" <<'PYEOF'
import json, sys
from pathlib import Path

out_file, distro, target, arch, parts, builder, aib_ver, aib_img, aib_cmd = sys.argv[1:10]
annotations = {
    "automotive.sdv.cloud.redhat.com/distro":  distro,
    "automotive.sdv.cloud.redhat.com/target":  target,
    "automotive.sdv.cloud.redhat.com/arch":    arch,
}
if parts:    annotations["automotive.sdv.cloud.redhat.com/parts"]                    = parts
if builder:  annotations["automotive.sdv.cloud.redhat.com/builder-image"]            = builder
if aib_ver:  annotations["automotive.sdv.cloud.redhat.com/aib-version"]              = aib_ver
if aib_img:  annotations["automotive.sdv.cloud.redhat.com/automotive-image-builder"] = aib_img
if aib_cmd:  annotations["automotive.sdv.cloud.redhat.com/aib-command"]              = aib_cmd
Path(out_file).write_text(json.dumps({"$manifest": annotations}))
PYEOF

  emit_progress "Pushing artifact" 0 1

  echo "Pushing single-file artifact to ${repo_url}"
  echo "  File: ${exportFile}"
  echo "  Media type: ${media_type}"
  echo "  Annotations: distro=${distro}, target=${target}, arch=${arch}"

  "$HOME/bin/oras" push --disable-path-validation \
    --image-spec v1.1 \
    --artifact-type "${media_type}" \
    --annotation-file "$single_annotations_file" \
    "${repo_url}" \
    "${exportFile}:${media_type}"

  emit_progress "Pushing artifact" 1 1

  echo ""
  echo "=== Artifact pushed successfully ==="
fi
