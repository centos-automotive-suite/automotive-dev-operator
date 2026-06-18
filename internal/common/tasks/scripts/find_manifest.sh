#!/bin/sh
set -e

echo "looking for manifest file..."

echo "listing contents of manifest config workspace:"
ls -la "$(workspaces.manifest-config-workspace.path)"

MANIFEST_FILE=$(find "$(workspaces.manifest-config-workspace.path)" \( -name '*.mpp.yml' -o -name '*.aib.yml' \) -type f | head -n 1)

if [ -z "$MANIFEST_FILE" ]; then
  echo "No manifest file found in the ConfigMap"
  exit 1
fi

echo "found manifest file at $MANIFEST_FILE"

manifest_basename=$(basename "$MANIFEST_FILE")
workspace_manifest="/manifest-work/$manifest_basename"

cp "$MANIFEST_FILE" "$workspace_manifest"
echo "created working copy of manifest at $workspace_manifest"

# Copy uploaded files from shared workspace to manifest-work so they're accessible to AIB build container
SHARED_WS="$(workspaces.shared-workspace.path)"
if [ -d "$SHARED_WS" ] && [ "$(ls -A "$SHARED_WS" 2>/dev/null)" ]; then
  echo "Copying uploaded files from $SHARED_WS to /manifest-work/"
  for item in "$SHARED_WS"/*; do
    base="$(basename "$item")"
    # Skip build-cache (osbuild store) and known build artifacts from previous runs
    case "$base" in
      build-cache|aib-manifest.yml|image.json|disk.img|*-parts) continue ;;
    esac
    cp -rv "$item" /manifest-work/ 2>/dev/null || true
  done
  echo "Files copied to /manifest-work/:"
  find /manifest-work -type f | head -20
fi

cat "$workspace_manifest" > "$workspace_manifest.tmp"

# rewrite_add_files_paths rewrites relative source/source_path/source_glob
# values in add_files to absolute /manifest-work/ paths.
# Usage: rewrite_add_files_paths <yq_prefix>
#   e.g. rewrite_add_files_paths ".content.add_files"
rewrite_add_files_paths() {
  prefix="$1"
  yq eval "$prefix" "$workspace_manifest.tmp" | grep -q '^[^#]' || return 0

  # source -> source_path (legacy field)
  for idx in $(yq eval "$prefix | to_entries | .[] | select(.value.source != null and .value.text == null) | .key" "$workspace_manifest.tmp"); do
    yq eval -i "${prefix}[$idx].source_path = \"/manifest-work/\" + (${prefix}[$idx].source // \"\")" "$workspace_manifest.tmp"
  done

  # source_path (relative only)
  for idx in $(yq eval "$prefix | to_entries | .[] | select(.value.source_path != null and (.value.source_path | test(\"^/\") | not) and .value.text == null) | .key" "$workspace_manifest.tmp"); do
    yq eval -i "${prefix}[$idx].source_path = \"/manifest-work/\" + (${prefix}[$idx].source_path // \"\")" "$workspace_manifest.tmp"
  done

  # source_glob: do NOT rewrite to absolute paths.
  # AIB's absolute glob handler strips one extra directory component via
  # dirname(), which breaks preserve_path (e.g. /etc/etc/ instead of /etc/).
  # Since files are already copied into /manifest-work/ and the manifest lives
  # there too, relative globs resolve correctly without rewriting.
}

rewrite_add_files_paths ".content.add_files"
rewrite_add_files_paths ".qm.content.add_files"

# Replace original with processed file
mv "$workspace_manifest.tmp" "$workspace_manifest"

echo "updated manifest contents:"
cat "$workspace_manifest"

mkdir -p /tekton/results
printf '%s' "$workspace_manifest" > /tekton/results/manifest-file-path
