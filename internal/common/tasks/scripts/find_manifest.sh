#!/bin/sh
set -e

echo "looking for manifest file..."

echo "listing contents of manifest config workspace:"
ls -la $(workspaces.manifest-config-workspace.path)

MANIFEST_FILE=$(find $(workspaces.manifest-config-workspace.path) -name '*.mpp.yml' -o -name '*.aib.yml' -type f | head -n 1)

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

if yq eval '.content.add_files' "$workspace_manifest.tmp" | grep -q '^[^#]'; then
  indices=$(yq eval '.content.add_files | to_entries | .[] | select(.value.source != null and .value.text == null) | .key' "$workspace_manifest.tmp")

  for idx in $indices; do
    yq eval -i ".content.add_files[$idx].source_path = \"/manifest-work/\" + (.content.add_files[$idx].source // \"\")" "$workspace_manifest.tmp"
  done

  sp_indices=$(yq eval '.content.add_files | to_entries | .[] | select(.value.source_path != null and (.value.source_path | test("^/") | not) and .value.text == null) | .key' "$workspace_manifest.tmp")
  for idx in $sp_indices; do
    yq eval -i ".content.add_files[$idx].source_path = \"/manifest-work/\" + (.content.add_files[$idx].source_path // \"\")" "$workspace_manifest.tmp"
  done
fi

if yq eval '.qm.content.add_files' "$workspace_manifest.tmp" | grep -q '^[^#]'; then
  indices=$(yq eval '.qm.content.add_files | to_entries | .[] | select(.value.source != null and .value.text == null) | .key' "$workspace_manifest.tmp")

  for idx in $indices; do
    yq eval -i ".qm.content.add_files[$idx].source_path = \"/manifest-work/\" + (.qm.content.add_files[$idx].source // \"\")" "$workspace_manifest.tmp"
  done

  sp_indices=$(yq eval '.qm.content.add_files | to_entries | .[] | select(.value.source_path != null and (.value.source_path | test("^/") | not) and .value.text == null) | .key' "$workspace_manifest.tmp")
  for idx in $sp_indices; do
    yq eval -i ".qm.content.add_files[$idx].source_path = \"/manifest-work/\" + (.qm.content.add_files[$idx].source_path // \"\")" "$workspace_manifest.tmp"
  done
fi

# Replace original with processed file
mv "$workspace_manifest.tmp" "$workspace_manifest"

echo "updated manifest contents:"
cat "$workspace_manifest"

mkdir -p /tekton/results
echo -n "$workspace_manifest" > /tekton/results/manifest-file-path
