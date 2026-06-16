# shellcheck shell=bash
# NOTE: common.sh is prepended to this script at embed time.

echo "Prepare builder for distro: $DISTRO, arch: $TARGET_ARCH"

# If BUILDER_IMAGE is provided, use it directly
if [ -n "$BUILDER_IMAGE" ]; then
  echo "Using provided builder image: $BUILDER_IMAGE"
  echo -n "$BUILDER_IMAGE" > "$RESULT_PATH"
  exit 0
fi

# Determine registry and set up authentication
if [ -n "$CLUSTER_REGISTRY_ROUTE" ]; then
  echo "Using external registry route: $CLUSTER_REGISTRY_ROUTE"
fi
setup_cluster_auth "${CLUSTER_REGISTRY_ROUTE:-}"

# Include a short hash of the AIB image in the registry tag so that different
# AIB versions cache their builder images separately and don't overwrite each other.
AIB_HASH=$(echo -n "$AIB_IMAGE" | sha256sum | cut -c1-8)
TARGET_IMAGE="${REGISTRY}/${NAMESPACE}/aib-build:${DISTRO}-${TARGET_ARCH}-${AIB_HASH}"
echo "AIB image: $AIB_IMAGE (hash: $AIB_HASH)"

setup_container_config
setup_var_tmp

# Local target name for pushing to registry
LOCAL_TARGET="localhost/aib-build:${DISTRO}-${TARGET_ARCH}-${AIB_HASH}"

# Builder has 3 steps: check cache, build, push to registry
BUILDER_TOTAL=3

emit_progress "Checking builder cache" 0 "$BUILDER_TOTAL"

# Check if image already exists in cluster registry
if [ "$REBUILD_BUILDER" = "true" ]; then
  echo "Rebuild requested, skipping cache check"
else
  echo "Checking if $TARGET_IMAGE exists in cluster registry..."
  if skopeo inspect --authfile="$REGISTRY_AUTH_FILE" "docker://$TARGET_IMAGE" >/dev/null 2>&1; then
    echo "Builder image found in cluster registry: $TARGET_IMAGE"
    emit_progress "Builder cached" "$BUILDER_TOTAL" "$BUILDER_TOTAL"
    echo -n "$TARGET_IMAGE" > "$RESULT_PATH"
    exit 0
  fi
fi

echo "Builder image not found, building..."

install_custom_ca_certs
setup_osbuild

load_custom_definitions "$(workspaces.manifest-config-workspace.path)/custom-definitions.env"

emit_progress "Building builder image" 1 "$BUILDER_TOTAL"
echo "Running: aib build-builder --distro $DISTRO ${CUSTOM_DEFS_ARGS[*]} $LOCAL_TARGET"
aib --verbose build-builder --distro "$DISTRO" "${CUSTOM_DEFS_ARGS[@]}" "$LOCAL_TARGET"

echo "Built local image: $LOCAL_TARGET"
emit_progress "Pushing builder to registry" 2 "$BUILDER_TOTAL"
echo "Pushing to cluster registry: $TARGET_IMAGE"
skopeo copy --authfile="$REGISTRY_AUTH_FILE" \
  "containers-storage:$LOCAL_TARGET" \
  "docker://$TARGET_IMAGE"

emit_progress "Builder ready" "$BUILDER_TOTAL" "$BUILDER_TOTAL"
echo "Builder image ready: $TARGET_IMAGE"
echo -n "$TARGET_IMAGE" > "$RESULT_PATH"
