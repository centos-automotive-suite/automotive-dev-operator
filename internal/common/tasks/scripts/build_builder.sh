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

load_custom_definitions "$(workspaces.manifest-config-workspace.path)/custom-definitions.env"
BUILDER_CACHE_TAG=$(builder_cache_tag "$AIB_IMAGE" "$DISTRO" "$TARGET_ARCH" "${CUSTOM_DEFS_ARGS[@]}")
TARGET_IMAGE="${REGISTRY}/${NAMESPACE}/aib-build:${BUILDER_CACHE_TAG}"
echo "AIB image: $AIB_IMAGE (builder cache tag: $BUILDER_CACHE_TAG)"

setup_container_config
setup_var_tmp

# Local target name for pushing to registry
LOCAL_TARGET="localhost/aib-build:${BUILDER_CACHE_TAG}"

BUILDER_TOTAL=2

emit_progress "Checking builder cache" 0 "$BUILDER_TOTAL"

install_custom_ca_certs
setup_osbuild

emit_progress "Preparing builder image" 1 "$BUILDER_TOTAL"
# Used by the embedded builder cache helper.
# shellcheck disable=SC2034
declare -a SKOPEO_INSPECT_TLS_ARGS=() SKOPEO_COPY_TLS_ARGS=()
refresh_builder_image "$TARGET_IMAGE" "$LOCAL_TARGET" "$REGISTRY_AUTH_FILE" \
  --distro "$DISTRO" "${CUSTOM_DEFS_ARGS[@]}"

emit_progress "Builder ready" "$BUILDER_TOTAL" "$BUILDER_TOTAL"
echo "Builder image ready: $BUILDER_IMAGE"
echo -n "$BUILDER_IMAGE" > "$RESULT_PATH"
