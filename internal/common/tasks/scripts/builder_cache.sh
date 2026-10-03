# shellcheck shell=bash

builder_cache_tag() {
  local image="$1" distro="$2" arch="$3" image_hash defs_hash
  shift 3
  image_hash=$(printf '%s' "$image" | sha256sum | cut -c1-8)
  # Keep the default tag compatible with sealed operations' fallback lookup.
  if [ "$#" -eq 0 ]; then
    printf '%s-%s-%s' "$distro" "$arch" "$image_hash"
  else
    # Preserve argument boundaries and ordering, including repeated definitions.
    defs_hash=$(printf '%s\0' "$@" | sha256sum | cut -c1-16)
    printf '%s-%s-%s-%s' "$distro" "$arch" "$image_hash" "$defs_hash"
  fi
}

builder_digest_ref() {
  local ref="$1" digest="$2"
  if [[ ! "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "ERROR: invalid builder image digest: $digest" >&2
    return 1
  fi
  ref="${ref%%@*}"
  local name="${ref##*/}"
  if [[ "$ref" == */* ]]; then
    printf '%s@%s' "${ref%/*}/${name%%:*}" "$digest"
  else
    printf '%s@%s' "${name%%:*}" "$digest"
  fi
}

builder_local_digest() {
  local image="$1" digest
  if ! digest=$(skopeo inspect --format '{{.Digest}}' "containers-storage:$image"); then
    echo "ERROR: could not inspect local builder: $image" >&2
    return 1
  fi
  if [ -z "$digest" ]; then
    echo "ERROR: local builder has no manifest digest: $image" >&2
    return 1
  fi
  printf '%s' "$digest"
}

# Sets BUILDER_IMAGE to the registry digest corresponding to the local helper.
# Compare local digests separately: registry copies may convert manifest formats.
refresh_builder_image() {
  local target="$1" local_image="$2" auth_file="$3" sync_local="$4"
  shift 4
  local cached_digest="" old_local_digest="" new_local_digest pinned_ref digest_file
  local cache_policy="${BUILDER_CACHE_POLICY:-validate}"
  local -a freshness_args=(--if-needed)

  case "$cache_policy" in
    validate|reuse) ;;
    *) echo "ERROR: invalid builder cache policy: $cache_policy (expected validate or reuse)" >&2; return 1 ;;
  esac

  if [ "$REBUILD_BUILDER" = "true" ]; then
    echo "Rebuild requested, skipping builder cache check"
    freshness_args=()
  elif cached_digest=$(skopeo inspect "${SKOPEO_INSPECT_TLS_ARGS[@]}" \
    --authfile="$auth_file" --format '{{.Digest}}' "docker://$target" 2>/dev/null); then
    pinned_ref=$(builder_digest_ref "$target" "$cached_digest") || return 1
    echo "Checking cached builder: $pinned_ref"
    if [ "$cache_policy" != reuse ] || [ "$sync_local" = true ]; then
      # A pin must preserve the registry's compressed layers. Create it before
      # pulling; if cleanup won the race, rebuild instead of publishing a bad ref.
      if { [ "$sync_local" != true ] || pin_builder_image "$pinned_ref" "$auth_file"; } &&
        skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" --authfile="$auth_file" \
          "docker://$pinned_ref" "containers-storage:$local_image"; then
        old_local_digest=$(builder_local_digest "$local_image") || return 1
      else
        echo "WARNING: cached builder is unavailable; rebuilding: $pinned_ref" >&2
        cached_digest=""
        # A failed copy can leave an older local image behind.
        freshness_args=()
      fi
    fi
    if [ "$cache_policy" = reuse ] && [ -n "$cached_digest" ]; then
      echo "Reusing cached builder without checking package freshness: $pinned_ref"
      BUILDER_IMAGE="$pinned_ref"
      return 0
    fi
  else
    cached_digest=""
    echo "No cached builder available: $target"
  fi

  aib --verbose build-builder "${freshness_args[@]}" "$@" "$local_image" || {
    echo "ERROR: builder preparation failed: $local_image" >&2
    return 1
  }
  new_local_digest=$(builder_local_digest "$local_image") || return 1

  if [ -n "$cached_digest" ] && [ "$old_local_digest" = "$new_local_digest" ]; then
    echo "Builder is up to date"
    BUILDER_IMAGE=$(builder_digest_ref "$target" "$cached_digest") || return 1
    return 0
  fi

  digest_file=$(mktemp /tmp/builder-push-digest.XXXXXX) || {
    echo "ERROR: could not create builder push digest file" >&2
    return 1
  }
  echo "Pushing updated builder: $target"
  if ! skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" --authfile="$auth_file" --digestfile "$digest_file" \
    "containers-storage:$local_image" "docker://$target"; then
    rm -f "$digest_file"
    echo "ERROR: could not push updated builder: $target" >&2
    return 1
  fi
  cached_digest=$(cat "$digest_file")
  rm -f "$digest_file"
  pinned_ref=$(builder_digest_ref "$target" "$cached_digest") || return 1

  # Registry conversion can change the manifest digest. Synchronize local
  # consumers with the recorded digest; the prepare-only task has no consumer.
  if [ "$sync_local" = "true" ]; then
    pin_builder_image "$pinned_ref" "$auth_file" || return 1
    skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" --authfile="$auth_file" \
      "docker://$pinned_ref" "containers-storage:$local_image" || {
      echo "ERROR: could not synchronize local builder with pushed digest: $pinned_ref" >&2
      return 1
    }
  fi
  # Consumed by the task script prepended alongside this helper.
  # shellcheck disable=SC2034
  BUILDER_IMAGE="$pinned_ref"
}

# Keep the recorded digest pullable after its cache tag changes or expires.
pin_builder_image() {
  local ref="$1" auth_file="$2" digest pin_ref
  digest="${ref##*@}"
  builder_digest_ref "$ref" "$digest" >/dev/null || return 1
  pin_ref="${ref%@*}:pin-${digest#sha256:}"
  echo "Pinning builder for published artifacts: $pin_ref"
  skopeo copy "${SKOPEO_COPY_TLS_ARGS[@]}" --authfile="$auth_file" --preserve-digests \
    "docker://$ref" "docker://$pin_ref" || {
    echo "ERROR: could not pin builder: $ref" >&2
    return 1
  }
}
