# shellcheck shell=bash

# Adapter between AIB's JSON lockfile and Hermeto's best-effort RPM backend.
# Keep this isolated from the build orchestration so another fetcher can replace it.

aib_lock_check() {
  python3 - "$1" "$2" <<'PYEOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as lockfile:
    lock = json.load(lockfile)

mode = sys.argv[2]
depsolves = lock.get("depsolves", {})
has_rpms = isinstance(depsolves, dict) and any(
    isinstance(entry, dict) and (entry.get("packages") or entry.get("source")) for entry in depsolves.values()
)
if mode == "has-rpms":
    raise SystemExit(not has_rpms)
if mode not in {"rpm-only", "supported-sources"}:
    raise SystemExit(f"unknown AIB lockfile check: {mode}")

if lock.get("version") != 1 or not isinstance(depsolves, dict):
    raise SystemExit("AIB lockfile must have version 1 and object depsolves")

allowed_top_level = {"version", "depsolves"}
if mode == "supported-sources":
    allowed_top_level.update({"containers", "embedded_files", "ostree_commits"})
unknown_top_level = sorted(set(lock) - allowed_top_level)
if unknown_top_level:
    print(
        "unsupported top-level AIB lockfile sections: " + ", ".join(unknown_top_level),
        file=sys.stderr,
    )
    raise SystemExit(1)

allowed_depsolve_keys = {"request", "packages", "source", "module_metadata"}
for key, entry in depsolves.items() if isinstance(depsolves, dict) else ():
    if not isinstance(entry, dict):
        print(f"depsolve {key} must be an object", file=sys.stderr)
        raise SystemExit(1)
    unknown = sorted(set(entry) - allowed_depsolve_keys)
    if unknown:
        print(
            f"depsolve {key} contains unsupported sections: " + ", ".join(unknown),
            file=sys.stderr,
        )
        raise SystemExit(1)
raise SystemExit(0)
PYEOF
}

aib_lock_is_rpm_only() {
  aib_lock_check "$1" rpm-only
}

aib_lock_has_rpms() {
  aib_lock_check "$1" has-rpms
}

aib_lock_has_supported_sources() {
  aib_lock_check "$1" supported-sources
}

verify_locked_non_rpm_sources() {
  local aib_lock="$1" source_store="$2"

  python3 - "$aib_lock" "$source_store" <<'PYEOF'
import hashlib
import json
import pathlib
import re
import subprocess
import sys

lock_path, store = map(pathlib.Path, sys.argv[1:])
lock = json.loads(lock_path.read_text(encoding="utf-8"))


def verify_sha256(path, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SystemExit(f"invalid sha256 checksum: {expected}")
    if not path.is_file():
        raise SystemExit(f"locked source is missing: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit(f"locked source checksum mismatch: {path}")


for entry in lock.get("embedded_files", {}).values():
    checksum = entry["checksum"]
    verify_sha256(store / "org.osbuild.files" / f"sha256:{checksum}", checksum)

for entry in lock.get("containers", {}).values():
    config_digest = entry["config_digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest):
        raise SystemExit(f"invalid container config digest: {config_digest}")
    image_dir = store / "org.osbuild.containers" / config_digest / "image"
    if not image_dir.is_dir():
        raise SystemExit(f"locked container is missing: {image_dir}")
    manifest_digest = entry["manifest_digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest):
        raise SystemExit(f"invalid container manifest digest: {manifest_digest}")
    verify_sha256(image_dir / "manifest.json", manifest_digest.removeprefix("sha256:"))
    config = subprocess.check_output(["skopeo", "inspect", "--raw", "--config", f"dir:{image_dir}"])
    if hashlib.sha256(config).hexdigest() != config_digest.removeprefix("sha256:"):
        raise SystemExit(f"locked container config digest mismatch: {image_dir}")
    if entry.get("request", {}).get("index"):
        index_digest = entry["index_digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", index_digest):
            raise SystemExit(f"invalid container index digest: {index_digest}")
        verify_sha256(store / "org.osbuild.files" / index_digest, index_digest.removeprefix("sha256:"))

if lock.get("ostree_commits"):
    repo = store / "org.osbuild.ostree" / "repo"
    subprocess.run(["ostree", f"--repo={repo}", "fsck"], check=True)
    for entry in lock["ostree_commits"].values():
        checksum = entry["checksum"]
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise SystemExit(f"invalid OSTree commit checksum: {checksum}")
        subprocess.run(["ostree", f"--repo={repo}", "show", checksum],
                       check=True, stdout=subprocess.DEVNULL)
PYEOF
}

convert_aib_lock_to_hermeto() {
  local aib_lock="$1" hermeto_lock="$2" rpm_map="$3" local_map="${4:-$3.local.json}"

  python3 - "$aib_lock" "$hermeto_lock" "$rpm_map" "$local_map" <<'PYEOF'
import hashlib
import json
import pathlib
import posixpath
import re
import sys
import urllib.parse

aib_lock_path, hermeto_lock_path, rpm_map_path, local_map_path = map(pathlib.Path, sys.argv[1:])
with aib_lock_path.open(encoding="utf-8") as lockfile:
    lock = json.load(lockfile)

if lock.get("version") != 1:
    raise SystemExit("AIB lockfile version must be 1")

depsolves = lock.get("depsolves")
if not isinstance(depsolves, dict) or not depsolves:
    raise SystemExit("AIB lockfile contains no depsolved RPM packages")

by_arch = {}
local_entries = {}
rpm_arches = set()
url_checksums = {}
paths = {}
url_paths = {}
supported_hashes = {"sha256", "sha384", "sha512"}
for depsolve_key in sorted(depsolves):
    depsolve = depsolves[depsolve_key]
    arch = depsolve.get("request", {}).get("architecture")
    if not isinstance(arch, str) or not re.fullmatch(r"[A-Za-z0-9_+-]+", arch):
        raise SystemExit(f"depsolve {depsolve_key} has no usable request architecture")

    arch_entries = by_arch.setdefault(arch, {})
    for kind in ("packages", "source", "module_metadata"):
        entries = depsolve.get(kind, [])
        if not isinstance(entries, list):
            raise SystemExit(f"depsolve {depsolve_key} has invalid {kind} list")
        for entry in entries:
            url = entry.get("url")
            checksum = entry.get("checksum")
            if not isinstance(url, str) or not url:
                raise SystemExit(f"depsolve {depsolve_key} contains {kind} without a URL")
            parsed = urllib.parse.urlsplit(url)
            is_local = parsed.scheme == "file"
            if is_local:
                path = posixpath.normpath(urllib.parse.unquote(parsed.path))
                if parsed.netloc or not path.startswith("/extra-repos/oci-repo/"):
                    raise SystemExit(f"file URL is outside OCI repository mount: {url}")
            elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise SystemExit(f"Hermeto spike supports only HTTP(S) URLs: {url}")
            if parsed.query or parsed.fragment:
                raise SystemExit(f"Hermeto spike does not support URL queries or fragments: {url}")
            if not isinstance(checksum, str) or not re.fullmatch(
                r"[A-Za-z0-9_+-]+:[0-9a-f]+", checksum
            ):
                raise SystemExit(f"{kind} has no usable checksum: {url}")
            algorithm = checksum.split(":", 1)[0]
            if algorithm not in supported_hashes:
                raise SystemExit(f"unsupported checksum algorithm {algorithm} for {url}")
            if entry.get("secrets"):
                raise SystemExit(f"Hermeto spike does not support secret-backed URLs: {url}")
            previous_checksum = url_checksums.setdefault(url, checksum)
            if previous_checksum != checksum:
                raise SystemExit(f"URL has conflicting checksums: {url}")

            filename = pathlib.Path(url).name
            if filename in {"", ".", ".."}:
                raise SystemExit(f"URL has no usable filename: {url}")
            if kind != "module_metadata" and not filename.endswith(".rpm"):
                raise SystemExit(f"RPM URL does not end in .rpm: {url}")
            if kind == "source" and not filename.endswith((".src.rpm", ".nosrc.rpm")):
                raise SystemExit(f"Source RPM URL must end in .src.rpm or .nosrc.rpm: {url}")
            if kind == "packages" and filename.endswith((".src.rpm", ".nosrc.rpm")):
                raise SystemExit(f"Source RPM must be listed in source: {url}")

            if kind != "module_metadata":
                rpm_arches.add(arch)
            if is_local:
                item = {"url": url, "checksum": checksum, "kind": kind}
                if kind != "module_metadata":
                    for field in ("name", "evr", "arch"):
                        if not isinstance(entry.get(field), str) or not entry[field]:
                            raise SystemExit(f"Local RPM has no usable {field}: {url}")
                        item[field] = entry[field]
                local_entries[(arch, kind, checksum, url)] = item
                continue

            repoid = entry.get("repoid")
            if kind == "module_metadata" and not repoid:
                raise SystemExit(f"Module metadata requires repoid: {url}")
            if repoid is None:
                # Hermeto omits synthetic repository IDs from RPM PURLs.
                repo_path = parsed.path.rsplit("/", 1)[0] + "/"
                repo_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, repo_path, "", ""))
                repoid = "hermeto-aib-" + hashlib.sha256(repo_url.encode()).hexdigest()[:12]
            if not isinstance(repoid, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", repoid):
                raise SystemExit(f"Invalid repository ID for {url}")

            identity = (kind, repoid, checksum)
            existing = arch_entries.get(identity)
            if existing is not None:
                if url >= existing["url"]:
                    continue
            item = {"url": url, "repoid": repoid, "checksum": checksum}
            for optional in ("name", "evr", "size"):
                if optional in entry:
                    item[optional] = entry[optional]
            arch_entries[identity] = item

arches = []
rpm_map = []
for arch, entries in sorted(by_arch.items()):
    if not entries:
        continue
    output = {"arch": arch}
    for (kind, repoid, checksum), entry in sorted(entries.items()):
        path = str(pathlib.Path("deps/rpm") / arch / repoid / pathlib.Path(entry["url"]).name)
        if paths.setdefault(path, checksum) != checksum:
            raise SystemExit(f"Conflicting downloads target {path}")
        # Hermeto indexes downloads by URL within each architecture.
        if url_paths.setdefault((arch, entry["url"]), path) != path:
            raise SystemExit(f"URL has conflicting repository destinations: {entry['url']}")
        output.setdefault(kind, []).append(entry)
        rpm_map.append({"checksum": checksum, "path": path, "url": entry["url"]})
    if arch not in rpm_arches:
        raise SystemExit(f"Architecture {arch} has no binary or source RPMs")
    arches.append(output)

if not rpm_arches:
    raise SystemExit("AIB lockfile contains no RPM packages")

# JSON is valid YAML 1.2. Emitting it avoids adding a YAML library to the AIB image.
hermeto_lock = {
    "lockfileVersion": 1,
    "lockfileVendor": "redhat",
    "arches": arches,
}
hermeto_lock_path.write_text(json.dumps(hermeto_lock, indent=2) + "\n", encoding="utf-8")
rpm_map_path.write_text(json.dumps(rpm_map, indent=2) + "\n", encoding="utf-8")
local_map_path.write_text(json.dumps(list(local_entries.values()), indent=2) + "\n", encoding="utf-8")
PYEOF
}

map_hermeto_rpms_to_osbuild_store() {
  map_locked_rpms_to_osbuild_store "$1" "$2" "$3" "${4:-false}" false
}

map_local_rpms_to_osbuild_store() {
  map_locked_rpms_to_osbuild_store "$1" "" "$2" "${3:-false}" true
}

map_locked_rpms_to_osbuild_store() {
  local rpm_map="$1" hermeto_output="$2" store="$3" verify_only="$4" local_rpms="$5"

  python3 - "$rpm_map" "$hermeto_output" "$store" "$verify_only" "$local_rpms" <<'PYEOF'
import hashlib
import json
import os
import pathlib
import shutil
import sys
import urllib.parse

rpm_map_path, output_path, store_path = map(pathlib.Path, sys.argv[1:4])
verify_only = sys.argv[4] == "true"
local_rpms = sys.argv[5] == "true"
entries = json.loads(rpm_map_path.read_text(encoding="utf-8"))
store_path.mkdir(parents=True, exist_ok=True)

for entry in entries:
    if verify_only:
        source = store_path / entry["checksum"]
    elif local_rpms:
        parsed = urllib.parse.urlsplit(entry["url"])
        source = pathlib.Path(urllib.parse.unquote(parsed.path)).resolve()
        if parsed.scheme != "file" or parsed.netloc or not source.is_relative_to("/extra-repos/oci-repo"):
            raise SystemExit(f"RPM is outside OCI repository mount: {entry['url']}")
    else:
        source = output_path / entry["path"]
    if not source.is_file():
        raise SystemExit(f"locked source is missing or not a regular file: {entry['url']} at {source}")

    algorithm, expected = entry["checksum"].split(":", 1)
    if algorithm not in {"sha256", "sha384", "sha512"}:
        raise SystemExit(f"unsupported checksum algorithm {algorithm}")
    digest = hashlib.new(algorithm)
    with source.open("rb") as rpm:
        for chunk in iter(lambda: rpm.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit(f"checksum mismatch while mapping {entry['url']}")

    if verify_only:
        continue

    destination = store_path / entry["checksum"]
    temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
    try:
        if local_rpms:
            shutil.copyfile(source, temporary)
        else:
            os.link(source, temporary)
    except OSError:
        shutil.copyfile(source, temporary)
    os.replace(temporary, destination)

print(len({entry["checksum"] for entry in entries}))
PYEOF
}

append_local_rpms_to_sbom() {
  local local_map="$1" bom="$2" repo_image="$3"

  python3 - "$local_map" "$bom" "$repo_image" <<'PYEOF'
import json
import pathlib
import sys
import urllib.parse

map_path, bom_path = map(pathlib.Path, sys.argv[1:3])
repo_image = sys.argv[3]
entries = json.loads(map_path.read_text(encoding="utf-8"))
if bom_path.exists():
    bom = json.loads(bom_path.read_text(encoding="utf-8"))
else:
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}

components = bom.setdefault("components", [])
seen = {component.get("purl") for component in components}
for entry in entries:
    if entry["kind"] == "module_metadata":
        continue
    if not repo_image:
        raise SystemExit("OCI repository image reference is required for local RPM SBOM provenance")
    epoch, separator, version = entry["evr"].partition(":")
    if not separator:
        epoch, version = "", entry["evr"]
    qualifiers = {
        "arch": "src" if entry["kind"] == "source" else entry["arch"],
        "download_url": entry["url"],
        "checksum": entry["checksum"],
    }
    if epoch:
        qualifiers["epoch"] = epoch
    quote = lambda value: urllib.parse.quote(value, safe="")
    purl = f"pkg:rpm/{quote(entry['name'])}@{quote(version)}?" + "&".join(
        f"{key}={quote(value)}" for key, value in sorted(qualifiers.items())
    )
    if purl in seen:
        continue
    seen.add(purl)
    components.append({
        "type": "library", "name": entry["name"], "version": version.rsplit("-", 1)[0],
        "purl": purl, "bom-ref": purl,
        "properties": [
            {"name": "ado:oci-repo:image", "value": repo_image},
        ],
    })
bom_path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
PYEOF
}

prepare_locked_rpms_with_hermeto() {
  local aib_lock="$1" build_dir="$2" workspace_path="$3" restore_sources_ref="$4"
  local restored_sbom="$build_dir/osbuild_store/hermeto-rpm-bom.json"
  local require_locked=false
  if [ "${SECURE_BUILD:-false}" = "true" ] || [ "${REPRODUCIBLE:-false}" = "true" ]; then
    require_locked=true
    [ -s "$aib_lock" ] || fail "secure/reproducible build requires a lockfile"
    aib_lock_has_supported_sources "$aib_lock" \
      || fail "secure dependency preparation found unsupported AIB lockfile sections"
  fi
  rm -f "$workspace_path/hermeto-rpm-bom.json"
  if [ ! -f "$aib_lock" ]; then
    if [ -n "$restore_sources_ref" ] && [ -f "$restored_sbom" ]; then
      cp "$restored_sbom" "$workspace_path/hermeto-rpm-bom.json"
    elif [ -z "$restore_sources_ref" ]; then
      rm -f "$restored_sbom"
    fi
    return 0
  fi

  if [ "${HERMETO_PREFETCH:-false}" != "true" ]; then
    if [ -n "$restore_sources_ref" ] && [ -f "$restored_sbom" ]; then
      cp "$restored_sbom" "$workspace_path/hermeto-rpm-bom.json"
    else
      rm -f "$restored_sbom"
    fi
    echo "Hermeto RPM prefetch disabled; using AIB source handling"
    return 0
  fi

  aib_lock_has_supported_sources "$aib_lock" \
    || fail "Hermeto prefetch found an invalid or unsupported AIB lockfile"
  if aib_lock_is_rpm_only "$aib_lock" 2>/dev/null; then
    command -v unshare >/dev/null 2>&1 || fail "RPM-only locked builds require unshare for network isolation"
    # shellcheck disable=SC2034 # Consumed by the concatenated build_image.sh.
    AIB_BUILD_NETWORK_DISABLED=true
  elif [ "$require_locked" = "true" ]; then
    command -v unshare >/dev/null 2>&1 || fail "secure locked builds require unshare for network isolation"
    # shellcheck disable=SC2034 # Consumed by the concatenated build_image.sh.
    AIB_BUILD_NETWORK_DISABLED=true
    # shellcheck disable=SC2034 # Consumed by the concatenated build_image.sh.
    AIB_SOURCE_PREFETCH_REQUIRED=true
  else
    echo "WARNING: AIB lockfile contains non-RPM dependencies; AIB build network remains enabled"
  fi

  if [ -n "$restore_sources_ref" ]; then
    if [ "$require_locked" = "true" ] && aib_lock_has_rpms "$aib_lock"; then
      local verify_dir
      verify_dir=$(mktemp -d "$build_dir/verify-restored.XXXXXX")
      convert_aib_lock_to_hermeto "$aib_lock" "$verify_dir/rpms.lock.yaml" "$verify_dir/map.json" "$verify_dir/local-map.json" \
        || fail "failed to validate restored lockfile"
      map_hermeto_rpms_to_osbuild_store "$verify_dir/map.json" "" "$build_dir/osbuild_store/sources/org.osbuild.files" true \
        || fail "restored sources do not match the lockfile"
      map_local_rpms_to_osbuild_store "$verify_dir/local-map.json" "$build_dir/osbuild_store/sources/org.osbuild.files" true \
        || fail "restored local sources do not match the lockfile"
      rm -rf "$verify_dir"
      [ -s "$restored_sbom" ] || fail "restored Hermeto SBOM is missing"
    fi
    if [ -f "$restored_sbom" ]; then
      cp "$restored_sbom" "$workspace_path/hermeto-rpm-bom.json"
    fi
    echo "Using restored osbuild sources; skipping Hermeto RPM fetch"
    return 0
  fi

  if ! aib_lock_has_rpms "$aib_lock"; then
    rm -f "$restored_sbom"
    echo "AIB lockfile contains no RPMs; skipping Hermeto"
    return 0
  fi

  command -v python3 >/dev/null 2>&1 || fail "Hermeto RPM prefetch requires python3"

  local input_dir="$build_dir/hermeto-input"
  local output_dir="$build_dir/hermeto-output"
  local hermeto_lock="$input_dir/rpms.lock.yaml"
  local rpm_map="$input_dir/aib-rpm-map.json"
  local local_map="$input_dir/aib-local-rpm-map.json"
  local source_store="$build_dir/osbuild_store/sources/org.osbuild.files"
  rm -rf "$input_dir" "$output_dir"
  mkdir -p "$input_dir" "$output_dir"
  chmod 0755 "$input_dir"
  chmod 0777 "$output_dir"

  convert_aib_lock_to_hermeto "$aib_lock" "$hermeto_lock" "$rpm_map" "$local_map" \
    || fail "failed to convert AIB lockfile for Hermeto"

  local mapped_count=0 local_count
  if python3 -c 'import json, sys; sys.exit(not json.load(open(sys.argv[1])))' "$rpm_map"; then
    command -v podman >/dev/null 2>&1 || fail "Hermeto RPM prefetch requires podman"
    echo "Fetching locked RPMs with Hermeto image $HERMETO_IMAGE"
    local -a certificate_args=()
    if [ -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ]; then
      certificate_args=(
        -e SSL_CERT_FILE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
        -v /etc/pki/ca-trust:/etc/pki/ca-trust:ro
      )
    fi
    podman run --rm --network=host \
      "${certificate_args[@]}" \
      -v "$input_dir:/source:ro,Z" \
      -v "$output_dir:/output:Z" \
      "$HERMETO_IMAGE" \
      fetch-deps --source /source --output /output rpm \
      || fail "Hermeto RPM fetch failed"

    mapped_count=$(map_hermeto_rpms_to_osbuild_store "$rpm_map" "$output_dir" "$source_store") \
      || fail "failed to map Hermeto RPMs into the osbuild source store"
    [ -s "$output_dir/bom.json" ] || fail "Hermeto did not produce bom.json"
  else
    echo "AIB lockfile contains only local RPMs; skipping Hermeto"
  fi
  local_count=$(map_local_rpms_to_osbuild_store "$local_map" "$source_store") \
    || fail "failed to map local RPMs into the osbuild source store"
  append_local_rpms_to_sbom "$local_map" "$output_dir/bom.json" "${OCI_REPO_IMAGE:-}" \
    || fail "failed to append local RPMs to the SBOM"
  cp "$output_dir/bom.json" "$restored_sbom"
  cp "$output_dir/bom.json" "$workspace_path/hermeto-rpm-bom.json"
  rm -rf "$input_dir" "$output_dir"
  echo "Mapped $((mapped_count + local_count)) verified RPM and metadata artifacts into the osbuild source store"
}
