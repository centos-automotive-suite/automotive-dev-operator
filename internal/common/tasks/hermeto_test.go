package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type hermetoRPMMapEntry struct {
	Checksum string `json:"checksum"`
	Path     string `json:"path"`
	URL      string `json:"url"`
}

func runHermetoFunction(t *testing.T, function string, args ...string) []byte {
	t.Helper()
	return runHermetoScript(t, `"$@"`, append([]string{function}, args...)...)
}

func runHermetoScript(t *testing.T, scriptBody string, args ...string) []byte {
	t.Helper()
	script, err := filepath.Abs("scripts/hermeto.sh")
	if err != nil {
		t.Fatal(err)
	}
	command := `set -e; source "$1"; shift; ` + scriptBody
	cmd := exec.Command("bash", "-c", command, "bash", script)
	cmd.Args = append(cmd.Args, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Hermeto script failed: %v\n%s", err, out)
	}
	return out
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestConvertAIBLockToHermetoDeduplicatesRPMs(t *testing.T) {
	dir := t.TempDir()
	aibLock := filepath.Join(dir, "aib.lock")
	hermetoLock := filepath.Join(dir, "rpms.lock.yaml")
	rpmMap := filepath.Join(dir, "rpm-map.json")
	checksum := "sha256:" + strings.Repeat("a", 64)
	writeJSONFile(t, aibLock, map[string]any{
		"version": 1,
		"depsolves": map[string]any{
			"second": map[string]any{
				"request": map[string]any{"architecture": "x86_64"},
				"packages": []any{
					map[string]any{"name": "demo", "evr": "1-1", "arch": "x86_64", "url": "https://repo.example/demo.rpm", "checksum": checksum},
				},
			},
			"first": map[string]any{
				"request": map[string]any{"architecture": "x86_64"},
				"packages": []any{
					map[string]any{"name": "demo", "evr": "1-1", "arch": "x86_64", "url": "https://repo.example/demo.rpm", "checksum": checksum},
				},
			},
		},
	})

	runHermetoFunction(t, "convert_aib_lock_to_hermeto", aibLock, hermetoLock, rpmMap)

	var lock struct {
		LockfileVersion int    `json:"lockfileVersion"`
		LockfileVendor  string `json:"lockfileVendor"`
		Arches          []struct {
			Arch     string `json:"arch"`
			Packages []struct {
				RepoID   string `json:"repoid"`
				URL      string `json:"url"`
				Checksum string `json:"checksum"`
			} `json:"packages"`
		} `json:"arches"`
	}
	data, err := os.ReadFile(hermetoLock)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.LockfileVersion != 1 || lock.LockfileVendor != "redhat" {
		t.Fatalf("unexpected Hermeto lockfile header: %+v", lock)
	}
	if len(lock.Arches) != 1 || lock.Arches[0].Arch != "x86_64" || len(lock.Arches[0].Packages) != 1 {
		t.Fatalf("RPMs were not deduplicated by architecture and checksum: %+v", lock.Arches)
	}
	packageEntry := lock.Arches[0].Packages[0]
	// Hermeto 0.51.0 treats this namespace as synthetic and includes download_url
	// instead of a fictitious repository_id in the component PURL.
	if !strings.HasPrefix(packageEntry.RepoID, "hermeto-") {
		t.Fatalf("synthetic repository ID would replace SBOM provenance: %q", packageEntry.RepoID)
	}
	var entries []hermetoRPMMapEntry
	mapData, err := os.ReadFile(rpmMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mapData, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "deps/rpm/x86_64/"+packageEntry.RepoID+"/demo.rpm" {
		t.Fatalf("store mapper does not match fetcher paths: %+v", entries)
	}
	if packageEntry.URL != "https://repo.example/demo.rpm" || packageEntry.Checksum != checksum {
		t.Fatalf("URL or checksum changed during conversion: %+v", packageEntry)
	}
}

func TestMapHermetoRPMsToOsbuildStore(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	store := filepath.Join(dir, "store")
	rpmMap := filepath.Join(dir, "rpm-map.json")
	content := []byte("verified rpm content")
	digest := sha256.Sum256(content)
	checksum := "sha256:" + hex.EncodeToString(digest[:])
	relativePath := filepath.Join("deps", "rpm", "x86_64", "aib-test", "demo.rpm")
	rpmPath := filepath.Join(output, relativePath)
	if err := os.MkdirAll(filepath.Dir(rpmPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rpmPath, content, 0600); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, rpmMap, []hermetoRPMMapEntry{{
		Checksum: checksum,
		Path:     relativePath,
		URL:      "https://repo.example/demo.rpm",
	}})

	out := runHermetoFunction(t, "map_hermeto_rpms_to_osbuild_store", rpmMap, output, store)
	if strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("mapped count = %q, want 1", out)
	}
	mapped, err := os.ReadFile(filepath.Join(store, checksum))
	if err != nil {
		t.Fatal(err)
	}
	if string(mapped) != string(content) {
		t.Fatalf("mapped RPM content changed: %q", mapped)
	}
}

func TestAIBLockRPMOnlyDetection(t *testing.T) {
	dir := t.TempDir()
	rpmOnly := filepath.Join(dir, "rpm-only.lock")
	mixed := filepath.Join(dir, "mixed.lock")
	packages := []any{map[string]any{"url": "https://repo.example/demo.rpm"}}
	writeJSONFile(t, rpmOnly, map[string]any{"version": 1, "depsolves": map[string]any{"one": map[string]any{"packages": packages}}})
	writeJSONFile(t, mixed, map[string]any{
		"version":    1,
		"depsolves":  map[string]any{"one": map[string]any{"packages": packages}},
		"containers": map[string]any{"image": map[string]any{}},
	})

	runHermetoFunction(t, "aib_lock_is_rpm_only", rpmOnly)
	script, err := filepath.Abs("scripts/hermeto.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; aib_lock_is_rpm_only "$2"`, "bash", script, mixed)
	if err := cmd.Run(); err == nil {
		t.Fatal("mixed lockfile was incorrectly classified as RPM-only")
	}
}

func TestHermetoPrefetchClearsStaleSBOMWithoutLockfile(t *testing.T) {
	dir := t.TempDir()
	buildDir := filepath.Join(dir, "build")
	workspace := filepath.Join(dir, "workspace")
	buildSBOM := filepath.Join(buildDir, "osbuild_store", "hermeto-rpm-bom.json")
	workspaceSBOM := filepath.Join(workspace, "hermeto-rpm-bom.json")
	for _, path := range []string{buildSBOM, workspaceSBOM} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	runHermetoFunction(
		t,
		"prepare_locked_rpms_with_hermeto",
		filepath.Join(dir, "missing.lock"),
		buildDir,
		workspace,
		"",
	)
	for _, path := range []string{buildSBOM, workspaceSBOM} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale SBOM remains at %s: %v", path, err)
		}
	}
}

func TestHermetoPrefetchSkipsLockfileWithoutRPMs(t *testing.T) {
	t.Setenv("HERMETO_PREFETCH", "true")
	dir := t.TempDir()
	lockfile := filepath.Join(dir, "aib.lock")
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, lockfile, map[string]any{
		"version":    1,
		"containers": map[string]any{"image": map[string]any{"digest": "sha256:test"}},
	})

	out := runHermetoFunction(
		t,
		"prepare_locked_rpms_with_hermeto",
		lockfile,
		filepath.Join(dir, "build"),
		workspace,
		"",
	)
	if !strings.Contains(string(out), "contains no RPMs; skipping Hermeto") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestRunAIBCommandDisablesNetworkForRPMLock(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "run_aib_command() {")
	if !ok {
		t.Fatal("run_aib_command function missing")
	}
	body, _, ok := strings.Cut(rest, "\nannotate_oci_image()")
	if !ok {
		t.Fatal("run_aib_command function terminator missing")
	}

	dir := t.TempDir()
	unshare := filepath.Join(dir, "unshare")
	if err := os.WriteFile(unshare, []byte("#!/bin/sh\nprintf 'UNSHARE'; printf ' <%s>' \"$@\"; printf '\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	script := `
write_result() { :; }
emit_progress() { :; }
aib() { printf 'AIB'; printf ' <%s>' "$@"; printf '\n'; }
AIB_BUILD_NETWORK_DISABLED=true
STEP_BUILD=1
PROGRESS_TOTAL=1
run_aib_command() {` + body + `
run_aib_command "locked build" aib build --lockfile /input/aib.lock
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("network-isolated AIB command failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"UNSHARE <--net> <--> <aib> <build> <--lockfile> </input/aib.lock>",
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("network-isolated command output missing %q:\n%s", want, out)
		}
	}
}

func TestHermetoPrefetchRequiresOptIn(t *testing.T) {
	for _, enabled := range []string{"", "false"} {
		t.Run("prefetch="+enabled, func(t *testing.T) {
			t.Setenv("HERMETO_PREFETCH", enabled)
			dir := t.TempDir()
			lock := filepath.Join(dir, "aib.lock")
			writeJSONFile(t, lock, map[string]any{"version": 1, "depsolves": map[string]any{
				"one": map[string]any{"packages": []any{map[string]any{"url": "file:///repo/demo.rpm", "secrets": "org.osbuild.rhsm"}}},
			}})
			out := runHermetoScript(t, `
AIB_BUILD_NETWORK_DISABLED=false
python3() { echo "unexpected lockfile inspection" >&2; exit 91; }
podman() { echo "unexpected container execution" >&2; exit 92; }
prepare_locked_rpms_with_hermeto "$1" "$2" "$3" ""
[ "$AIB_BUILD_NETWORK_DISABLED" = false ]
`, lock, filepath.Join(dir, "build"), dir)
			if !strings.Contains(string(out), "Hermeto RPM prefetch disabled") {
				t.Fatalf("unexpected output: %s", out)
			}
		})
	}
}

func TestHermetoPrefetchOptInIsolatesRestoredRPMBuild(t *testing.T) {
	t.Setenv("HERMETO_PREFETCH", "true")
	dir := t.TempDir()
	lock := filepath.Join(dir, "aib.lock")
	writeJSONFile(t, lock, map[string]any{"version": 1, "depsolves": map[string]any{
		"one": map[string]any{"packages": []any{map[string]any{"url": "https://repo.example/demo.rpm"}}},
	}})
	runHermetoScript(t, `
AIB_BUILD_NETWORK_DISABLED=false
unshare() { :; }
podman() { echo "restored sources must not be fetched" >&2; exit 92; }
prepare_locked_rpms_with_hermeto "$1" "$2" "$3" "registry.example/prior-build"
[ "$AIB_BUILD_NETWORK_DISABLED" = true ]
`, lock, filepath.Join(dir, "build"), dir)
}

func TestHermetoSourceAndModuleArtifacts(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "aib.lock")
	convertedPath := filepath.Join(dir, "rpms.lock.yaml")
	mapPath := filepath.Join(dir, "map.json")
	contents := map[string][]byte{
		"packages":        []byte("binary RPM"),
		"source":          []byte("source RPM"),
		"module_metadata": []byte("module metadata"),
	}
	filenames := map[string]string{"packages": "demo.rpm", "source": "demo.src.rpm", "module_metadata": "modules.yaml.gz"}
	depsolve := map[string]any{"request": map[string]any{"architecture": "aarch64"}}
	checksums := map[string]string{}
	for kind, content := range contents {
		digest := sha256.Sum256(content)
		checksums[kind] = "sha256:" + hex.EncodeToString(digest[:])
		depsolve[kind] = []any{map[string]any{
			"url": "https://repo.example/" + filenames[kind], "checksum": checksums[kind], "repoid": "appstream",
		}}
	}
	writeJSONFile(t, lockPath, map[string]any{"version": 1, "depsolves": map[string]any{"one": depsolve, "duplicate": depsolve}})
	runHermetoFunction(t, "convert_aib_lock_to_hermeto", lockPath, convertedPath, mapPath)
	var converted struct {
		Arches []struct {
			Packages []map[string]any `json:"packages"`
			Source   []map[string]any `json:"source"`
			Modules  []map[string]any `json:"module_metadata"`
		} `json:"arches"`
	}
	data, err := os.ReadFile(convertedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &converted); err != nil {
		t.Fatal(err)
	}
	if len(converted.Arches) != 1 {
		t.Fatalf("unexpected architectures: %s", data)
	}
	arch := converted.Arches[0]
	for kind, entries := range map[string][]map[string]any{"packages": arch.Packages, "source": arch.Source, "module_metadata": arch.Modules} {
		if len(entries) != 1 || entries[0]["checksum"] != checksums[kind] || entries[0]["repoid"] != "appstream" {
			t.Fatalf("%s was not preserved and deduplicated: %s", kind, data)
		}
	}
	output := filepath.Join(dir, "output")
	for kind, filename := range filenames {
		path := filepath.Join(output, "deps/rpm/aarch64/appstream", filename)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents[kind], 0600); err != nil {
			t.Fatal(err)
		}
	}
	store := filepath.Join(dir, "store")
	runHermetoFunction(t, "map_hermeto_rpms_to_osbuild_store", mapPath, output, store)
	for kind, checksum := range checksums {
		data, err := os.ReadFile(filepath.Join(store, checksum))
		if err != nil || string(data) != string(contents[kind]) {
			t.Fatalf("%s artifact not preserved: %v", kind, err)
		}
	}
}

func TestHermetoSourceOnlyLock(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "aib.lock")
	writeJSONFile(t, lock, map[string]any{"version": 1, "depsolves": map[string]any{"one": map[string]any{
		"request": map[string]any{"architecture": "aarch64"},
		"source":  []any{map[string]any{"url": "https://repo.example/demo.src.rpm", "checksum": "sha256:" + strings.Repeat("a", 64)}},
	}}})
	runHermetoFunction(t, "aib_lock_has_rpms", lock)
	runHermetoFunction(t, "aib_lock_is_rpm_only", lock)
	runHermetoFunction(t, "convert_aib_lock_to_hermeto", lock, filepath.Join(dir, "converted"), filepath.Join(dir, "map"))
}

func TestHermetoRejectsInvalidSupplementalArtifacts(t *testing.T) {
	checksum := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, kind, want string
		entries          []any
	}{
		{"missing checksum", "source", "no usable checksum", []any{map[string]any{"url": "https://repo.example/demo.src.rpm"}}},
		{"missing module repository", "module_metadata", "requires repoid", []any{map[string]any{"url": "https://repo.example/modules.yaml.gz", "checksum": checksum}}},
		{"repository traversal", "source", "Invalid repository ID", []any{map[string]any{"url": "https://repo.example/demo.src.rpm", "checksum": checksum, "repoid": "../../escape"}}},
		{"wrong source type", "source", "Source RPM URL must end", []any{map[string]any{"url": "https://repo.example/demo.rpm", "checksum": checksum}}},
		{"metadata filename collision", "module_metadata", "Conflicting downloads target", []any{
			map[string]any{"url": "https://repo.example/a/modules.yaml.gz", "checksum": checksum, "repoid": "appstream"},
			map[string]any{"url": "https://repo.example/b/modules.yaml.gz", "checksum": "sha256:" + strings.Repeat("b", 64), "repoid": "appstream"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lock := filepath.Join(dir, "aib.lock")
			writeJSONFile(t, lock, map[string]any{"version": 1, "depsolves": map[string]any{"one": map[string]any{
				"request":  map[string]any{"architecture": "aarch64"},
				"packages": []any{map[string]any{"url": "https://repo.example/demo.rpm", "checksum": checksum}}, tc.kind: tc.entries,
			}}})
			out := runHermetoScript(t, `if convert_aib_lock_to_hermeto "$1" "$2" "$3"; then exit 99; fi`, lock, filepath.Join(dir, "converted"), filepath.Join(dir, "map"))
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("expected %q, got %s", tc.want, out)
			}
		})
	}
}

func TestSecureHermetoPreparation(t *testing.T) {
	for _, scenario := range []string{"fetch", "fetch failure", "missing SBOM", "mixed", "missing lock", "restore", "corrupt restore", "missing restore blob", "missing restore SBOM"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			build := filepath.Join(dir, "build")
			store := filepath.Join(build, "osbuild_store", "sources", "org.osbuild.files")
			if err := os.MkdirAll(store, 0700); err != nil {
				t.Fatal(err)
			}
			bytes := []byte("rpm bytes")
			hash := sha256.Sum256(bytes)
			checksum := "sha256:" + hex.EncodeToString(hash[:])
			lock := filepath.Join(dir, "aib.lock")
			input := map[string]any{"version": 1, "depsolves": map[string]any{"one": map[string]any{"request": map[string]any{"architecture": "aarch64"}, "packages": []any{map[string]any{"url": "https://repo.example/demo.rpm", "repoid": "baseos", "checksum": checksum}}}}}
			if scenario == "mixed" {
				input["containers"] = map[string]any{"example": "sha256:abc"}
			}
			if scenario != "missing lock" {
				writeJSONFile(t, lock, input)
			}
			restore := ""
			if strings.Contains(scenario, "restore") {
				restore = "registry.example/prior@sha256:abc"
				if scenario != "missing restore blob" {
					if scenario == "corrupt restore" {
						bytes = []byte("tampered")
					}
					if err := os.WriteFile(filepath.Join(store, checksum), bytes, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario != "missing restore SBOM" {
					writeJSONFile(t, filepath.Join(build, "osbuild_store", "hermeto-rpm-bom.json"), map[string]any{"bomFormat": "CycloneDX"})
				}
			}
			scriptPath, err := filepath.Abs("scripts/hermeto.sh")
			if err != nil {
				t.Fatal(err)
			}
			script := `set -e
source "$1"
fail() { echo "ERROR: $*"; exit 1; }
unshare() { :; }
podman() {
 echo FETCH
 [ "$SCENARIO" != 'fetch failure' ] || return 42
 [ -z "$RESTORE" ] || exit 99
 mkdir -p "$BUILD/hermeto-output/deps/rpm/aarch64/baseos"
 printf 'rpm bytes' > "$BUILD/hermeto-output/deps/rpm/aarch64/baseos/demo.rpm"
 if [ "$SCENARIO" != 'missing SBOM' ]; then printf '{"bomFormat":"CycloneDX"}' > "$BUILD/hermeto-output/bom.json"; fi
}
AIB_BUILD_NETWORK_DISABLED=false
prepare_locked_rpms_with_hermeto "$LOCK" "$BUILD" "$WORKSPACE" "$RESTORE"
[ "$AIB_BUILD_NETWORK_DISABLED" = true ]
echo PREPARED
`
			cmd := exec.Command("bash", "-c", script, "bash", scriptPath)
			cmd.Env = append(os.Environ(), "SECURE_BUILD=true", "REPRODUCIBLE=false", "HERMETO_PREFETCH=false", "HERMETO_IMAGE=example/hermeto@sha256:abc", "SCENARIO="+scenario, "LOCK="+lock, "BUILD="+build, "WORKSPACE="+dir, "RESTORE="+restore)
			out, err := cmd.CombinedOutput()
			wantSuccess := scenario == "fetch" || scenario == "restore"
			if (err == nil) != wantSuccess {
				t.Fatalf("err=%v output=%s", err, out)
			}
			if strings.Contains(string(out), "PREPARED") != wantSuccess {
				t.Fatalf("unexpected continuation: %s", out)
			}
			if restore != "" && strings.Contains(string(out), "FETCH") {
				t.Fatalf("restore fetched: %s", out)
			}
		})
	}
}
