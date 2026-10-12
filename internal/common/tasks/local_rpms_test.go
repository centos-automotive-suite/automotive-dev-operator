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

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
)

func localRPMTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func localRPMChecksum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func localRPMLock(t *testing.T, path string, urls ...string) {
	t.Helper()
	entries := make([]map[string]any, 0, len(urls))
	for _, url := range urls {
		name, content := "local", "local rpm"
		if strings.HasPrefix(url, "https:") {
			name, content = "remote", "remote rpm"
		}
		entries = append(entries, map[string]any{"url": url, "checksum": localRPMChecksum(content), "name": name, "evr": "2:1.0-3", "arch": "noarch", "repoid": "test"})
	}
	writeJSONFile(t, path, map[string]any{"version": 1, "depsolves": map[string]any{"one": map[string]any{"request": map[string]any{"architecture": "aarch64"}, "packages": entries}}})
}

// Substitute the container mount in a private script copy so tests need no host root access.
func localRPMScript(t *testing.T, dir, mount string) string {
	t.Helper()
	data, err := os.ReadFile("scripts/hermeto.sh")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hermeto.sh")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), "/extra-repos/oci-repo", mount)), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConvertAIBLockSplitsLocalRPMs(t *testing.T) {
	dir := localRPMTempDir(t)
	lock, remote, local := filepath.Join(dir, "lock"), filepath.Join(dir, "remote"), filepath.Join(dir, "local")
	localRPMLock(t, lock, "file:///extra-repos/oci-repo/local.rpm", "https://repo.example/remote.rpm")
	runHermetoFunction(t, "convert_aib_lock_to_hermeto", lock, filepath.Join(dir, "converted"), remote, local)
	converted, err := os.ReadFile(filepath.Join(dir, "converted"))
	if err != nil {
		t.Fatal(err)
	}
	var hermeto struct {
		Arches []struct{ Packages []hermetoRPMMapEntry }
	}
	if err := json.Unmarshal(converted, &hermeto); err != nil {
		t.Fatal(err)
	}
	if len(hermeto.Arches) != 1 || len(hermeto.Arches[0].Packages) != 1 || hermeto.Arches[0].Packages[0].URL != "https://repo.example/remote.rpm" {
		t.Fatalf("Hermeto lock includes local RPMs or lost remote RPMs: %s", converted)
	}
	for path, want := range map[string]string{remote: "https://repo.example/remote.rpm", local: "file:///extra-repos/oci-repo/local.rpm"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var entries []map[string]any
		if err := json.Unmarshal(data, &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0]["url"] != want {
			t.Fatalf("incorrect split: %s", data)
		}
		if path == local && (entries[0]["name"] != "local" || entries[0]["evr"] != "2:1.0-3" || entries[0]["arch"] != "noarch") {
			t.Fatalf("missing RPM identity: %s", data)
		}
	}
}

func TestConvertAIBLockRejectsOutsideLocalPaths(t *testing.T) {
	for _, url := range []string{"file:///tmp/local.rpm", "file:///extra-repos/oci-repo-other/local.rpm", "file:///extra-repos/oci-repo/../local.rpm", "file:///extra-repos/oci-repo/%2e%2e/local.rpm", "file://host/extra-repos/oci-repo/local.rpm"} {
		t.Run(url, func(t *testing.T) {
			dir := localRPMTempDir(t)
			lock := filepath.Join(dir, "lock")
			localRPMLock(t, lock, url)
			script, err := filepath.Abs("scripts/hermeto.sh")
			if err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("bash", "-c", `source "$1"; convert_aib_lock_to_hermeto "$2" "$3" "$4" "$5"`, "bash", script, lock, filepath.Join(dir, "converted"), filepath.Join(dir, "remote"), filepath.Join(dir, "local")).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "outside OCI repository mount") {
				t.Fatalf("err=%v output=%s", err, out)
			}
		})
	}
}

func TestMapLocalRPMsSecurity(t *testing.T) {
	for _, scenario := range []string{"copy", "symlink escape", "checksum mismatch", "directory"} {
		t.Run(scenario, func(t *testing.T) {
			dir := localRPMTempDir(t)
			mount := filepath.Join(dir, "mount")
			store := filepath.Join(dir, "store")
			if err := os.Mkdir(mount, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(mount, "local.rpm")
			switch scenario {
			case "symlink escape":
				outside := filepath.Join(dir, "outside.rpm")
				if err := os.WriteFile(outside, []byte("local rpm"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, source); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				content := "local rpm"
				if scenario == "checksum mismatch" {
					content = "tampered"
				}
				if err := os.WriteFile(source, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			rpmMap := filepath.Join(dir, "local-map")
			writeJSONFile(t, rpmMap, []map[string]any{{"url": "file://" + source, "checksum": localRPMChecksum("local rpm")}})
			out, err := exec.Command("bash", "-c", `source "$1"; map_local_rpms_to_osbuild_store "$2" "$3"`, "bash", localRPMScript(t, dir, mount), rpmMap, store).CombinedOutput()
			if scenario != "copy" {
				want := "regular file"
				if scenario == "symlink escape" {
					want = "outside OCI repository mount"
				}
				if scenario == "checksum mismatch" {
					want = "checksum mismatch"
				}
				if err == nil || !strings.Contains(string(out), want) {
					t.Fatalf("err=%v output=%s", err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("err=%v output=%s", err, out)
			}
			src, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			dst, err := os.Stat(filepath.Join(store, localRPMChecksum("local rpm")))
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(src, dst) {
				t.Fatal("local RPM was hard linked")
			}
		})
	}
}

func assertLocalRPMSBOM(t *testing.T, data []byte, mixed bool, ref string) {
	t.Helper()
	var bom struct {
		Components []struct {
			Type, Name, Version, Purl string
			Properties                []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	wantCount := 1
	if mixed {
		wantCount = 2
	}
	if len(bom.Components) != wantCount {
		t.Fatalf("SBOM: %s", data)
	}
	found := false
	for _, c := range bom.Components {
		if c.Name != "local" {
			continue
		}
		found = true
		if c.Type != "library" || c.Version != "1.0" || !strings.Contains(c.Purl, "pkg:rpm/local@1.0-3?") || !strings.Contains(c.Purl, "arch=noarch") || !strings.Contains(c.Purl, "epoch=2") {
			t.Fatalf("invalid local component: %s", data)
		}
		hasRef := false
		for _, p := range c.Properties {
			if p.Name == "ado:oci-repo:image" && p.Value == ref {
				hasRef = true
			}
		}
		if !hasRef {
			t.Fatalf("missing OCI provenance: %s", data)
		}
	}
	if !found {
		t.Fatalf("missing local component: %s", data)
	}
}

func TestPrepareLocalRPMsAndRestore(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "local only"
		if mixed {
			name = "mixed"
		}
		t.Run(name, func(t *testing.T) {
			dir := localRPMTempDir(t)
			mount := filepath.Join(dir, "mount")
			build := filepath.Join(dir, "build")
			lock := filepath.Join(dir, "lock")
			if err := os.Mkdir(mount, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(mount, "local.rpm")
			if err := os.WriteFile(source, []byte("local rpm"), 0600); err != nil {
				t.Fatal(err)
			}
			urls := []string{"file://" + source}
			if mixed {
				urls = append(urls, "https://repo.example/remote.rpm")
			}
			localRPMLock(t, lock, urls...)
			script := localRPMScript(t, dir, mount)
			ref := "quay.io/org/rpms:v1@sha256:" + strings.Repeat("a", 64)
			body := `set -e; source "$1"
fail() { echo "$*" >&2; exit 1; }
unshare() { :; }
podman() {
 echo FETCH
 mkdir -p "$BUILD/hermeto-output/deps/rpm/aarch64/test"
 printf 'remote rpm' > "$BUILD/hermeto-output/deps/rpm/aarch64/test/remote.rpm"
 printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"remote","version":"1.0-3","purl":"pkg:rpm/remote@1.0-3?arch=noarch&epoch=2"}]}' > "$BUILD/hermeto-output/bom.json"
}
prepare_locked_rpms_with_hermeto "$LOCK" "$BUILD" "$WORKSPACE" "$RESTORE"
`
			run := func(restore string) []byte {
				t.Helper()
				cmd := exec.Command("bash", "-c", body, "bash", script)
				cmd.Env = append(os.Environ(), "SECURE_BUILD=true", "HERMETO_PREFETCH=true", "REPRODUCIBLE=false", "HERMETO_IMAGE=example/hermeto", "OCI_REPO_IMAGE="+ref, "LOCK="+lock, "BUILD="+build, "WORKSPACE="+dir, "RESTORE="+restore)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("err=%v output=%s", err, out)
				}
				return out
			}
			out := run("")
			if strings.Contains(string(out), "FETCH") != mixed {
				t.Fatalf("incorrect Hermeto invocation: %s", out)
			}
			for _, content := range []string{"local rpm", "remote rpm"} {
				if content == "remote rpm" && !mixed {
					continue
				}
				data, err := os.ReadFile(filepath.Join(build, "osbuild_store/sources/org.osbuild.files", localRPMChecksum(content)))
				if err != nil || string(data) != content {
					t.Fatalf("store content=%s err=%v", data, err)
				}
			}
			data, err := os.ReadFile(filepath.Join(dir, "hermeto-rpm-bom.json"))
			if err != nil {
				t.Fatal(err)
			}
			assertLocalRPMSBOM(t, data, mixed, ref)
			if err := os.RemoveAll(mount); err != nil {
				t.Fatal(err)
			}
			if out := run("registry.example/prior"); strings.Contains(string(out), "FETCH") {
				t.Fatalf("restore fetched: %s", out)
			}
			restored, err := os.ReadFile(filepath.Join(dir, "hermeto-rpm-bom.json"))
			if err != nil || string(restored) != string(data) {
				t.Fatalf("restored SBOM changed: %v", err)
			}
			if err := os.WriteFile(filepath.Join(build, "osbuild_store/sources/org.osbuild.files", localRPMChecksum("local rpm")), []byte("tampered"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `source "$1"; map_local_rpms_to_osbuild_store "$2" "$3" true`, "bash", script, filepath.Join(dir, "verify-map"), filepath.Join(build, "osbuild_store/sources/org.osbuild.files"))
			writeJSONFile(t, filepath.Join(dir, "verify-map"), []map[string]any{{"url": "file://" + source, "checksum": localRPMChecksum("local rpm")}})
			if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "checksum mismatch") {
				t.Fatalf("restore accepted corruption: %v %s", err, out)
			}
		})
	}
}

func TestOCIRepoImageTaskBinding(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test", nil, "")
	pipeline := GenerateTektonPipeline("test", "test", nil)
	for _, params := range [][]tektonv1.ParamSpec{task.Spec.Params, pipeline.Spec.Params} {
		if got, ok := paramDefault(params, "oci-repo-image"); !ok || got != "" {
			t.Fatalf("repo default=%q, present=%v", got, ok)
		}
	}
	build := findPipelineTask(pipeline.Spec.Tasks, PipelineTaskBuildImage)
	if build == nil {
		t.Fatal("missing build task")
	}
	if got, ok := taskParamBinding(build, "oci-repo-image"); !ok || got != "$(params.oci-repo-image)" {
		t.Fatalf("repo binding=%q present=%v", got, ok)
	}
	for _, step := range task.Spec.Steps {
		if step.Name != PipelineTaskBuildImage {
			continue
		}
		for _, env := range step.Env {
			if env.Name == "OCI_REPO_IMAGE" && env.Value == "$(params.oci-repo-image)" {
				return
			}
		}
	}
	t.Fatal("OCI repository image environment binding missing")
}

func TestLocalRPMAppendPreservesRemoteSBOM(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []map[string]any
	}{
		{name: "no local entries", entries: []map[string]any{}},
		{name: "local metadata only", entries: []map[string]any{{"kind": "module_metadata"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			localMap, bom := filepath.Join(dir, "local-map.json"), filepath.Join(dir, "bom.json")
			writeJSONFile(t, localMap, tc.entries)
			original := []byte("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"version\":1,\"components\":[{\"type\":\"library\",\"name\":\"remote\",\"purl\":\"pkg:rpm/remote@1.0-1?arch=noarch\"}]}\n")
			if err := os.WriteFile(bom, original, 0600); err != nil {
				t.Fatal(err)
			}
			runHermetoFunction(t, "append_local_rpms_to_sbom", localMap, bom, "")
			got, err := os.ReadFile(bom)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(original) {
				t.Fatalf("remote SBOM bytes changed:\n%s", got)
			}
		})
	}
}

func TestLocalRPMIdentityRequirements(t *testing.T) {
	for _, tc := range []struct {
		name, kind, filename, missing, wantErr string
	}{
		{name: "source without arch", kind: "source", filename: "demo.src.rpm", missing: "arch"},
		{name: "nosrc without arch", kind: "source", filename: "demo.nosrc.rpm", missing: "arch"},
		{name: "source normalizes arch", kind: "source", filename: "demo.src.rpm"},
		{name: "binary requires arch", kind: "packages", filename: "demo.rpm", missing: "arch", wantErr: "Local RPM has no usable arch"},
		{name: "source requires name", kind: "source", filename: "demo.src.rpm", missing: "name", wantErr: "Local RPM has no usable name"},
		{name: "source requires evr", kind: "source", filename: "demo.src.rpm", missing: "evr", wantErr: "Local RPM has no usable evr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lock, localMap := filepath.Join(dir, "aib.lock"), filepath.Join(dir, "local-map.json")
			entry := map[string]any{"url": "file:///extra-repos/oci-repo/" + tc.filename, "checksum": localRPMChecksum("local rpm"), "name": "demo", "evr": "1.0-1", "arch": "noarch"}
			delete(entry, tc.missing)
			writeJSONFile(t, lock, map[string]any{"version": 1, "depsolves": map[string]any{"one": map[string]any{
				"request": map[string]any{"architecture": "aarch64"}, tc.kind: []map[string]any{entry},
			}}})
			script, err := filepath.Abs("scripts/hermeto.sh")
			if err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("bash", "-c", `source "$1"; convert_aib_lock_to_hermeto "$2" "$3" "$4" "$5"`, "bash", script, lock, filepath.Join(dir, "hermeto.lock"), filepath.Join(dir, "remote-map.json"), localMap).CombinedOutput()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(string(out), tc.wantErr) {
					t.Fatalf("err=%v output=%s", err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("conversion failed: %v\n%s", err, out)
			}
			data, err := os.ReadFile(localMap)
			if err != nil {
				t.Fatal(err)
			}
			var entries []map[string]any
			if err := json.Unmarshal(data, &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0]["arch"] != "src" || entries[0]["name"] != "demo" || entries[0]["evr"] != "1.0-1" {
				t.Fatalf("incorrect source RPM identity: %s", data)
			}
			runHermetoFunction(t, "append_local_rpms_to_sbom", localMap, filepath.Join(dir, "bom.json"), "quay.io/org/rpms@sha256:"+strings.Repeat("a", 64))
			bom, err := os.ReadFile(filepath.Join(dir, "bom.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(bom), "arch=src") {
				t.Fatalf("source RPM SBOM lost architecture: %s", bom)
			}
		})
	}
}
