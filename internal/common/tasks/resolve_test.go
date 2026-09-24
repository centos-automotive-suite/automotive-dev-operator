package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
)

func TestSecureBuildTaskBinding(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test", nil, "")
	pipeline := GenerateTektonPipeline("test", "test", nil)
	for _, params := range [][]tektonv1.ParamSpec{task.Spec.Params, pipeline.Spec.Params} {
		if got, ok := paramDefault(params, "secure-build"); !ok || got != "false" {
			t.Fatalf("secure default=%q, present=%v", got, ok)
		}
	}
	build := findPipelineTask(pipeline.Spec.Tasks, PipelineTaskBuildImage)
	if build == nil {
		t.Fatal("missing build task")
	}
	if got, ok := taskParamBinding(build, "secure-build"); !ok || got != "$(params.secure-build)" {
		t.Fatalf("secure binding=%q present=%v", got, ok)
	}
	for _, step := range task.Spec.Steps {
		for _, env := range step.Env {
			if env.Name == "SECURE_BUILD" && env.Value == "$(params.secure-build)" {
				return
			}
		}
	}
	t.Fatal("secure-build env missing")
}

func TestResolveOnlyTaskBinding(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test", nil, "")
	pipeline := GenerateTektonPipeline("test", "test", nil)
	for _, params := range [][]tektonv1.ParamSpec{task.Spec.Params, pipeline.Spec.Params} {
		if got, ok := paramDefault(params, "resolve-only"); !ok || got != "false" {
			t.Fatalf("resolve default=%q, present=%v", got, ok)
		}
	}
	build := findPipelineTask(pipeline.Spec.Tasks, PipelineTaskBuildImage)
	if build == nil {
		t.Fatal("build task missing")
	}
	if got, ok := taskParamBinding(build, "resolve-only"); !ok || got != "$(params.resolve-only)" {
		t.Fatalf("resolve binding=%q, present=%v", got, ok)
	}
	found := false
	for _, step := range task.Spec.Steps {
		for _, env := range step.Env {
			if env.Name == "RESOLVE_ONLY" && env.Value == "$(params.resolve-only)" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("resolve-only environment binding missing")
	}
}

func TestResolveOnlyStopsBeforeImageBuild(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	branch := lockedBuildScript(t, string(data))
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			preamble := `
set -e
fail() { echo "ERROR: $*"; exit 1; }
write_result() { printf 'RESULT <%s> <%s>\n' "$1" "$2"; }
compute_artifact_digest() { echo sha256:example; }
aib-dev() {
 printf 'AIB'; printf ' <%s>' "$@"; printf '\n'
 if [ "$1" = "--version" ]; then return; fi
 if [ "$AIB_FAIL" = "true" ]; then return 42; fi
 while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then shift; printf '{"version":1}' > "$1"; return; fi
  shift
 done
}
aib() { [ "$1" = "--version" ] || exit 99; }
CUSTOM_DEFS_ARGS=(--define 'message=two words')
AIB_EXTRA_ARGS=(--verbose)
`
			cmd := exec.Command("bash", "-c", preamble+branch+"\necho UNEXPECTED_IMAGE_BUILD")
			dir := t.TempDir()
			cmd.Env = append(os.Environ(), "RESOLVE_ONLY=true", "BUILD_MODE=package", "REPRODUCIBLE=false", "USE_PERSISTENT_CACHE=false", "AIB_FAIL="+map[bool]string{false: "false", true: "true"}[fail],
				"WORKSPACE_PATH="+dir, "MANIFEST_CONFIG_PATH="+dir+"/config", "MANIFEST_FILE="+dir+"/input with spaces.aib.yml",
				"DISTRO=autosd", "TARGET=qemu", "ARCH=aarch64", "AIB_IMAGE_REF=registry/aib@sha256:example")
			out, err := cmd.CombinedOutput()
			if (err != nil) != fail {
				t.Fatalf("err=%v, output=%s", err, out)
			}
			if strings.Contains(string(out), "UNEXPECTED_IMAGE_BUILD") {
				t.Fatalf("image build was executed: %s", out)
			}
			published := strings.Contains(string(out), "RESULT <artifact-filename> <aib.lock>")
			if published == fail {
				t.Fatalf("unexpected artifact publication: %s", out)
			}
			if !strings.Contains(string(out), "<resolve> <--distro> <autosd> <--target> <qemu> <--arch> <aarch64> <--define> <message=two words>") {
				t.Fatalf("resolver arguments lost: %s", out)
			}
		})
	}
}

func lockedBuildScript(t *testing.T, data string) string {
	t.Helper()
	_, rest, ok := strings.Cut(data, "resolve_dependency_lock() {")
	if !ok {
		t.Fatal("resolution helper missing")
	}
	block, _, ok := strings.Cut(rest, "declare -a ROOT_PASSWORD_ARGS=()")
	if !ok {
		t.Fatal("locked build boundary missing")
	}
	return "resolve_dependency_lock() {" + block
}

func TestAutomaticBuildLock(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	block := lockedBuildScript(t, string(data))
	cases := []struct {
		name, mode, secure, repro, supplied, restore, resolverResult string
		wantResolve, wantPrefetch, wantFailure                       bool
	}{
		{name: "ordinary", mode: "package"},
		{name: "secure", mode: "package", secure: "true", wantResolve: true, wantPrefetch: true},
		{name: "reproducible", mode: "package", repro: "true", wantResolve: true, wantPrefetch: true},
		{name: "bootc entrypoint", mode: "bootc", secure: "true", wantResolve: true, wantPrefetch: true},
		{name: "supplied", mode: "package", secure: "true", supplied: "original", wantPrefetch: true},
		{name: "restored", mode: "package", secure: "true", restore: "recorded", wantPrefetch: true},
		{name: "missing restore lock", mode: "package", secure: "true", restore: "missing", wantFailure: true},
		{name: "resolution failed", mode: "package", secure: "true", resolverResult: "fail", wantResolve: true, wantFailure: true},
		{name: "empty resolution", mode: "package", secure: "true", resolverResult: "empty", wantResolve: true, wantFailure: true},
		{name: "empty supplied", mode: "package", secure: "true", supplied: "empty", wantFailure: true},
		{name: "preparation failed", mode: "package", secure: "true", resolverResult: "prefetch-fail", wantResolve: true, wantPrefetch: true, wantFailure: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "aib.lock"), []byte("stale"), 0600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(dir, "config")
			if err := os.Mkdir(config, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.supplied != "" {
				content := tc.supplied
				if content == "empty" {
					content = ""
				}
				if err := os.WriteFile(filepath.Join(config, "aib.lock"), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			script := `set -e
fail() { echo "ERROR: $*"; exit 1; }
write_result() { :; }
aib-dev() { echo "RESOLVE aib-dev"; resolve_stub "$@"; }
aib() { echo "RESOLVE aib"; resolve_stub "$@"; }
resolve_stub() {
 printf 'ARGS'; printf ' <%s>' "$@"; printf '\n'
 [ "$RESOLVER_RESULT" != fail ] || return 42
 [ "$RESOLVER_RESULT" != empty ] || return 0
 while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then shift; printf generated > "$1"; return; fi
  shift
 done
 return 1
}
restore_sources_if_requested() {
 [ "$RESTORE_KIND" != recorded ] || printf recorded > "$AIB_LOCKFILE"
 return 0
}
prepare_locked_rpms_with_hermeto() {
 echo "PREFETCH $HERMETO_PREFETCH"
 [ "$RESOLVER_RESULT" != prefetch-fail ] || return 42
}
setup_osbuild() { echo SETUP; }
CUSTOM_DEFS_ARGS=(--define 'message=two words')
AIB_EXTRA_ARGS=(--verbose)
` + block + `printf 'BUILD'; printf ' <%s>' "${LOCKFILE_ARGS[@]}"; printf '\n'`
			restoreRef := ""
			if tc.restore != "" {
				restoreRef = "registry.example/prior@sha256:abc"
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "RESOLVE_ONLY=false", "USE_PERSISTENT_CACHE=false", "BUILD_MODE="+tc.mode, "SECURE_BUILD="+tc.secure, "REPRODUCIBLE="+tc.repro, "HERMETO_PREFETCH=false", "RESTORE_SOURCES_REF="+restoreRef, "RESTORE_KIND="+tc.restore, "RESOLVER_RESULT="+tc.resolverResult, "WORKSPACE_PATH="+dir, "MANIFEST_CONFIG_PATH="+config, "BUILD_DIR="+dir, "MANIFEST_FILE=input.aib.yml", "DISTRO=autosd", "TARGET=qemu", "ARCH=aarch64")
			output, err := cmd.CombinedOutput()
			out := string(output)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("error=%v, output=%s", err, out)
			}
			if strings.Contains(out, "RESOLVE ") != tc.wantResolve {
				t.Fatalf("unexpected resolution: %s", out)
			}
			if strings.Contains(out, "PREFETCH true") != tc.wantPrefetch {
				t.Fatalf("unexpected preparation: %s", out)
			}
			if tc.wantFailure {
				if strings.Contains(out, "BUILD <") || strings.Contains(out, "SETUP") {
					t.Fatalf("continued after failure: %s", out)
				}
				return
			}
			if tc.wantResolve {
				want := "RESOLVE aib-dev"
				if tc.mode == "bootc" {
					want = "RESOLVE aib\n"
				}
				if !strings.Contains(out, want) {
					t.Fatalf("wrong resolver: %s", out)
				}
				if tc.repro == "true" && !strings.Contains(out, "<reproducible_image=true>") {
					t.Fatalf("missing reproducibility definition: %s", out)
				}
			}
			if tc.secure == "true" || tc.repro == "true" {
				if !strings.Contains(out, "<--lockfile> <"+filepath.Join(dir, "aib.lock")+">") {
					t.Fatalf("build lost lock: %s", out)
				}
				expected := "generated"
				if tc.supplied != "" {
					expected = tc.supplied
				}
				if tc.restore == "recorded" {
					expected = "recorded"
				}
				content, err := os.ReadFile(filepath.Join(dir, "aib.lock"))
				if err != nil || string(content) != expected {
					t.Fatalf("lock changed: %s %v", content, err)
				}
			}
		})
	}
}

func TestRestoreRecordedLock(t *testing.T) {
	data, err := os.ReadFile("scripts/build_image.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "restore_sources_if_requested() {")
	if !ok {
		t.Fatal("restore function missing")
	}
	body, _, ok := strings.Cut(rest, "\nprepare_build_directory\n")
	if !ok {
		t.Fatal("restore boundary missing")
	}
	for _, scenario := range []string{"restore", "oras 1.2", "matching", "mismatch", "missing", "ambiguous", "pull failure"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			lock := filepath.Join(dir, "aib.lock")
			if scenario == "matching" || scenario == "mismatch" {
				contents := "recorded"
				if scenario == "mismatch" {
					contents = "other"
				}
				if err := os.WriteFile(lock, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			script := `set -e -o pipefail
fail() { echo "ERROR: $*"; exit 1; }
install_oras() { :; }
oras() {
 local operation="$1"; shift
 if [ "$operation" = resolve ]; then printf 'sha256:%064d\n' 1; return; fi
 if [ "$operation" = discover ]; then
   [[ "$1" = *@sha256:* ]] || exit 90
   if [ "$3" = sources ]; then
     if [ "$SCENARIO" = 'oras 1.2' ]; then printf '{"manifests":[{"digest":"sha256:%064d"}]}\n' 2;
     else printf '{"reference":"image@sha256:%064d","digest":"sha256:%064d","referrers":[{"digest":"sha256:%064d"}]}\n' 1 1 2; fi
     return
   fi
   if [ "$SCENARIO" = missing ]; then echo '{"referrers":[]}'; return; fi
   if [ "$SCENARIO" = ambiguous ]; then echo '{"referrers":[{},{}]}'; return; fi
   if [ "$SCENARIO" = 'oras 1.2' ]; then printf '{"manifests":[{"digest":"sha256:%064d"}]}\n' 3; return; fi
   printf '{"referrers":[{"digest":"sha256:%064d"}]}\n' 3; return
 fi
 if [ "$operation" = pull ]; then
   local dest="$3"
   if [[ "$dest" = */lock ]]; then
     [ "$SCENARIO" != 'pull failure' ] || return 42
     printf recorded > "$dest/aib.lock"
   else
     [[ "$1" = *@$(printf 'sha256:%064d' 2) ]] || exit 91
     mkdir -p "$FIXTURE/sources"
     printf rpm > "$FIXTURE/sources/example"
     tar -czf "$dest/build-sources.tar.gz" -C "$FIXTURE" sources
   fi
 fi
}
` + "restore_sources_if_requested() {" + body + "\nrestore_sources_if_requested\necho RESTORED\n"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "SECURE_BUILD=true", "REPRODUCIBLE=false", "RESTORE_SOURCES_REF=registry.example:5000/test/image:old", "REGISTRY_AUTH_FILE=", "AIB_LOCKFILE="+lock, "BUILD_DIR="+filepath.Join(dir, "build"), "FIXTURE="+filepath.Join(dir, "fixture"), "SCENARIO="+scenario, "OCI_REFERRER_TYPE_BUILD_SOURCES=sources", "OCI_REFERRER_TYPE_AIB_LOCKFILE=lock")
			output, err := cmd.CombinedOutput()
			want := scenario == "restore" || scenario == "matching" || scenario == "oras 1.2"
			if (err == nil) != want {
				t.Fatalf("err=%v output=%s", err, output)
			}
			if want {
				got, err := os.ReadFile(lock)
				if err != nil || string(got) != "recorded" {
					t.Fatalf("lock=%q err=%v", got, err)
				}
			}
		})
	}
}
