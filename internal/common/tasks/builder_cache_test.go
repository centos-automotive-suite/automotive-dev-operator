package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type builderCacheCase struct {
	name, scenario, policy                 string
	force, fails, skipAIB, prepareSucceeds bool
	pulls, pushes                          int
}

func TestBuilderCache(t *testing.T) {
	for _, entrypoint := range []string{"build", "prepare"} {
		for _, tc := range []builderCacheCase{
			{name: "unchanged", scenario: "unchanged", pulls: 1},
			{name: "explicit validation", scenario: "unchanged", policy: "validate", pulls: 1},
			{name: "reuse without depsolve", scenario: "aib-fail", policy: "reuse", pulls: 1, skipAIB: true},
			{name: "reuse cache miss builds", scenario: "missing", policy: "reuse", pulls: 1, pushes: 1},
			{name: "force overrides reuse", scenario: "unchanged", policy: "reuse", force: true, pulls: 1, pushes: 1},
			{name: "reuse pull failure rebuilds", scenario: "pull-fail", policy: "reuse", pulls: 2, pushes: 1},
			{name: "reuse local inspection failure only affects local consumer", scenario: "inspect-fail", policy: "reuse", fails: true, prepareSucceeds: true, skipAIB: true},
			{name: "reuse invalid digest is fatal", scenario: "cache-invalid", policy: "reuse", fails: true},
			{name: "invalid policy", scenario: "unchanged", policy: "invalid", fails: true},
			{name: "changed inputs", scenario: "changed", pulls: 2, pushes: 1},
			{name: "cache miss", scenario: "missing", pulls: 1, pushes: 1},
			{name: "forced identical rebuild", scenario: "unchanged", force: true, pulls: 1, pushes: 1},
			{name: "cached pull failure rebuilds", scenario: "pull-fail", pulls: 2, pushes: 1},
			{name: "cache removed before pin", scenario: "pin-race", pulls: 1, pushes: 1},
			{name: "pin failure stops publication", scenario: "pin-fail", fails: true},
			{name: "freshness check fails", scenario: "aib-fail", fails: true},
			{name: "local inspect fails", scenario: "inspect-fail", fails: true},
			{name: "local digest empty", scenario: "inspect-empty", fails: true},
			{name: "push fails", scenario: "push-fail", fails: true},
			{name: "push digest missing", scenario: "digest-missing", fails: true},
			{name: "push digest invalid", scenario: "digest-invalid", fails: true},
			{name: "cache digest invalid", scenario: "cache-invalid", fails: true},
			{name: "pushed digest pull fails", scenario: "final-pull-fail", fails: true},
		} {
			if entrypoint == "prepare" && (tc.scenario == "final-pull-fail" || tc.scenario == "pin-fail" || tc.scenario == "pin-race") {
				continue // The prepare task has no local consumer after the push.
			}
			t.Run(entrypoint+"/"+tc.name, func(t *testing.T) {
				if entrypoint == "prepare" && tc.scenario == "pull-fail" && tc.policy == "reuse" {
					tc.pulls, tc.pushes, tc.skipAIB = 0, 0, true
				}
				dir := t.TempDir()
				body := builderCacheTestScript(t, entrypoint, dir)
				force := "false"
				if tc.force {
					force = "true"
				}
				cmd := exec.Command("bash", "-c", body)
				cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "RESULT_PATH="+filepath.Join(dir, "result"),
					"SCENARIO="+tc.scenario, "REBUILD_BUILDER="+force, "BUILDER_CACHE_POLICY="+tc.policy)
				output, err := cmd.CombinedOutput()
				out := string(output)
				fails := tc.fails && (entrypoint != "prepare" || !tc.prepareSucceeds)
				if (err != nil) != fails {
					t.Fatalf("error=%v, want failure=%t\n%s", err, fails, out)
				}
				leftovers, err := filepath.Glob(filepath.Join(dir, "builder-*-*.*"))
				if err != nil || len(leftovers) != 0 {
					t.Fatalf("temporary builder files leaked: %v, %v", leftovers, err)
				}
				if fails {
					if !strings.Contains(out, "ERROR:") {
						t.Errorf("failure has no diagnostic\n%s", out)
					}
					if _, err := os.Stat(filepath.Join(dir, "result")); !os.IsNotExist(err) || strings.Contains(out, "SUCCESS") {
						t.Fatalf("published a builder result after failure\n%s", out)
					}
					return
				}
				assertBuilderCacheSuccess(t, entrypoint, tc, dir, out)
			})
		}
	}
}

func assertBuilderCacheSuccess(t *testing.T, entrypoint string, tc builderCacheCase, dir, out string) {
	t.Helper()
	pulls := tc.pulls
	if entrypoint == "prepare" && tc.pushes > 0 {
		pulls--
	}
	if entrypoint == "prepare" && tc.skipAIB {
		pulls = 0
		if _, err := os.Stat(filepath.Join(dir, "local-inspects")); !os.IsNotExist(err) {
			t.Fatalf("prepare reuse inspected local storage: %v", err)
		}
		inspects, err := os.ReadFile(filepath.Join(dir, "remote-inspects"))
		if err != nil || string(inspects) != "inspect\n" {
			t.Fatalf("prepare reuse should only inspect the registry once: %q, %v", inspects, err)
		}
	}
	aibCalls := 1
	if tc.skipAIB {
		aibCalls = 0
	}
	pins := 0
	if entrypoint == "build" {
		pins = 1
		if tc.pushes > 0 && !tc.force && tc.scenario != "missing" {
			pins++
		}
	}
	for event, want := range map[string]int{"PIN <": pins, "PULL <": pulls, "PUSH <": tc.pushes, "AIB <": aibCalls} {
		if got := strings.Count(out, event); got != want {
			t.Errorf("%s count=%d, want %d\n%s", event, got, want, out)
		}
	}
	if !tc.skipAIB && strings.Contains(out, "<--if-needed>") == (tc.force || tc.scenario == "pull-fail" || tc.scenario == "pin-race") {
		t.Errorf("incorrect freshness flag for force=%t\n%s", tc.force, out)
	}
	if entrypoint == "build" && !strings.Contains(out, "PROGRESS <Builder image ready> <3> <6>") {
		t.Errorf("incorrect prepared-builder progress\n%s", out)
	}
	if entrypoint == "prepare" && !strings.Contains(out, "PROGRESS <Builder ready> <2> <2>") {
		t.Errorf("incorrect prepare-task progress\n%s", out)
	}
	if !tc.skipAIB && !strings.Contains(out, "<--distro> <autosd> <--define> <repo=two words>") {
		t.Errorf("builder lost custom definitions\n%s", out)
	}
	digestChar := "a"
	if tc.pushes > 0 {
		digestChar = "b"
	}
	want := "registry.example:5000/test/aib-build@sha256:" + strings.Repeat(digestChar, 64)
	if !strings.Contains(out, "SUCCESS <"+want+">") {
		t.Errorf("result does not pin the consumed builder\n%s", out)
	}
}

func builderCacheTestScript(t *testing.T, entrypoint, dir string) string {
	t.Helper()
	body := builderCacheHarness + builderCacheScript
	if entrypoint == "build" {
		body += shellFunctions(t, buildImageScript, "cleanup() {", "fail() {")
		body += shellFunctions(t, buildImageScript, "BOOTC_CONTAINER_NAME=", "\nprepare_builder_if_needed() {")
		body += shellFunctions(t, buildImageScript, "prepare_builder_if_needed() {", "\nprepare_builder_if_needed\n") + "\nprepare_builder_if_needed\n"
	} else {
		body += strings.ReplaceAll(buildBuilderScript, "$(workspaces.manifest-config-workspace.path)", dir)
	}
	return body + "\nprintf 'SUCCESS <%s>\\n' \"$(cat \"$RESULT_PATH\")\"\n"
}

func TestBuilderCacheTagsAcrossCallers(t *testing.T) {
	var previous string
	for _, definition := range []string{"repo=two words", "repo=another repo"} {
		var buildTag string
		for _, entrypoint := range []string{"build", "prepare"} {
			dir := t.TempDir()
			cmd := exec.Command("bash", "-c", builderCacheTestScript(t, entrypoint, dir))
			cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "RESULT_PATH="+filepath.Join(dir, "result"),
				"SCENARIO=unchanged", "REBUILD_BUILDER=false", "BUILDER_CACHE_POLICY=validate", "TEST_DEFINITION="+definition)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s failed: %v\n%s", entrypoint, err, out)
			}
			lookup, err := os.ReadFile(filepath.Join(dir, "lookup"))
			if err != nil {
				t.Fatal(err)
			}
			if entrypoint == "build" {
				buildTag = string(lookup)
			} else if string(lookup) != buildTag {
				t.Fatalf("callers use different cache tags: %s != %s", buildTag, lookup)
			}
		}
		if buildTag == previous {
			t.Fatal("different definitions share a cache tag")
		}
		previous = buildTag
	}
}

func TestBuilderCacheTagSeparatesInputs(t *testing.T) {
	inputs := [][]string{
		{"aib:1.3.5", "autosd", "arm64"},
		{"aib:1.3.6", "autosd", "arm64"},
		{"aib:1.3.5", "other", "arm64"},
		{"aib:1.3.5", "autosd", "amd64"},
		{"aib:1.3.5", "autosd", "arm64", "--define", "a=one --define b=two"},
		{"aib:1.3.5", "autosd", "arm64", "--define", "a=one", "--define", "b=two"},
		{"aib:1.3.5", "autosd", "arm64", "--define", "a=one", "--define", "a=two"},
		{"aib:1.3.5", "autosd", "arm64", "--define", "a=two", "--define", "a=one"},
	}
	seen := make(map[string]bool)
	for _, args := range inputs {
		cmd := exec.Command("bash", append([]string{"-c", builderCacheScript + `builder_cache_tag "$@"`, "test"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("tag failed: %v\n%s", err, out)
		}
		if seen[string(out)] {
			t.Fatalf("cache tag collision for %q: %s", args, out)
		}
		seen[string(out)] = true
	}
}

func TestBuilderDigestRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for ref, repo := range map[string]string{
		"builder": "builder", "builder:latest": "builder",
		"registry:5000/team/builder:latest": "registry:5000/team/builder",
		"registry/team/builder@" + digest:   "registry/team/builder",
	} {
		t.Run(ref, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", builderCacheScript+`builder_digest_ref "$REF" "$DIGEST"`)
			cmd.Env = append(os.Environ(), "REF="+ref, "DIGEST="+digest)
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != repo+"@"+digest {
				t.Fatalf("unexpected reference: %s, %v", out, err)
			}
		})
	}
}

func TestBuilderCacheEmbeddedInBothTasks(t *testing.T) {
	for name, script := range map[string]string{"build": BuildImageScript, "prepare": BuildBuilderScript} {
		if !strings.Contains(script, builderCacheScript) {
			t.Errorf("%s task does not embed builder cache helpers", name)
		}
	}
}

func TestProvidedBuilderSkipsFreshnessCheck(t *testing.T) {
	for _, entrypoint := range []string{"build", "prepare"} {
		t.Run(entrypoint, func(t *testing.T) {
			dir := t.TempDir()
			body := builderCacheHarness + builderCacheScript + `
PREPARES_BUILDER=false
BUILDER_IMAGE=registry.example/custom:chosen
REBUILD_BUILDER=true
aib() { echo 'unexpected rebuild' >&2; exit 1; }
skopeo() { echo 'unexpected cache access' >&2; exit 1; }
pull_registry_image() {
  [ "$1" = "$BUILDER_IMAGE" ] && [ "$2" = "containers-storage:$LOCAL_BUILDER_IMAGE" ]
}
`
			if entrypoint == "build" {
				body += shellFunctions(t, buildImageScript, "prepare_builder_if_needed() {", "\nprepare_builder_if_needed\n") + "\nprepare_builder_if_needed\n"
			} else {
				body += buildBuilderScript
			}
			result := filepath.Join(dir, "result")
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "RESULT_PATH="+result)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("provided builder failed: %v\n%s", err, output)
			}
			ref, err := os.ReadFile(result)
			if err != nil || string(ref) != "registry.example/custom:chosen" {
				t.Fatalf("provided builder changed: %s, %v", ref, err)
			}
		})
	}
}

const builderCacheHarness = `
set -e
PREPARES_BUILDER=true
PULLS_BUILDER=true
CLUSTER_REGISTRY_ROUTE=registry.example:5000
REGISTRY="$CLUSTER_REGISTRY_ROUTE"
REGISTRY_AUTH_FILE="$TEST_DIR/auth"
NAMESPACE=test
DISTRO=autosd
TARGET_ARCH=amd64
BUILDER_CACHE_TAG=test-tag
AIB_IMAGE=quay.io/example/aib:1.3.5
AIB_IMAGE_REF="$AIB_IMAGE"
LOCAL_BUILDER_IMAGE=localhost/builder
BUILDER_IMAGE=
BUILD_DIR="$TEST_DIR/build"
SECURE_BUILD=true
STEP_BUILD=4
PROGRESS_TOTAL=6
CUSTOM_DEFS_ARGS=(--define "${TEST_DEFINITION:-repo=two words}")
SKOPEO_INSPECT_TLS_ARGS=(--tls-verify=false)
SKOPEO_COPY_TLS_ARGS=(--src-tls-verify=false --dest-tls-verify=false)
OLD_DIGEST=sha256:$(printf 'a%.0s' {1..64})
PUSH_DIGEST=sha256:$(printf 'b%.0s' {1..64})
create_service_account_auth() { printf auth > "$2"; }
mktemp() { command mktemp "$TEST_DIR/${1##*/}"; }
emit_progress() { printf 'PROGRESS <%s> <%s> <%s>\n' "$@"; }
setup_cluster_auth() { printf auth > "$REGISTRY_AUTH_FILE"; }
setup_container_config() { :; }
setup_var_tmp() { :; }
install_custom_ca_certs() { :; }
setup_osbuild() { :; }
load_custom_definitions() { CUSTOM_DEFS_ARGS=(--define "${TEST_DEFINITION:-repo=two words}"); }
write_result() { printf '%s' "$2" > "$RESULT_PATH"; }
pull_registry_image() { echo 'Unexpected second pull' >&2; return 1; }
aib() {
  printf 'AIB'; printf ' <%s>' "$@"; printf '\n'
  [ "$SCENARIO" != aib-fail ] || return 1
  if [ "$SCENARIO" = unchanged ]; then
    printf "%s" "$OLD_DIGEST" > "$TEST_DIR/local"
  else
    printf "sha256:%064d" 0 > "$TEST_DIR/local"
  fi
}
skopeo() {
  local op="$1" digest_file= auth=false
  shift
  if [ "$op" = inspect ]; then
    case "${@: -1}" in
      docker:*)
        printf 'inspect\n' >> "$TEST_DIR/remote-inspects"
        printf '%s' "${@: -1}" > "$TEST_DIR/lookup"
        [ "$SCENARIO" != missing ] || return 1
        if [ "$SCENARIO" = cache-invalid ]; then echo invalid; else echo "$OLD_DIGEST"; fi
        ;;
      containers-storage:*)
        printf 'inspect\n' >> "$TEST_DIR/local-inspects"
        [ "$SCENARIO" != inspect-fail ] || return 1
        [ "$SCENARIO" != inspect-empty ] || return 0
        cat "$TEST_DIR/local"
        ;;
      *) return 1 ;;
    esac
    return
  fi
  [ "$op" = copy ] || return 1
  while [[ "$1" == --* ]]; do
    case "$1" in
      --digestfile) digest_file="$2"; shift ;;
      --authfile=*) auth=true; [ -f "${1#*=}" ] || return 1 ;;
      --src-tls-verify=false|--dest-tls-verify=false|--preserve-digests) ;;
      *) echo "Unexpected copy option: $1" >&2; return 1 ;;
    esac
    shift
  done
  [ "$auth" = true ] || return 1
      case "$2" in
        *:pin-*)
          printf 'PIN <%s>\n' "$2"
          [ "$SCENARIO" != pin-fail ] || return 1
          if [ "$SCENARIO" = pin-race ] && [[ "$1" == *"@$OLD_DIGEST" ]]; then return 1; fi
          return 0 ;;
      esac
  case "$1" in
    docker:*)
      printf 'PULL <%s>\n' "$1"
      # Reject mutable-tag pulls, including after a competing push moves the tag.
      case "$1" in
        *"@$OLD_DIGEST")
          [ "$SCENARIO" != pull-fail ] || return 1
          printf "%s" "$OLD_DIGEST" > "$TEST_DIR/local"
          ;;
        *"@$PUSH_DIGEST")
          [ "$SCENARIO" != final-pull-fail ] || return 1
          printf "%s" "$PUSH_DIGEST" > "$TEST_DIR/local" ;;
        *) echo 'Unexpected registry digest' >&2; return 1 ;;
      esac
      ;;
    containers-storage:*)
      printf 'PUSH <%s>\n' "$2"
      [ "$SCENARIO" != push-fail ] || return 1
      [ -n "$digest_file" ] || return 1
      case "$SCENARIO" in
        digest-missing) : ;;
        digest-invalid) echo invalid > "$digest_file" ;;
        *) echo "$PUSH_DIGEST" > "$digest_file" ;;
      esac
      ;;
    *) return 1 ;;
  esac
}
`

func TestProvidedManagedBuilderPinnedBeforePull(t *testing.T) {
	for _, suffix := range []string{":manual", "@sha256:" + strings.Repeat("a", 64)} {
		t.Run(suffix, func(t *testing.T) {
			dir := t.TempDir()
			body := builderCacheHarness + builderCacheScript + `
PREPARES_BUILDER=false
BUILDER_IMAGE="registry.example:5000/test/aib-build$TEST_SUFFIX"
pull_registry_image() { printf 'CONSUME <%s>\n' "$1"; }
` + shellFunctions(t, buildImageScript, "prepare_builder_if_needed() {", "\nprepare_builder_if_needed\n") + "\nprepare_builder_if_needed\n"
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "RESULT_PATH="+filepath.Join(dir, "result"), "TEST_SUFFIX="+suffix, "SCENARIO=unchanged")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			pin, consume := strings.Index(string(out), "PIN <"), strings.Index(string(out), "CONSUME <")
			if pin < 0 || consume < pin {
				t.Fatalf("did not pin before consuming: %s", out)
			}
			result, err := os.ReadFile(filepath.Join(dir, "result"))
			if err != nil || string(result) != "registry.example:5000/test/aib-build@sha256:"+strings.Repeat("a", 64) {
				t.Fatalf("wrong recorded ref: %s, %v", result, err)
			}
		})
	}
}
