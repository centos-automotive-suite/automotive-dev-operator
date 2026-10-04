package tasks

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitSourceTaskValidation(t *testing.T) {
	if err := GenerateGitSourceTask("test", nil).Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := GenerateGitSourceDiscoveryTask("test", nil).Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGitManifestStepCanRewritePVCCheckout(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test", nil, "")
	for _, step := range task.Spec.Steps {
		if step.Name != "find-manifest-file" {
			continue
		}
		if step.SecurityContext == nil || step.SecurityContext.RunAsUser == nil || *step.SecurityContext.RunAsUser != 0 {
			t.Fatal("find-manifest-file must run as root to rewrite the Git checkout")
		}
		return
	}
	t.Fatal("find-manifest-file step not found")
}

func TestGitSourceStaging(t *testing.T) {
	if _, err := exec.LookPath("yq"); err != nil {
		t.Skip("yq unavailable")
	}
	dir := t.TempDir()
	repository := filepath.Join(dir, "shared", ".caib-source", "repository")
	config := filepath.Join(dir, "config")
	work := filepath.Join(dir, "manifest-work")
	for _, p := range []string{filepath.Join(repository, "images"), filepath.Join(repository, "shared"), config, work} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for p, content := range map[string]string{
		filepath.Join(config, "git-manifest-path"):           "images/demo.aib.yml",
		filepath.Join(repository, "images", "demo.aib.yml"):  "content:\n  add_files:\n    - path: /etc/config\n      source_path: ../shared/config\n",
		filepath.Join(repository, "images", "demo.aib.lock"): `{"version":1}`,
		filepath.Join(repository, "shared", "config"):        "from Git",
		filepath.Join(repository, ".settings"):               "hidden",
	} {
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.NewReplacer("$(workspaces.manifest-config-workspace.path)", config, "$(workspaces.shared-workspace.path)", filepath.Join(dir, "shared"), "/manifest-work", work, "/tekton/results", filepath.Join(dir, "results")).Replace(FindManifestScript)
	if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("staging: %v %s", err, out)
	}
	manifest := filepath.Join(work, "source", "images", "demo.aib.yml")
	file, err := exec.Command("yq", "eval", ".content.add_files[0].source_path", manifest).Output()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(strings.TrimSpace(string(file)))
	if err != nil || string(data) != "from Git" {
		t.Fatalf("staged reference: %s %v", data, err)
	}
	for _, p := range []string{filepath.Join(work, "source", "images", "demo.aib.lock"), filepath.Join(work, "source", ".settings")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
}

func assertGitSourceSnapshot(t *testing.T, cmd *exec.Cmd, workspace, wantCommit string) string {
	t.Helper()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("checkout: %v %s", err, out)
	}
	commit, err := os.ReadFile(filepath.Join(workspace, ".caib-source", "commit"))
	if err != nil || strings.TrimSpace(string(commit)) != wantCommit {
		t.Fatalf("commit=%s want=%s err=%v", commit, wantCommit, err)
	}
	data, err := os.ReadFile(filepath.Join(workspace, ".caib-source", "repository", "demo.aib.yml"))
	if err != nil || string(data) != "name: first\n" {
		t.Fatalf("manifest=%s err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".caib-source", "repository", ".git")); !os.IsNotExist(err) {
		t.Fatal("Git metadata retained in build context")
	}
	return string(out)
}

func TestCloneGitSourceSnapshot(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(git, append([]string{"-C", repo, "-c", "user.name=Test", "-c", "user.email=test@example.com"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "--initial-branch=main")
	runGit("config", "uploadpack.allowFilter", "true")
	manifest := filepath.Join(repo, "demo.aib.yml")
	if err := os.WriteFile(manifest, []byte("name: first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "large.bin"), []byte(strings.Repeat("x", 200*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	manifestBlob := runGit("hash-object", "demo.aib.yml")
	largeBlob := runGit("hash-object", "large.bin")
	runGit("add", ".")
	runGit("commit", "-m", "first")
	first := runGit("rev-parse", "HEAD")
	runGit("tag", "release")
	runGit("tag", "-a", "annotated-release", "-m", "first release")
	server := httptest.NewTLSServer(&cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + dir, "GIT_HTTP_EXPORT_ALL=1"}})
	defer server.Close()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	sourceCommand := func(ref, workspace string, env ...string) *exec.Cmd {
		cmd := exec.Command("sh", "-c", CloneGitSourceScript)
		cmd.Env = append(os.Environ(), "SOURCE_URL="+server.URL+"/repo/.git", "SOURCE_REVISION="+ref, "SOURCE_WORKSPACE="+workspace, "SOURCE_MANIFEST=demo.aib.yml", "SOURCE_DISCOVERY=", "SOURCE_COMMIT=", "GIT_SSL_CAINFO="+caFile)
		cmd.Env = append(cmd.Env, env...)
		return cmd
	}
	clone := func(ref string, env ...string) string {
		t.Helper()
		workspace := t.TempDir()
		return assertGitSourceSnapshot(t, sourceCommand(ref, workspace, env...), workspace, first)
	}
	clone("")
	clone("main")
	clone("release")
	clone("annotated-release")
	discover := func(ref string) string {
		t.Helper()
		workspace := t.TempDir()
		if out, err := sourceCommand(ref, workspace, "SOURCE_DISCOVERY=true").CombinedOutput(); err != nil {
			t.Fatalf("discover %q: %v %s", ref, err, out)
		} else if strings.Contains(string(out), "filtering not recognized by server") {
			t.Fatalf("discovery did not use the blob-less fetch: %s", out)
		}
		commit, err := os.ReadFile(filepath.Join(workspace, ".caib-source", "commit"))
		if err != nil || strings.TrimSpace(string(commit)) != first {
			t.Fatalf("discovered %q commit=%s want=%s err=%v", ref, commit, first, err)
		}
		if data, err := os.ReadFile(filepath.Join(workspace, ".caib-source", "manifest")); err != nil || string(data) != "name: first\n" {
			t.Fatalf("discovered manifest=%q err=%v", data, err)
		}
		if _, err := os.Stat(filepath.Join(workspace, ".caib-source", "repository", "demo.aib.yml")); !os.IsNotExist(err) {
			t.Fatal("discovery checked out the repository")
		}
		objects := exec.Command(git, "-C", filepath.Join(workspace, ".caib-source", "repository"), "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
		localObjects, err := objects.Output()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(localObjects), manifestBlob) || strings.Contains(string(localObjects), largeBlob) {
			t.Fatal("discovery should fetch the manifest blob but not unrelated file blobs")
		}
		return strings.TrimSpace(string(commit))
	}
	discover("main")
	discover("release")
	annotatedCommit := discover("annotated-release")
	clone("annotated-release", "SOURCE_COMMIT="+annotatedCommit)

	// Some servers reject fetching a commit ID directly; keep the fallback fetch real.
	bin := t.TempDir()
	const rejectedFetch = "simulated rejection of direct commit fetch"
	shim := `#!/bin/sh
if [ "$1" = fetch ] && [ -n "${SOURCE_COMMIT:-}" ] && [ "${6:-}" = "$SOURCE_COMMIT" ]; then
  echo '` + rejectedFetch + `' >&2
  exit 1
fi
exec "$GIT_SOURCE_TEST_REAL_GIT" "$@"
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	fallbackEnv := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "GIT_SOURCE_TEST_REAL_GIT=" + git, "SOURCE_COMMIT=" + annotatedCommit}
	if out := clone("annotated-release", fallbackEnv...); !strings.Contains(out, rejectedFetch) {
		t.Fatalf("pinned checkout did not exercise the fallback fetch: %s", out)
	}
	if err := os.WriteFile(manifest, []byte("name: second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-m", "second")
	clone(first)
	runGit("tag", "-f", "-a", "annotated-release", "-m", "second release")
	clone("annotated-release", "SOURCE_COMMIT="+annotatedCommit)
	workspace := t.TempDir()
	if out, err := sourceCommand("annotated-release", workspace, fallbackEnv...).CombinedOutput(); err == nil || !strings.Contains(string(out), rejectedFetch) || !strings.Contains(string(out), "Git revision changed since discovery") {
		t.Fatalf("moved annotated tag fallback: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".caib-source", "repository", "demo.aib.yml")); !os.IsNotExist(err) {
		t.Fatal("moved annotated tag was checked out despite the pinned commit")
	}
	checkout := func(commit string) (string, error) {
		t.Helper()
		out, err := sourceCommand("main", t.TempDir(), "SOURCE_COMMIT="+commit).CombinedOutput()
		return string(out), err
	}
	if out, err := checkout(first); err != nil {
		t.Fatalf("pinned checkout: %v %s", err, out)
	}
	if out, err := checkout(strings.Repeat("a", 40)); err == nil || !strings.Contains(out, "Git revision changed since discovery") {
		t.Fatalf("moved revision: %v %s", err, out)
	}
	if err := os.Symlink("demo.aib.yml", filepath.Join(repo, "link.aib.yml")); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-m", "symlink")
	symlinkDiscovery := sourceCommand("main", t.TempDir(), "SOURCE_MANIFEST=link.aib.yml", "SOURCE_DISCOVERY=true")
	if out, err := symlinkDiscovery.CombinedOutput(); err == nil || !strings.Contains(string(out), "must not be a symlink") {
		t.Fatalf("symlink discovery: %v %s", err, out)
	}
}

func assertGitLockfileMetadata(t *testing.T, workspace, output, candidate, committed string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(workspace, ".caib-source", "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]string
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["lockfilePath"] != committed {
		t.Fatalf("recorded lockfile = %q, want %q", metadata["lockfilePath"], committed)
	}
	message := "No committed lockfile at " + candidate
	if committed != "" {
		message = "Using committed lockfile " + committed
	}
	if !strings.Contains(output, message) {
		t.Fatalf("missing %q in prepare output: %s", message, output)
	}
}

func TestPrepareGitSourceInputs(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	if err := exec.Command(python, "-c", "import yaml").Run(); err != nil {
		t.Skip("PyYAML unavailable")
	}
	for _, tt := range []struct {
		name, lock, lockfilePath, committedLock, source, payload, manifest string
		invalid, danglingSymlink                                           bool
		extraFiles                                                         map[string]string
	}{
		{name: "nested locked", lock: `{"version":1}`, committedLock: "images/demo.aib.lock", source: "../shared/config"},
		{name: "unlocked", source: "../shared/config"},
		{name: "other manifest lock ignored", source: "../shared/config", extraFiles: map[string]string{"images/other.aib.lock": `{"version":2}`}},
		{name: "custom lock", lockfilePath: "locks/release.json", committedLock: "locks/release.json", source: "../shared/config", extraFiles: map[string]string{"locks/release.json": `{"version":1}`, "images/demo.aib.lock": `{"version":2}`}},
		{name: "missing custom lock", lockfilePath: "locks/missing.json", source: "../shared/config", invalid: true},
		{name: "invalid custom lock", lockfilePath: "locks/release.json", source: "../shared/config", invalid: true, extraFiles: map[string]string{"locks/release.json": `{"version":2}`}},
		{name: "invalid lock", lock: `{"version":2}`, source: "../shared/config", invalid: true},
		{name: "non JSON lock", lock: `version: 1`, source: "../shared/config", invalid: true},
		{name: "escape", source: "../../../outside", invalid: true},
		{name: "missing file", source: "missing", invalid: true},
		{name: "absolute", source: "/etc/passwd", invalid: true},
		{name: "null add_files", manifest: "target: board\ncontent:\n  add_files: null\n"},
		{name: "LFS input", source: "../shared/config", payload: "version https://git-lfs.github.com/spec/v1\n", invalid: true},
		{
			name:     "recursive glob finds nested LFS input",
			manifest: "target: board\ncontent:\n  add_files:\n    - path: /etc/config\n      source_glob: ../shared/data/**/*.bin\n",
			invalid:  true,
			extraFiles: map[string]string{
				"shared/data/a/ok.bin":    "config",
				"shared/data/a/b/big.bin": "version https://git-lfs.github.com/spec/v1\n",
			},
		},
		{
			name:     "empty glob allowed",
			manifest: "target: board\ncontent:\n  add_files:\n    - path: /etc/config\n      source_glob: ../shared/missing/*.bin\n      allow_empty: true\n",
		},
		{name: "dangling symlink", source: "../shared/config", invalid: true, danglingSymlink: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, ".caib-source", "repository")
			for _, p := range []string{"images", "shared"} {
				if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(p, content string) {
				t.Helper()
				if err := os.WriteFile(p, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			manifest := tt.manifest
			if manifest == "" {
				manifest = "target: board\ncontent:\n  add_files:\n    - path: /etc/config\n      source_path: " + tt.source + "\n"
			}
			write(filepath.Join(root, "images", "demo.aib.yml"), manifest)
			payload := tt.payload
			if payload == "" {
				payload = "config"
			}
			write(filepath.Join(root, "shared", "config"), payload)
			for path, content := range tt.extraFiles {
				file := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				write(file, content)
			}
			if tt.danglingSymlink {
				if err := os.Symlink("missing", filepath.Join(root, "shared", "broken")); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(dir, ".caib-source", "commit"), strings.Repeat("a", 40))
			if tt.lock != "" {
				write(filepath.Join(root, "images", "demo.aib.lock"), tt.lock)
			}
			results := filepath.Join(dir, "results")
			if err := os.Mkdir(results, 0700); err != nil {
				t.Fatal(err)
			}
			body := strings.Replace(PrepareGitSourceScript, `Path("/tekton/results")`, `Path(os.environ["TEST_RESULTS"])`, 1)
			cmd := exec.Command(python, "-c", body)
			cmd.Env = append(os.Environ(), "SOURCE_WORKSPACE="+dir, "SOURCE_MANIFEST=images/demo.aib.yml", "SOURCE_LOCKFILE="+tt.lockfilePath, "TEST_RESULTS="+results)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tt.invalid {
				t.Fatalf("error=%v output=%s", err, out)
			}
			if !tt.invalid {
				lockfilePath, err := os.ReadFile(filepath.Join(dir, ".caib-source", "lockfile-path"))
				if err != nil {
					t.Fatal(err)
				}
				want := tt.lockfilePath
				if want == "" {
					want = "images/demo.aib.lock"
				}
				if string(lockfilePath) != want {
					t.Fatalf("selected lockfile = %q, want %q", lockfilePath, want)
				}
				assertGitLockfileMetadata(t, dir, string(out), want, tt.committedLock)
				target, err := os.ReadFile(filepath.Join(results, "target"))
				if err != nil || string(target) != "board" {
					t.Fatalf("target=%q error=%v", target, err)
				}
			}
		})
	}
}

func TestPrepareGitSourceRejectsSymlinkedManifestPath(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	if err := exec.Command(python, "-c", "import yaml").Run(); err != nil {
		t.Skip("PyYAML unavailable")
	}
	for _, manifestPath := range []string{"images/link.aib.yml", "images/linked-dir/real.aib.yml"} {
		t.Run(manifestPath, func(t *testing.T) {
			workspace := t.TempDir()
			root := filepath.Join(workspace, ".caib-source", "repository")
			for _, directory := range []string{filepath.Join(root, "images"), filepath.Join(root, "deep", "dir"), filepath.Join(workspace, "results")} {
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			realManifest := filepath.Join(root, "deep", "dir", "real.aib.yml")
			if err := os.WriteFile(realManifest, []byte("target: board\ncontent:\n  add_files:\n    - path: /etc/commit\n      source_path: ../../commit\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../deep/dir/real.aib.yml", filepath.Join(root, "images", "link.aib.yml")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../deep/dir", filepath.Join(root, "images", "linked-dir")); err != nil {
				t.Fatal(err)
			}
			body := strings.Replace(PrepareGitSourceScript, `Path("/tekton/results")`, `Path(os.environ["TEST_RESULTS"])`, 1)
			cmd := exec.Command(python, "-c", body)
			cmd.Env = append(os.Environ(), "SOURCE_WORKSPACE="+workspace, "SOURCE_MANIFEST="+manifestPath, "TEST_RESULTS="+filepath.Join(workspace, "results"))
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "Git manifest path must not contain symlinks") {
				t.Fatalf("symlinked manifest was accepted: %v %s", err, out)
			}
		})
	}
}

func TestDiscoverGitSourceTarget(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	if err := exec.Command(python, "-c", "import yaml").Run(); err != nil {
		t.Skip("PyYAML unavailable")
	}
	for _, tt := range []struct {
		name, manifest, want string
	}{
		{name: "manifest target", manifest: "target: board\n", want: "board"},
		{name: "default target", manifest: "name: demo\n", want: "qemu"},
		{name: "invalid target", manifest: "target: [board]\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			workspace := t.TempDir()
			source := filepath.Join(workspace, ".caib-source")
			results := filepath.Join(workspace, "results")
			for _, path := range []string{source, results} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(source, "manifest"), []byte(tt.manifest), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "commit"), []byte(strings.Repeat("a", 40)), 0600); err != nil {
				t.Fatal(err)
			}
			body := strings.Replace(PrepareGitSourceScript, `Path("/tekton/results")`, `Path(os.environ["TEST_RESULTS"])`, 1)
			cmd := exec.Command(python, "-c", body)
			cmd.Env = append(os.Environ(), "SOURCE_WORKSPACE="+workspace, "SOURCE_MANIFEST=demo.aib.yml", "SOURCE_DISCOVERY=true", "TEST_RESULTS="+results)
			out, err := cmd.CombinedOutput()
			if tt.want == "" {
				if err == nil {
					t.Fatalf("invalid target accepted: %s", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("discover target: %v %s", err, out)
			}
			got, err := os.ReadFile(filepath.Join(results, "target"))
			if err != nil || string(got) != tt.want {
				t.Fatalf("target=%q err=%v", got, err)
			}
		})
	}
}
