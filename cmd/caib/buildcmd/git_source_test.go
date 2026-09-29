package buildcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

func TestReadGitBuildSource(t *testing.T) {
	url := "https://git.example.com/os.git"
	ref := "release"
	h := NewHandler(Options{Build: &commandopts.Build{GitURL: url, GitRef: ref}})
	data, source, err := h.readBuildSource("does-not-exist/demo.aib.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 || source.Revision != ref || source.ManifestPath != "does-not-exist/demo.aib.yml" {
		t.Fatalf("unexpected source: %+v", source)
	}
	gitLockfile := "./locks/release.json"
	h.opts.Build.GitLockfile = gitLockfile
	if _, source, err := h.readBuildSource("demo.aib.yml"); err != nil || source.LockfilePath != "locks/release.json" {
		t.Fatalf("Git lockfile selection: %+v, %v", source, err)
	}
	lock := "local.lock"
	h.opts.Build.Lockfile = lock
	if _, _, err := h.readBuildSource("demo.aib.yml"); err == nil || !strings.Contains(err.Error(), "commit demo.aib.lock beside the manifest") {
		t.Fatalf("local lockfile override: %v", err)
	}
}

func TestGitLockfileRequiresGitURL(t *testing.T) {
	lockfile := "locks/release.json"
	_, _, err := NewHandler(Options{Build: &commandopts.Build{GitLockfile: lockfile}}).readBuildSource("demo.aib.yml")
	if err == nil || !strings.Contains(err.Error(), "--git-lockfile require --git-url") {
		t.Fatalf("missing Git URL: %v", err)
	}
}

func TestReadLocalBuildSource(t *testing.T) {
	p := filepath.Join(t.TempDir(), "demo.aib.yml")
	if err := os.WriteFile(p, []byte("name: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, source, err := NewHandler(Options{}).readBuildSource(p)
	if err != nil || source != nil || string(data) != "name: demo\n" {
		t.Fatalf("local source changed: %q, %+v, %v", data, source, err)
	}
}

func TestDeferGitDefaults(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("target", "qemu", "")
	cmd.Flags().String("arch", "arm64", "")
	cmd.Flags().String("format", "qcow2", "")
	if err := cmd.Flags().Set("arch", "amd64"); err != nil {
		t.Fatal(err)
	}
	req := buildcontract.BuildRequest{GitSource: &api.GitSource{}, Target: "qemu", Architecture: "amd64", ExportFormat: "qcow2"}
	deferGitDefaults(cmd, &req)
	if req.Target != "" || req.Architecture != "amd64" || req.ExportFormat != "" {
		t.Fatalf("defaults: %+v", req)
	}
	if req.ArchitectureFallback != "" {
		t.Fatalf("explicit architecture gained a fallback: %+v", req)
	}
	cmd2 := &cobra.Command{}
	cmd2.Flags().String("target", "qemu", "")
	cmd2.Flags().String("arch", "amd64", "")
	cmd2.Flags().String("format", "qcow2", "")
	cmd2.Flags().String("disk-format", "qcow2", "")
	req2 := buildcontract.BuildRequest{GitSource: &api.GitSource{}, Target: "qemu", Architecture: "amd64", ExportFormat: "qcow2"}
	deferGitDefaults(cmd2, &req2)
	if req2.Target != "" || req2.Architecture != "" || req2.ArchitectureFallback != "amd64" || req2.ExportFormat != "" {
		t.Fatalf("host fallback was not deferred: %+v", req2)
	}
}
