package workspaceagent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func symlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func wantAgentError(t *testing.T, err error, code int, parts ...string) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != code {
		t.Fatalf("error = %v, want HTTP %d", err, code)
	}
	for _, part := range parts {
		if !strings.Contains(apiErr.Message, part) {
			t.Errorf("error %q does not mention %q", apiErr.Message, part)
		}
	}
}

// Refs name files the way AIB's add_files do, and match what Python's
// os.walk and glob.glob(recursive=True) find: directories are walked without
// entering linked directories, and wildcards skip hidden names unless the
// pattern names them.
func TestListFilesFindsFilesDirectoriesAndGlobs(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workspace, map[string]string{
		"src/app.rpm":       "app",
		"src/pkg/a.rpm":     "a",
		"src/pkg/sub/b.rpm": "b",
		"src/pkg/sub/notes": "notes",
		"src/pkg/.d.rpm":    "hidden file",
		"src/.hidden/c.rpm": "hidden directory",
		"conf/x.conf":       "x",
		"conf/inner/y.conf": "y",
		"elsewhere/z.conf":  "z",
	})
	symlink(t, "../app.rpm", filepath.Join(a.workspace, "src/pkg/link.rpm"))
	symlink(t, "../elsewhere", filepath.Join(a.workspace, "conf/linked"))

	files, err := a.ListFiles(context.Background(), []FileRef{
		{Path: "src/app.rpm"},
		{Path: "conf"},
		{Path: "src/**/*.rpm", Glob: true},
		{Path: "src/pkg/.*.rpm", Glob: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"conf/inner/y.conf",
		"conf/x.conf",
		"src/app.rpm",
		"src/pkg/.d.rpm",
		"src/pkg/a.rpm",
		"src/pkg/link.rpm",
		"src/pkg/sub/b.rpm",
	}
	if !slices.Equal(files, want) {
		t.Errorf("files = %q\nwant    %q", files, want)
	}
}

func TestListFilesFollowsALinkTheRefNames(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workspace, map[string]string{"build/out/x.rpm": "x"})
	symlink(t, "build/out", filepath.Join(a.workspace, "latest"))

	files, err := a.ListFiles(context.Background(), []FileRef{{Path: "latest"}, {Path: "latest/*.rpm", Glob: true}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"latest/x.rpm"}; !slices.Equal(files, want) {
		t.Errorf("files = %q, want %q", files, want)
	}
}

// A build that names files the workspace doesn't have fails at once, listing
// them all, instead of building without them.
func TestListFilesReportsEveryMissingRef(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workspace, map[string]string{"src/a.rpm": "a"})
	if err := os.MkdirAll(filepath.Join(a.workspace, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := a.ListFiles(context.Background(), []FileRef{
		{Path: "src/a.rpm"},
		{Path: "nope"},
		{Path: "src/*.deb", Glob: true},
		{Path: "empty"},
	})
	wantAgentError(t, err, http.StatusUnprocessableEntity, "missing", "nope", "src/*.deb", "empty")
}

// The workspace's files can link anywhere, but a build gets only files whose
// real path is in the workspace.
func TestListFilesRefusesLinksOutOfTheWorkspace(t *testing.T) {
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"secret": "secret", "dir/secret": "secret"})
	for name, ref := range map[string]FileRef{
		"a file link":            {Path: "src/key"},
		"a directory link":       {Path: "src/dir"},
		"a file in a linked dir": {Path: "src/dir/secret"},
		"a glob":                 {Path: "src/*", Glob: true},
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestAgent(t)
			writeTree(t, a.workspace, map[string]string{"src/a.rpm": "a"})
			symlink(t, filepath.Join(outside, "secret"), filepath.Join(a.workspace, "src/key"))
			symlink(t, filepath.Join(outside, "dir"), filepath.Join(a.workspace, "src/dir"))
			_, err := a.ListFiles(context.Background(), []FileRef{ref})
			wantAgentError(t, err, http.StatusUnprocessableEntity, "outside the workspace")
		})
	}
}

func TestListFilesRejectsRefsOutsideTheWorkspace(t *testing.T) {
	a := newTestAgent(t)
	for _, ref := range []FileRef{{Path: ""}, {Path: "../x"}, {Path: "/etc/passwd"}, {Path: "src/../../x", Glob: true}} {
		_, err := a.ListFiles(context.Background(), []FileRef{ref})
		wantAgentError(t, err, http.StatusBadRequest, "invalid path")
	}
}

func TestBuildFilesOverHTTP(t *testing.T) {
	a := newTestAgent(t)
	writeTree(t, a.workspace, map[string]string{"src/my pkg%1.rpm": "rpm bytes", "src/sub/x": "x"})
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"secret": "secret"})
	symlink(t, filepath.Join(outside, "secret"), filepath.Join(a.workspace, "src/key"))
	server := httptest.NewServer(a.Handler("secret", nil))
	defer server.Close()
	client := NewClient(server.URL, "secret", nil)
	ctx := context.Background()

	files, err := client.ListFiles(ctx, []FileRef{{Path: "src/*.rpm", Glob: true}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"src/my pkg%1.rpm"}; !slices.Equal(files, want) {
		t.Fatalf("files = %q, want %q", files, want)
	}
	body, err := client.OpenFile(ctx, files[0])
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil || string(data) != "rpm bytes" {
		t.Errorf("file = %q, %v", data, err)
	}

	_, err = client.ListFiles(ctx, []FileRef{{Path: "nope"}})
	wantAgentError(t, err, http.StatusUnprocessableEntity, "nope")
	for _, name := range []string{"src/key", "src/sub", "nope", "../x"} {
		if body, err := client.OpenFile(ctx, name); err == nil {
			_ = body.Close()
			t.Errorf("opened %s", name)
		}
	}
	if _, err := NewClient(server.URL, "wrong", nil).OpenFile(ctx, "src/sub/x"); err == nil {
		t.Error("opened a file without the token")
	}
}

// AIB globs with Python's fnmatch, whose syntax differs from path.Match.
func TestMatchNameFollowsPythonsFnmatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"*.rpm", "a.rpm", true},
		{"?.rpm", "ab.rpm", false},
		{"[!a]*", "b.rpm", true},
		{"[!a]*", "a.rpm", false},
		{"[^a]*", "^x", true},
		{"[^a]*", "b", false},
		{"[]a]", "]", true},
		{"[-a]", "-", true},
		{"[a-]", "-", true},
		{"[a-c]", "b", true},
		{`a\b`, `a\b`, true},
		{"x[", "x[", true},
		{"x[y", "x[y", true},
	} {
		if got := matchName(tc.pattern, tc.name); got != tc.want {
			t.Errorf("matchName(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}
