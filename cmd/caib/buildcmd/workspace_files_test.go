package buildcmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestStripExecStream(t *testing.T) {
	got, err := stripExecStream([]byte(execStreamPreamble + "posix-hydrate-ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "posix-hydrate-ok\n" {
		t.Fatalf("got %q", got)
	}

	_, err = stripExecStream([]byte(execStreamPreamble + "\n[exec failed: command terminated with exit code 1]\n"))
	if err == nil {
		t.Fatal("expected exec failure")
	}
}

func TestStripExecStream_BinaryContainsSentinel(t *testing.T) {
	payload := []byte{0x00, 0x7f, 0x01}
	payload = append(payload, []byte("\n[exec failed: fake]")...)
	payload = append(payload, 0x02, 0x03)
	raw := append([]byte(execStreamPreamble), payload...)
	got, err := stripExecStream(raw)
	if err != nil {
		t.Fatalf("mid-file sentinel must not error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("binary payload mutated: got %q", got)
	}
}

func TestMaterializeWorkspaceFiles_RepoOnlyLeavesFileURLs(t *testing.T) {
	h := &Handler{}
	manifest := "content:\n  repos:\n    - id: local\n      baseurl: file:///workspace/src/bin\n"
	got, refs, err := h.materializeWorkspaceFiles(context.Background(), nil, "posix-bake", manifest)
	if err != nil {
		t.Fatalf("repo-only --workspace manifest should not error: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("refs = %d, want 0 (server rewrites file:// repos)", len(refs))
	}
	if !strings.Contains(got, "file:///workspace/src/bin") {
		t.Fatalf("file:// repo should be left for the server, got:\n%s", got)
	}
}
