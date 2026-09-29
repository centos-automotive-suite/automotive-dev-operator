package buildcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCustomDefs_FileThenInline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vars.yaml")
	if err := os.WriteFile(path, []byte("routing: Proxy\nverbose: true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := newTestDiskOpts()
	opts.Build.DefineFiles = []string{path}
	opts.Build.CustomDefs = []string{"routing=Engine"}

	h := NewHandler(opts)
	got, err := h.resolveCustomDefs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File defines first, inline after — inline "routing=Engine" comes last
	want := []string{`routing="Proxy"`, `verbose=true`, `routing=Engine`}
	if len(got) != len(want) {
		t.Fatalf("got %d items, want %d: %v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
