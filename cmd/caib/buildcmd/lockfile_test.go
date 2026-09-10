package buildcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLockfile(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		valid         bool
	}{
		{"valid", "{\n  \"version\": 1\n}\n", true},
		{"empty", "", false},
		{"invalid", "version: 1", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.lock")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := NewHandler(Options{Lockfile: &path}).readLockfile()
			if (err == nil) != tt.valid {
				t.Fatalf("error = %v, valid = %v", err, tt.valid)
			}
			if tt.valid && got != tt.content {
				t.Fatal("lockfile contents changed")
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.lock")
		if _, err := NewHandler(Options{Lockfile: &path}).readLockfile(); err == nil {
			t.Fatal("expected read error")
		}
	})
	t.Run("omitted", func(t *testing.T) {
		got, err := NewHandler(Options{}).readLockfile()
		if err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}
