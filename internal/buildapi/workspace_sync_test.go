package buildapi

import (
	"strings"
	"testing"
)

func TestValidateWorkspaceRelPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "src/main.go", false},
		{"dots in name", "notes..old", false},
		{"nested dots in name", "dir/foo..bar.txt", false},
		{"empty", "", true},
		{"absolute", "/etc/passwd", true},
		{"parent", "..", true},
		{"parent prefix", "../etc/passwd", true},
		{"mid traversal escapes", "foo/../../etc/passwd", true},
		{"dot only", ".", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkspaceRelPath(tt.input)
			if tt.wantErr && err == nil {
				t.Fatalf("validateWorkspaceRelPath(%q) expected error", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateWorkspaceRelPath(%q) unexpected error: %v", tt.input, err)
			}
		})
	}
}

func TestBuildSyncDeleteScript(t *testing.T) {
	script := buildSyncDeleteScript([]string{"pkg/foo.go", "-rf", "notes..old"})
	for _, want := range []string{
		"set -e",
		"cd /workspace/src || exit 1",
		"rm -f -- 'pkg/foo.go'",
		"rm -f -- '-rf'",
		"rm -f -- 'notes..old'",
		"dirname -- 'pkg/foo.go'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q\n%s", want, script)
		}
	}
	if strings.Contains(script, "find /workspace/src") {
		t.Error("script must not prune all empty directories under src")
	}
	if strings.HasSuffix(strings.TrimSpace(script), "true") {
		t.Error("script must not mask failures with trailing true")
	}
}
