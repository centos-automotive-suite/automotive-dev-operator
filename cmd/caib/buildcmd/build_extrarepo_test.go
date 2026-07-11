package buildcmd

import (
	"strings"
	"testing"
)

func TestSplitExtraRepos(t *testing.T) {
	tests := []struct {
		name           string
		input          []string
		wantWorkspace  []string
		wantOCI        []string
		wantErrContain string
	}{
		{
			name:          "nil input",
			input:         nil,
			wantWorkspace: nil,
			wantOCI:       nil,
		},
		{
			name:          "empty input",
			input:         []string{},
			wantWorkspace: nil,
			wantOCI:       nil,
		},
		{
			name:          "workspace only",
			input:         []string{"myworkspace:/rpms"},
			wantWorkspace: []string{"myworkspace:/rpms"},
			wantOCI:       nil,
		},
		{
			name:          "oci only",
			input:         []string{"oci:quay.io/org/rpms:v1"},
			wantWorkspace: nil,
			wantOCI:       []string{"quay.io/org/rpms:v1"},
		},
		{
			name:          "mixed entries",
			input:         []string{"myworkspace:/rpms", "oci:quay.io/org/rpms:v1", "otherws:/extra"},
			wantWorkspace: []string{"myworkspace:/rpms", "otherws:/extra"},
			wantOCI:       []string{"quay.io/org/rpms:v1"},
		},
		{
			name:           "oci with empty ref",
			input:          []string{"oci:"},
			wantErrContain: "requires an image reference",
		},
		{
			name:          "oci with port in registry",
			input:         []string{"oci:registry.example.com:5000/rpms:v1"},
			wantWorkspace: nil,
			wantOCI:       []string{"registry.example.com:5000/rpms:v1"},
		},
		{
			name:          "multiple oci entries",
			input:         []string{"oci:quay.io/org/rpms:v1", "oci:quay.io/org/rpms2:latest"},
			wantWorkspace: nil,
			wantOCI:       []string{"quay.io/org/rpms:v1", "quay.io/org/rpms2:latest"},
		},
		{
			name:          "entry without prefix treated as workspace",
			input:         []string{"/local/path"},
			wantWorkspace: []string{"/local/path"},
			wantOCI:       nil,
		},
		{
			name:          "oci with digest ref",
			input:         []string{"oci:quay.io/org/rpms@sha256:abcdef1234567890"},
			wantWorkspace: nil,
			wantOCI:       []string{"quay.io/org/rpms@sha256:abcdef1234567890"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workspace, oci, err := splitExtraRepos(tt.input)

			if tt.wantErrContain != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrContain)
				}
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErrContain, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !slicesEqual(workspace, tt.wantWorkspace) {
				t.Errorf("workspace repos = %v, want %v", workspace, tt.wantWorkspace)
			}
			if !slicesEqual(oci, tt.wantOCI) {
				t.Errorf("OCI images = %v, want %v", oci, tt.wantOCI)
			}
		})
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
