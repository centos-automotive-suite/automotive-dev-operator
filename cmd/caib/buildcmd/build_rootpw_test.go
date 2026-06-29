package buildcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRootPassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		envVars map[string]string
		files   map[string]string
		want    string
		wantErr bool
	}{
		{
			name:  "env prefix resolves environment variable",
			input: "env:ROOT_PW_HASH",
			envVars: map[string]string{
				"ROOT_PW_HASH": "$6$salt$hashvalue",
			},
			want: "$6$salt$hashvalue",
		},
		{
			name:    "env prefix with missing variable returns error",
			input:   "env:NONEXISTENT_VAR",
			wantErr: true,
		},
		{
			name:  "file prefix reads from file",
			input: "file:PLACEHOLDER",
			files: map[string]string{
				"root-pw.txt": "$6$rounds=5000$salt$longhashvalue\n",
			},
			want: "$6$rounds=5000$salt$longhashvalue",
		},
		{
			name:    "file prefix with missing file returns error",
			input:   "file:/nonexistent/path/to/file",
			wantErr: true,
		},
		{
			name:    "no prefix returns error",
			input:   "$6$salt$hashvalue",
			wantErr: true,
		},
		{
			name:    "empty string returns error",
			input:   "",
			wantErr: true,
		},
		{
			name:    "unknown prefix returns error",
			input:   "secret:my-secret",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			if len(tt.files) > 0 {
				dir := t.TempDir()
				for name, content := range tt.files {
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, []byte(content), 0644); err != nil {
						t.Fatal(err)
					}
					if tt.input == "file:PLACEHOLDER" {
						tt.input = "file:" + path
					}
				}
			}

			got, err := parseRootPassword(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
