package buildapi

import (
	"testing"
)

func TestManifestNeedsUpload(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     bool
	}{
		{
			name:     "no add_files",
			manifest: "name: simple\n",
			want:     false,
		},
		{
			name: "add_files with source_path",
			manifest: `content:
  add_files:
    - source_path: my-app
      dest: /usr/bin/my-app
`,
			want: true,
		},
		{
			name: "add_files with source only",
			manifest: `content:
  add_files:
    - source: config.toml
      dest: /etc/my-app/config.toml
`,
			want: false,
		},
		{
			name: "qm section with source_path",
			manifest: `qm:
  content:
    add_files:
      - source_path: qm-app
        dest: /usr/bin/qm-app
`,
			want: true,
		},
		{
			name:     "invalid yaml returns false",
			manifest: "{{invalid yaml",
			want:     false,
		},
		{
			name: "add_files with source_glob only",
			manifest: `content:
  add_files:
    - source_glob: "*.rpm"
      dest: /tmp/rpms/
`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := manifestNeedsUpload(tt.manifest)
			if got != tt.want {
				t.Errorf("manifestNeedsUpload() = %v, want %v", got, tt.want)
			}
		})
	}
}
