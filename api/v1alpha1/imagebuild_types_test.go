package v1alpha1

import (
	"testing"
)

func TestGetFlashLeaseTags(t *testing.T) {
	tests := []struct {
		name string
		spec ImageBuildSpec
		want string
	}{
		{
			name: "returns tags when flash is set",
			spec: ImageBuildSpec{
				Flash: &FlashSpec{LeaseTags: "env=staging,team=platform"},
			},
			want: "env=staging,team=platform",
		},
		{
			name: "returns empty when flash is nil",
			spec: ImageBuildSpec{},
			want: "",
		},
		{
			name: "returns empty when tags are empty",
			spec: ImageBuildSpec{
				Flash: &FlashSpec{},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetFlashLeaseTags()
			if got != tt.want {
				t.Errorf("GetFlashLeaseTags() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetManifest(t *testing.T) {
	tests := []struct {
		name string
		spec ImageBuildSpec
		want string
	}{
		{
			name: "returns manifest when AIB is set",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{
					Manifest: "name: my-build\npackages:\n  - vim\n",
				},
			},
			want: "name: my-build\npackages:\n  - vim\n",
		},
		{
			name: "returns empty string when AIB is nil",
			spec: ImageBuildSpec{},
			want: "",
		},
		{
			name: "returns empty string when manifest is empty",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetManifest()
			if got != tt.want {
				t.Errorf("GetManifest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetManifestFileName(t *testing.T) {
	tests := []struct {
		name string
		spec ImageBuildSpec
		want string
	}{
		{
			name: "returns filename when set",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{
					ManifestFileName: "my-build.aib.yml",
				},
			},
			want: "my-build.aib.yml",
		},
		{
			name: "returns empty string when AIB is nil",
			spec: ImageBuildSpec{},
			want: "",
		},
		{
			name: "returns empty string when filename is empty",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{},
			},
			want: "",
		},
		{
			name: "handles mpp.yml extension",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{
					ManifestFileName: "build.mpp.yml",
				},
			},
			want: "build.mpp.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetManifestFileName()
			if got != tt.want {
				t.Errorf("GetManifestFileName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetCustomDefs(t *testing.T) {
	tests := []struct {
		name string
		spec ImageBuildSpec
		want []string
	}{
		{
			name: "returns custom defs when set",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{
					CustomDefs: []string{"FOO=bar", "BAZ=qux"},
				},
			},
			want: []string{"FOO=bar", "BAZ=qux"},
		},
		{
			name: "returns nil when AIB is nil",
			spec: ImageBuildSpec{},
			want: nil,
		},
		{
			name: "returns nil when custom defs is nil",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{},
			},
			want: nil,
		},
		{
			name: "returns empty slice when custom defs is empty",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{
					CustomDefs: []string{},
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetCustomDefs()
			if tt.want == nil {
				if got != nil {
					t.Errorf("GetCustomDefs() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("GetCustomDefs() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetCustomDefs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGetAIBExtraArgs(t *testing.T) {
	tests := []struct {
		name string
		spec ImageBuildSpec
		want []string
	}{
		{
			name: "returns extra args when set",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{
					AIBExtraArgs: []string{"--verbose", "--no-cache"},
				},
			},
			want: []string{"--verbose", "--no-cache"},
		},
		{
			name: "returns nil when AIB is nil",
			spec: ImageBuildSpec{},
			want: nil,
		},
		{
			name: "returns nil when extra args is nil",
			spec: ImageBuildSpec{
				AIB: &AIBSpec{},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetAIBExtraArgs()
			if tt.want == nil {
				if got != nil {
					t.Errorf("GetAIBExtraArgs() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("GetAIBExtraArgs() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetAIBExtraArgs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
