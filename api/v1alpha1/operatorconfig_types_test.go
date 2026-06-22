package v1alpha1

import (
	"testing"

	"k8s.io/utils/ptr"
)

func TestGetUsePVCScratchVolumes_NilDefaultsToTrue(t *testing.T) {
	cfg := &OSBuildsConfig{}
	if !cfg.GetUsePVCScratchVolumes() {
		t.Fatal("nil UsePVCScratchVolumes should default to true")
	}
}

func TestGetUsePVCScratchVolumes_ExplicitTrue(t *testing.T) {
	cfg := &OSBuildsConfig{UsePVCScratchVolumes: ptr.To(true)}
	if !cfg.GetUsePVCScratchVolumes() {
		t.Fatal("explicit true should return true")
	}
}

func TestGetUsePVCScratchVolumes_ExplicitFalse(t *testing.T) {
	cfg := &OSBuildsConfig{UsePVCScratchVolumes: ptr.To(false)}
	if cfg.GetUsePVCScratchVolumes() {
		t.Fatal("explicit false should return false")
	}
}

func TestGetDefaultLeaseTags_NilConfig(t *testing.T) {
	var cfg *JumpstarterConfig
	if cfg.GetDefaultLeaseTags() != DefaultFlashLeaseTags {
		t.Fatal("nil JumpstarterConfig should return fallback")
	}
}

func TestGetDefaultLeaseTags_EmptyDefault(t *testing.T) {
	cfg := &JumpstarterConfig{}
	if cfg.GetDefaultLeaseTags() != DefaultFlashLeaseTags {
		t.Fatal("empty DefaultLeaseTags should return fallback")
	}
}

func TestGetDefaultLeaseTags_ExplicitValue(t *testing.T) {
	cfg := &JumpstarterConfig{DefaultLeaseTags: "platform=caib,cluster=prod"}
	if cfg.GetDefaultLeaseTags() != "platform=caib,cluster=prod" {
		t.Fatalf("got %q, want platform=caib,cluster=prod", cfg.GetDefaultLeaseTags())
	}
}

func TestIsImageAllowed(t *testing.T) {
	tests := []struct {
		name        string
		config      *WorkspacesConfig
		image       string
		wantAllowed bool
	}{
		{
			name:        "toolchain image always allowed with nil config",
			config:      nil,
			image:       DefaultToolchainImage,
			wantAllowed: true,
		},
		{
			name:        "toolchain image always allowed with empty allowedImages",
			config:      &WorkspacesConfig{},
			image:       DefaultToolchainImage,
			wantAllowed: true,
		},
		{
			name:        "custom image rejected when allowedImages empty",
			config:      &WorkspacesConfig{},
			image:       "quay.io/evil/image:latest",
			wantAllowed: false,
		},
		{
			name:        "custom image rejected with nil config",
			config:      nil,
			image:       "quay.io/evil/image:latest",
			wantAllowed: false,
		},
		{
			name:        "exact match allowed",
			config:      &WorkspacesConfig{AllowedImages: []string{"quay.io/myorg/toolchain:v1"}},
			image:       "quay.io/myorg/toolchain:v1",
			wantAllowed: true,
		},
		{
			name:        "exact match rejected when not in list",
			config:      &WorkspacesConfig{AllowedImages: []string{"quay.io/myorg/toolchain:v1"}},
			image:       "quay.io/myorg/toolchain:v2",
			wantAllowed: false,
		},
		{
			name:        "glob prefix match allowed",
			config:      &WorkspacesConfig{AllowedImages: []string{"quay.io/myorg/*"}},
			image:       "quay.io/myorg/custom:latest",
			wantAllowed: true,
		},
		{
			name:        "glob prefix no match",
			config:      &WorkspacesConfig{AllowedImages: []string{"quay.io/myorg/*"}},
			image:       "quay.io/evil/image:latest",
			wantAllowed: false,
		},
		{
			name:        "configured toolchain image allowed even when different from default",
			config:      &WorkspacesConfig{ToolchainImage: "registry.example.com/custom-toolchain:v1"},
			image:       "registry.example.com/custom-toolchain:v1",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsImageAllowed(tt.image)
			if got != tt.wantAllowed {
				t.Errorf("IsImageAllowed(%q) = %v, want %v", tt.image, got, tt.wantAllowed)
			}
		})
	}
}
