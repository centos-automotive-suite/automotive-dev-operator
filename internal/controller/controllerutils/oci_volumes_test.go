package controllerutils

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
)

func TestApplyOCIVolumesConfig_NilBuildConfig(_ *testing.T) {
	spec := &automotivev1alpha1.OperatorConfigSpec{
		FeatureGates: map[string]bool{string(featuregates.OCIVolumes): true},
	}
	ApplyOCIVolumesConfig(nil, spec)
}

func TestApplyOCIVolumesConfig_NilSpec(t *testing.T) {
	cfg := &tasks.BuildConfig{}
	ApplyOCIVolumesConfig(cfg, nil)
	if cfg.UseOCIVolumes {
		t.Fatal("UseOCIVolumes should remain false with nil spec")
	}
}

func TestApplyOCIVolumesConfig_GateDisabled(t *testing.T) {
	cfg := &tasks.BuildConfig{}
	spec := &automotivev1alpha1.OperatorConfigSpec{}
	ApplyOCIVolumesConfig(cfg, spec)
	if cfg.UseOCIVolumes {
		t.Fatal("UseOCIVolumes should be false when gate is not enabled")
	}
	if cfg.OrasImage != "" {
		t.Fatalf("OrasImage = %q, want empty", cfg.OrasImage)
	}
}

func TestApplyOCIVolumesConfig_GateEnabled_DefaultImage(t *testing.T) {
	cfg := &tasks.BuildConfig{}
	spec := &automotivev1alpha1.OperatorConfigSpec{
		FeatureGates: map[string]bool{string(featuregates.OCIVolumes): true},
	}
	ApplyOCIVolumesConfig(cfg, spec)
	if !cfg.UseOCIVolumes {
		t.Fatal("UseOCIVolumes should be true when gate is enabled")
	}
	if cfg.OrasImage != automotivev1alpha1.DefaultOrasImage {
		t.Fatalf("OrasImage = %q, want default %q", cfg.OrasImage, automotivev1alpha1.DefaultOrasImage)
	}
}

func TestApplyOCIVolumesConfig_GateEnabled_CustomImage(t *testing.T) {
	custom := "registry.example.com/oras:custom"
	cfg := &tasks.BuildConfig{}
	spec := &automotivev1alpha1.OperatorConfigSpec{
		FeatureGates: map[string]bool{string(featuregates.OCIVolumes): true},
		Images: &automotivev1alpha1.ImagesConfig{
			Oras: custom,
		},
	}
	ApplyOCIVolumesConfig(cfg, spec)
	if !cfg.UseOCIVolumes {
		t.Fatal("UseOCIVolumes should be true")
	}
	if cfg.OrasImage != custom {
		t.Fatalf("OrasImage = %q, want %q", cfg.OrasImage, custom)
	}
}
