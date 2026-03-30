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
