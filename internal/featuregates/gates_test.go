package featuregates

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

const (
	testAlpha FeatureName = "TestAlphaFeature"
	testBeta  FeatureName = "TestBetaFeature"
	testGA    FeatureName = "TestGAFeature"
)

func setupTestFeatures(t *testing.T) {
	t.Helper()
	saved := make(map[FeatureName]FeatureSpec, len(defaultFeatures))
	for k, v := range defaultFeatures {
		saved[k] = v
	}
	t.Cleanup(func() {
		defaultFeatures = saved
	})

	defaultFeatures[testAlpha] = FeatureSpec{Stage: Alpha}
	defaultFeatures[testBeta] = FeatureSpec{Stage: Beta}
	defaultFeatures[testGA] = FeatureSpec{Stage: GA}
}

func TestDefaults(t *testing.T) {
	setupTestFeatures(t)
	g := New(nil)

	tests := []struct {
		name    string
		feature FeatureName
		want    bool
	}{
		{"alpha defaults to disabled", testAlpha, false},
		{"beta defaults to enabled", testBeta, true},
		{"GA always enabled", testGA, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := g.Enabled(tt.feature); got != tt.want {
				t.Errorf("Enabled(%s) = %v, want %v", tt.feature, got, tt.want)
			}
		})
	}
}

func TestOverrides(t *testing.T) {
	setupTestFeatures(t)

	tests := []struct {
		name    string
		feature FeatureName
		enable  bool
		want    bool
	}{
		{"enable alpha via override", testAlpha, true, true},
		{"disable beta via override", testBeta, false, false},
		{"GA ignores disable override", testGA, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(map[FeatureName]bool{tt.feature: tt.enable})
			if got := g.Enabled(tt.feature); got != tt.want {
				t.Errorf("Enabled(%s) = %v, want %v", tt.feature, got, tt.want)
			}
		})
	}
}

func TestNewFromConfig(t *testing.T) {
	setupTestFeatures(t)

	tests := []struct {
		name    string
		spec    *automotivev1alpha1.OperatorConfigSpec
		feature FeatureName
		want    bool
	}{
		{
			"nil spec uses defaults",
			nil,
			testAlpha,
			false,
		},
		{
			"empty featureGates uses defaults",
			&automotivev1alpha1.OperatorConfigSpec{},
			testBeta,
			true,
		},
		{
			"enable alpha from config",
			&automotivev1alpha1.OperatorConfigSpec{
				FeatureGates: map[string]bool{string(testAlpha): true},
			},
			testAlpha,
			true,
		},
		{
			"disable beta from config",
			&automotivev1alpha1.OperatorConfigSpec{
				FeatureGates: map[string]bool{string(testBeta): false},
			},
			testBeta,
			false,
		},
		{
			"GA stays enabled despite config override",
			&automotivev1alpha1.OperatorConfigSpec{
				FeatureGates: map[string]bool{string(testGA): false},
			},
			testGA,
			true,
		},
		{
			"unknown feature in config is ignored",
			&automotivev1alpha1.OperatorConfigSpec{
				FeatureGates: map[string]bool{"UnknownFeature": true},
			},
			FeatureName("UnknownFeature"),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewFromConfig(tt.spec)
			if got := g.Enabled(tt.feature); got != tt.want {
				t.Errorf("Enabled(%s) = %v, want %v", tt.feature, got, tt.want)
			}
		})
	}
}

func TestUnknownFeature(t *testing.T) {
	setupTestFeatures(t)
	g := New(nil)
	if g.Enabled("NonExistentFeature") {
		t.Error("unknown feature should default to disabled (Alpha)")
	}
}

func TestKnown(t *testing.T) {
	setupTestFeatures(t)

	if !Known(testAlpha) {
		t.Error("registered feature should be known")
	}
	if Known("NonExistentFeature") {
		t.Error("unregistered feature should not be known")
	}
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	setupTestFeatures(t)

	defer func() {
		if r := recover(); r == nil {
			t.Error("duplicate Register should panic")
		}
	}()

	Register(testAlpha, FeatureSpec{Stage: Alpha})
}
