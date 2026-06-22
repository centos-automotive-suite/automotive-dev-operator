package featuregates

import (
	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

// Gates evaluates feature state from OperatorConfig overrides + compile-time defaults.
type Gates struct {
	overrides map[FeatureName]bool
}

// New creates Gates from explicit overrides. Prefer NewFromConfig for controller use.
func New(overrides map[FeatureName]bool) *Gates {
	return &Gates{overrides: overrides}
}

// NewFromConfig creates Gates from an OperatorConfigSpec.
// Nil spec is safe — all features use defaults.
func NewFromConfig(spec *automotivev1alpha1.OperatorConfigSpec) *Gates {
	overrides := make(map[FeatureName]bool)
	if spec != nil {
		for name, enabled := range spec.FeatureGates {
			feature := FeatureName(name)
			if !Known(feature) {
				continue
			}
			overrides[feature] = enabled
		}
	}
	return &Gates{overrides: overrides}
}

// Enabled returns whether a feature is enabled.
//
// Evaluation order:
//  1. GA features are always enabled (overrides ignored)
//  2. Explicit override from OperatorConfig.spec.featureGates
//  3. Default: Alpha=false, Beta=true
func (g *Gates) Enabled(name FeatureName) bool {
	stage := DefaultStage(name)

	if stage == GA {
		return true
	}

	if override, ok := g.overrides[name]; ok {
		return override
	}

	return stage == Beta
}
