// Package featuregates provides a Kubernetes-style feature gate mechanism for the operator.
// Features progress through Alpha (default OFF) → Beta (default ON) → GA (always ON).
// Cluster admins override defaults via OperatorConfig.spec.featureGates.
package featuregates

// Stage represents a feature's maturity level.
type Stage string

// Feature lifecycle stages.
const (
	Alpha Stage = "Alpha"
	Beta  Stage = "Beta"
	GA    Stage = "GA"
)

// FeatureName is a typed string for feature gate names.
type FeatureName string

// FeatureSpec describes a feature's default lifecycle stage.
type FeatureSpec struct {
	Stage Stage
}

// defaultFeatures is the compile-time registry of known features and their
// default stages. Each feature PR adds its own entry here.
var defaultFeatures = map[FeatureName]FeatureSpec{}

// Register adds a feature to the default registry. Intended for use in init()
// functions within the package that implements the feature, or directly in this
// map literal. Panics on duplicate registration.
func Register(name FeatureName, spec FeatureSpec) {
	if _, exists := defaultFeatures[name]; exists {
		panic("duplicate feature gate registration: " + string(name))
	}
	defaultFeatures[name] = spec
}

// Known returns true if the feature name is registered.
func Known(name FeatureName) bool {
	_, ok := defaultFeatures[name]
	return ok
}

// DefaultStage returns the default stage for a registered feature.
// Returns Alpha for unknown features (safe default: disabled).
func DefaultStage(name FeatureName) Stage {
	if spec, ok := defaultFeatures[name]; ok {
		return spec.Stage
	}
	return Alpha
}
