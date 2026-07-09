package controllerutils

import (
	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
)

// ApplyOCIVolumesConfig enables OCI volume mounts on the build config when the OCIVolumes feature gate is active.
func ApplyOCIVolumesConfig(buildConfig *tasks.BuildConfig, spec *automotivev1alpha1.OperatorConfigSpec) {
	if buildConfig == nil || spec == nil {
		return
	}
	gates := featuregates.NewFromConfig(spec)
	if gates.Enabled(featuregates.OCIVolumes) {
		buildConfig.UseOCIVolumes = true
		buildConfig.OrasImage = spec.GetImages().GetOrasImage()
	}
}
