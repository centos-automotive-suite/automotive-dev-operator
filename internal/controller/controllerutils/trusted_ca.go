// Package controllerutils contains shared helpers used across controllers.
package controllerutils

import (
	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

// ApplyTrustedCABundleFromOSBuilds maps trusted CA bundle config into task build config.
func ApplyTrustedCABundleFromOSBuilds(buildConfig *tasks.BuildConfig, osBuilds *automotivev1alpha1.OSBuildsConfig) {
	if buildConfig == nil || osBuilds == nil || osBuilds.Certificates == nil {
		return
	}

	if osBuilds.Certificates.TrustedCABundle != nil {
		buildConfig.TrustedCABundleKind = osBuilds.Certificates.TrustedCABundle.Kind
		buildConfig.TrustedCABundleName = osBuilds.Certificates.TrustedCABundle.Name
	}
}
