package imagebuild

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
)

func TestApplyTrustedCABundleFromOSBuilds_ImageBuild(t *testing.T) {
	tests := []struct {
		name     string
		osBuilds *automotivev1alpha1.OSBuildsConfig
		wantKind string
		wantName string
	}{
		{
			name:     "nil osBuilds",
			osBuilds: nil,
		},
		{
			name:     "nil certificates",
			osBuilds: &automotivev1alpha1.OSBuildsConfig{},
		},
		{
			name: "configmap trusted bundle",
			osBuilds: &automotivev1alpha1.OSBuildsConfig{
				Certificates: &automotivev1alpha1.BuildCertificatesConfig{
					TrustedCABundle: &automotivev1alpha1.CertificateSourceRef{
						Kind: "ConfigMap",
						Name: "my-test-ca",
					},
				},
			},
			wantKind: "ConfigMap",
			wantName: "my-test-ca",
		},
		{
			name: "secret trusted bundle",
			osBuilds: &automotivev1alpha1.OSBuildsConfig{
				Certificates: &automotivev1alpha1.BuildCertificatesConfig{
					TrustedCABundle: &automotivev1alpha1.CertificateSourceRef{
						Kind: "Secret",
						Name: "my-test-ca-secret",
					},
				},
			},
			wantKind: "Secret",
			wantName: "my-test-ca-secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buildCfg := &tasks.BuildConfig{}
			controllerutils.ApplyTrustedCABundleFromOSBuilds(buildCfg, tc.osBuilds)
			if buildCfg.TrustedCABundleKind != tc.wantKind {
				t.Fatalf("kind mismatch: got %q want %q", buildCfg.TrustedCABundleKind, tc.wantKind)
			}
			if buildCfg.TrustedCABundleName != tc.wantName {
				t.Fatalf("name mismatch: got %q want %q", buildCfg.TrustedCABundleName, tc.wantName)
			}
		})
	}
}
