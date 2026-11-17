package imagebuild

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func TestArtifactNamePipelineParameter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		export *automotivev1alpha1.ExportSpec
		want   string
	}{
		{"unset", nil, ""},
		{"set", &automotivev1alpha1.ExportSpec{ArtifactName: "auto-osbuild-qemu-x86_64-1.abc"}, "auto-osbuild-qemu-x86_64-1.abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := &automotivev1alpha1.ImageBuild{Spec: automotivev1alpha1.ImageBuildSpec{Export: tc.export}}
			for _, param := range baseParams(build, &automotivev1alpha1.OperatorConfig{}, "", nil, nil) {
				if param.Name == "artifact-name" {
					if param.Value.StringVal != tc.want {
						t.Fatalf("artifact-name = %q, want %q", param.Value.StringVal, tc.want)
					}
					return
				}
			}
			t.Fatal("missing artifact-name parameter")
		})
	}
}
