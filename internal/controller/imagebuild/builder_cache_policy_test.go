package imagebuild

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func TestBuilderCachePolicyPipelineParameter(t *testing.T) {
	for _, policy := range []string{"", "validate", "reuse"} {
		build := &automotivev1alpha1.ImageBuild{Spec: automotivev1alpha1.ImageBuildSpec{AIB: &automotivev1alpha1.AIBSpec{BuilderCachePolicy: policy}}}
		params := baseParams(build, &automotivev1alpha1.OperatorConfig{}, "", nil, nil)
		want := policy
		if want == "" {
			want = "validate"
		}
		found := false
		for _, param := range params {
			if param.Name == "builder-cache-policy" {
				found = true
				if param.Value.StringVal != want {
					t.Fatalf("policy=%q, want %q", param.Value.StringVal, want)
				}
			}
		}
		if !found {
			t.Fatal("missing builder-cache-policy parameter")
		}
	}
}
