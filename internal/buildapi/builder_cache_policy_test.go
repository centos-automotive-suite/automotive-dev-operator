package buildapi

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestBuilderCachePolicyValidationAndSpec(t *testing.T) {
	for _, policy := range []string{"", "validate", "reuse", "invalid"} {
		t.Run(policy, func(t *testing.T) {
			req := &buildcontract.BuildRequest{Name: "test", Manifest: "name: test\n", Mode: buildcontract.ModeBootc, BuilderCachePolicy: policy}
			err := validateBuildRequest(req)
			if policy == "invalid" {
				if err == nil {
					t.Fatal("invalid policy accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			spec := automotivev1alpha1.ImageBuildSpec{AIB: buildAIBSpec(req, req.Manifest, "test.aib.yml", false)}
			want := policy
			if want == "" {
				want = "validate"
			}
			if got := spec.GetBuilderCachePolicy(); got != want {
				t.Fatalf("policy=%q, want %q", got, want)
			}
		})
	}
}
