package imagebuild

import (
	"context"
	"strconv"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestResolveOnlyReachesPipelineRun(t *testing.T) {
	for _, resolve := range []bool{false, true} {
		t.Run(strconv.FormatBool(resolve), func(t *testing.T) {
			ctx := context.Background()
			ib := newTestImageBuild("resolve-test", automotivev1alpha1.ImageBuildPhasePending, "", 0)
			ib.TypeMeta = metav1.TypeMeta{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageBuild"}
			ib.Spec.Architecture = "arm64"
			ib.Spec.AIB = &automotivev1alpha1.AIBSpec{Mode: "package", Manifest: "name: example\n", ResolveOnly: resolve}
			r := newExpiryReconciler(ib)
			config := &automotivev1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
				Spec:       automotivev1alpha1.OperatorConfigSpec{OSBuilds: &automotivev1alpha1.OSBuildsConfig{ClusterRegistryRoute: "registry.example", UsePVCScratchVolumes: new(false)}},
			}
			if err := r.Create(ctx, config); err != nil {
				t.Fatal(err)
			}
			if err := r.createBuildTaskRun(ctx, &ib); err != nil {
				t.Fatal(err)
			}
			var runs tektonv1.PipelineRunList
			if err := r.List(ctx, &runs); err != nil {
				t.Fatal(err)
			}
			if len(runs.Items) != 1 {
				t.Fatalf("got %d runs", len(runs.Items))
			}
			for _, p := range runs.Items[0].Spec.Params {
				if p.Name == "resolve-only" {
					if p.Value.StringVal != strconv.FormatBool(resolve) {
						t.Fatalf("wrong resolution flag: %+v", p)
					}
					return
				}
			}
			t.Fatal("resolve-only parameter missing")
		})
	}
}
