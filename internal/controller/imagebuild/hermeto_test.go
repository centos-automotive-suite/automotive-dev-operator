package imagebuild

import (
	"context"
	"strconv"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHermetoOperatorConfigReachesPipelineRun(t *testing.T) {
	const customImage = "registry.example/hermeto@sha256:mirror"
	for _, secure := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			enabled   bool
			image     string
			wantImage string
		}{
			{"disabled", false, customImage, customImage},
			{"default image", true, "", automotivev1alpha1.DefaultHermetoImage},
			{"custom image", true, customImage, customImage},
		} {
			name := tc.name
			if secure {
				name += "/bundle"
			} else {
				name += "/cluster"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				ib := newTestImageBuild("hermeto-build", automotivev1alpha1.ImageBuildPhasePending, "", 0)
				ib.TypeMeta = metav1.TypeMeta{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageBuild"}
				ib.Spec.Architecture = "arm64"
				ib.Spec.AIB = &automotivev1alpha1.AIBSpec{Mode: "package", Manifest: "name: test\n", Lockfile: `{"version":1}`}
				ib.Spec.SecureBuild = secure
				ib.Spec.TaskBundleRef = "registry.example/tasks@sha256:" + strings.Repeat("a", 64)
				r := newExpiryReconciler(ib)
				config := &automotivev1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
					Spec: automotivev1alpha1.OperatorConfigSpec{
						Images: &automotivev1alpha1.ImagesConfig{Hermeto: tc.image},
						OSBuilds: &automotivev1alpha1.OSBuildsConfig{
							HermetoPrefetch:      tc.enabled,
							ClusterRegistryRoute: "registry.example",
							UsePVCScratchVolumes: new(false),
						},
					},
				}
				if err := r.Create(ctx, config); err != nil {
					t.Fatal(err)
				}
				resolved := r.resolveBuildConfig(ctx)
				if resolved.HermetoPrefetch != tc.enabled || resolved.HermetoImage != config.Spec.GetImages().GetHermetoImage() {
					t.Fatalf("resolved config lost Hermeto settings: %+v", resolved)
				}
				if err := r.createBuildTaskRun(ctx, &ib); err != nil {
					t.Fatal(err)
				}
				var runs tektonv1.PipelineRunList
				if err := r.List(ctx, &runs); err != nil {
					t.Fatal(err)
				}
				if len(runs.Items) != 1 {
					t.Fatalf("got %d PipelineRuns", len(runs.Items))
				}
				run := runs.Items[0]
				if got := string(run.Spec.PipelineRef.Resolver); secure && got != "bundles" {
					t.Fatalf("resolver = %q; want bundles", got)
				}
				params := make(map[string]string)
				for _, p := range run.Spec.Params {
					params[p.Name] = p.Value.StringVal
				}
				if params["hermeto-prefetch"] != strconv.FormatBool(tc.enabled || secure) || params["hermeto-image"] != tc.wantImage {
					t.Fatalf("Hermeto settings did not reach PipelineRun: %+v", params)
				}
			})
		}
	}
}
