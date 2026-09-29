package imagebuild

import (
	"context"
	"strconv"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestSecureBuildRejectsDirectInternalRegistryExport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		export *automotivev1alpha1.ExportSpec
	}{
		{
			name: "container",
			export: &automotivev1alpha1.ExportSpec{
				Container: tasks.DefaultInternalRegistryURL + "/test-ns/image:latest",
			},
		},
		{
			name: "disk",
			export: &automotivev1alpha1.ExportSpec{
				Disk: &automotivev1alpha1.DiskExport{OCI: tasks.DefaultInternalRegistryURL + "/test-ns/disk:latest"},
			},
		},
		{
			name: "service account auth",
			export: &automotivev1alpha1.ExportSpec{
				UseServiceAccountAuth: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ib := newTestImageBuild("secure-internal", automotivev1alpha1.ImageBuildPhasePending, "", 0)
			ib.Spec.SecureBuild = true
			ib.Spec.Export = tc.export
			r := newExpiryReconciler(ib)
			if _, err := r.handleInitialState(context.Background(), &ib); err != nil {
				t.Fatal(err)
			}
			got := &automotivev1alpha1.ImageBuild{}
			if err := r.Get(context.Background(), types.NamespacedName{Name: ib.Name, Namespace: ib.Namespace}, got); err != nil {
				t.Fatal(err)
			}
			if got.Status.Phase != automotivev1alpha1.ImageBuildPhaseFailed || !strings.Contains(got.Status.Message, "secure builds cannot use the internal registry") {
				t.Fatalf("status = %+v, want immediate internal-registry rejection", got.Status)
			}
		})
	}
}

func TestValidateSecureExportAllowsExternalAndNonSecureBuilds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
		ref    string
	}{
		{"secure external", true, "quay.io/example/image:latest"},
		{"plain internal", false, tasks.DefaultInternalRegistryURL + "/test-ns/image:latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ib := newTestImageBuild("registry-validation", automotivev1alpha1.ImageBuildPhasePending, "", 0)
			ib.Spec.SecureBuild = tc.secure
			ib.Spec.Export = &automotivev1alpha1.ExportSpec{Container: tc.ref}
			if err := validateSecureExport(&ib); err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateSecureRegistryRoute(t *testing.T) {
	const route = "registry.apps.example.com"
	for _, tc := range []struct {
		name    string
		secure  bool
		ref     string
		route   string
		wantErr bool
	}{
		{"secure container route", true, route + "/test-ns/image:latest", route, true},
		{"secure disk route", true, route + "/test-ns/disk:latest", route + "/", true},
		{"secure external", true, "quay.io/example/image:latest", route, false},
		{"non-secure route", false, route + "/test-ns/image:latest", route, false},
		{"similar hostname", true, route + ".other/test-ns/image:latest", route, false},
		{"unknown route", true, route + "/test-ns/image:latest", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ib := newTestImageBuild("registry-route", automotivev1alpha1.ImageBuildPhasePending, "", 0)
			ib.Spec.SecureBuild = tc.secure
			ib.Spec.Export = &automotivev1alpha1.ExportSpec{Container: tc.ref}
			if tc.name == "secure disk route" {
				ib.Spec.Export = &automotivev1alpha1.ExportSpec{Disk: &automotivev1alpha1.DiskExport{OCI: tc.ref}}
			}
			err := validateSecureRegistryRoute(&ib, tc.route)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateSecureRegistryRoute() error = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}

func TestSecureBuildRejectsClusterRegistryRouteBeforePipeline(t *testing.T) {
	ctx := context.Background()
	ib := newTestImageBuild("secure-route", automotivev1alpha1.ImageBuildPhaseBuilding, "", 0)
	ib.Spec.Architecture = "arm64"
	ib.Spec.AIB = &automotivev1alpha1.AIBSpec{Mode: "package", Manifest: "name: test\n"}
	ib.Spec.SecureBuild = true
	ib.Spec.TaskBundleRef = "registry.example/tasks@sha256:" + strings.Repeat("a", 64)
	ib.Spec.Export = &automotivev1alpha1.ExportSpec{Container: "registry.example/test-ns/image:latest"}
	r := newExpiryReconciler(ib)
	config := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
		Spec: automotivev1alpha1.OperatorConfigSpec{OSBuilds: &automotivev1alpha1.OSBuildsConfig{
			ClusterRegistryRoute: "registry.example",
			UsePVCScratchVolumes: new(false),
		}},
	}
	if err := r.Create(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err := r.startNewBuild(ctx, &ib); err != nil {
		t.Fatal(err)
	}
	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: ib.Name, Namespace: ib.Namespace}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != automotivev1alpha1.ImageBuildPhaseFailed || !strings.Contains(got.Status.Message, "cannot use cluster registry route") {
		t.Fatalf("status = %+v, want early route rejection", got.Status)
	}
	var runs tektonv1.PipelineRunList
	if err := r.List(ctx, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("created %d PipelineRuns for unsupported secure export", len(runs.Items))
	}
}

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
				if err := r.createBuildPipelineRun(ctx, &ib); err != nil {
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
				if params["hermeto-prefetch"] != strconv.FormatBool(tc.enabled) || params["hermeto-image"] != tc.wantImage {
					t.Fatalf("Hermeto settings did not reach PipelineRun: %+v", params)
				}
			})
		}
	}
}
