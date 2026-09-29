package imagebuild

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPipelinePlanWorkspaceAndRun(t *testing.T) {
	build := &automotivev1alpha1.ImageBuild{
		TypeMeta:   metav1.TypeMeta{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageBuild"},
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "builds", UID: types.UID("build-uid")},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Architecture: "amd64", BuildCachePVC: "cache", StorageClass: "build-class",
		},
	}
	config := &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{
		OSBuilds: &automotivev1alpha1.OSBuildsConfig{
			PVCSize: "12Gi", StorageClass: "operator-class", RuntimeClassName: "kata",
		},
	}}
	buildConfig := buildConfigFromOperatorConfig(config)
	if buildConfig == nil || buildConfig.RuntimeClassName != "kata" {
		t.Fatalf("build configuration was not resolved: %+v", buildConfig)
	}
	if buildConfigFromOperatorConfig(nil) != nil {
		t.Fatal("missing OperatorConfig must not produce build configuration")
	}
	shared, err := sharedWorkspace(build, config)
	if err != nil {
		t.Fatal(err)
	}
	if shared.PersistentVolumeClaim == nil || shared.PersistentVolumeClaim.ClaimName != "cache" {
		t.Fatalf("cache PVC was not selected: %+v", shared)
	}
	build.Spec.BuildCachePVC = ""
	shared, err = sharedWorkspace(build, config)
	if err != nil {
		t.Fatal(err)
	}
	claim := shared.VolumeClaimTemplate
	if claim == nil || claim.Spec.StorageClassName == nil || *claim.Spec.StorageClassName != "build-class" ||
		claim.Spec.Resources.Requests.Storage().String() != "12Gi" {
		t.Fatalf("claim template did not preserve storage settings: %+v", shared)
	}
	workspaces := workspaceBindings(build, shared, "demo-manifest", "")
	if len(workspaces) != 2 || workspaces[0].Name != "shared-workspace" ||
		workspaces[1].ConfigMap.Name != "demo-manifest" {
		t.Fatalf("unexpected workspace bindings: %+v", workspaces)
	}
	params := []tektonv1.Param{{Name: "arch", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "amd64"}}}
	run := pipelineRunObject(build, config, buildConfig, params, workspaces)
	if run.GenerateName != "demo-build-" || run.Namespace != "builds" ||
		run.Spec.PipelineRef.Name != "automotive-build-pipeline" ||
		*run.Spec.TaskRunTemplate.PodTemplate.RuntimeClassName != "kata" ||
		len(run.Spec.Workspaces) != 2 || len(run.Spec.Params) != 1 {
		t.Fatalf("unexpected PipelineRun: %+v", run)
	}
}

func planTestBuild() *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "builds", UID: types.UID("build-uid")},
		Spec:       automotivev1alpha1.ImageBuildSpec{Architecture: "amd64", AIB: &automotivev1alpha1.AIBSpec{Distro: "autosd", Target: "qemu"}},
	}
}

func planParamValues(run *tektonv1.PipelineRun) map[string]string {
	values := make(map[string]string, len(run.Spec.Params))
	for _, param := range run.Spec.Params {
		values[param.Name] = param.Value.StringVal
	}
	return values
}

func TestNewPipelineRunInputs(t *testing.T) {
	build := planTestBuild() // TypeMeta deliberately absent.
	build.Spec.RuntimeClassName = "build-runtime"
	build.Spec.StorageClass = "build-storage"
	build.Spec.Export = &automotivev1alpha1.ExportSpec{Container: "registry.example/demo:latest"}
	config := &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{
		OSBuilds: &automotivev1alpha1.OSBuildsConfig{RuntimeClassName: "operator-runtime", StorageClass: "operator-storage"},
	}}
	in := pipelineRunInputs{
		build: build, operatorConfig: config, buildConfig: buildConfigFromOperatorConfig(config),
		exportFormat: "qcow2", extraArgs: []string{"--define", "answer=42"},
		registryRoute: "registry.example", manifestConfigMap: "manifest",
	}
	run, err := newPipelineRun(in)
	if err != nil {
		t.Fatal(err)
	}
	if run.OwnerReferences[0].APIVersion != automotivev1alpha1.GroupVersion.String() || run.OwnerReferences[0].Kind != "ImageBuild" {
		t.Fatalf("owner reference depends on TypeMeta: %+v", run.OwnerReferences)
	}
	if got := *run.Spec.TaskRunTemplate.PodTemplate.RuntimeClassName; got != "build-runtime" {
		t.Fatalf("runtime override = %q", got)
	}
	if got := *run.Spec.Workspaces[0].VolumeClaimTemplate.Spec.StorageClassName; got != "build-storage" {
		t.Fatalf("storage class override = %q", got)
	}
	build.Spec.RuntimeClassName = "changed-runtime"
	build.Spec.StorageClass = "changed-storage"
	if *run.Spec.TaskRunTemplate.PodTemplate.RuntimeClassName != "build-runtime" || *run.Spec.Workspaces[0].VolumeClaimTemplate.Spec.StorageClassName != "build-storage" {
		t.Fatal("PipelineRun pointers alias ImageBuild spec fields")
	}
	params := planParamValues(run)
	for key, want := range map[string]string{
		"arch": "amd64", "distro": "autosd", "target": "qemu", "export-format": "qcow2",
		"container-push": "registry.example/demo:latest", "aib-extra-args": "--define\nanswer=42",
		"cluster-registry-route": "registry.example",
	} {
		if params[key] != want {
			t.Errorf("param %q = %q, want %q", key, params[key], want)
		}
	}
	if _, ok := params["flash-enabled"]; ok {
		t.Fatal("flash params added for a non-flash build")
	}
}

func TestNewPipelineRunBundleAndFlash(t *testing.T) {
	build := planTestBuild()
	build.Spec.AIB.Target = "board"
	build.Spec.Flash = &automotivev1alpha1.FlashSpec{ClientConfigSecretRef: "jumpstarter-client", LeaseName: "existing"}
	build.Spec.Export = &automotivev1alpha1.ExportSpec{Disk: &automotivev1alpha1.DiskExport{OCI: "registry.example/disk:latest"}}
	config := &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{
		Jumpstarter: &automotivev1alpha1.JumpstarterConfig{TargetMappings: map[string]automotivev1alpha1.JumpstarterTargetMapping{
			"board": {Selector: "model=board", FlashCmd: "j storage flash"},
		}},
	}}
	flash, err := resolveFlashTarget(build, config, "")
	if err != nil {
		t.Fatal(err)
	}
	run, err := newPipelineRun(pipelineRunInputs{
		build: build, operatorConfig: config,
		buildConfig: &tasks.BuildConfig{TaskResolver: tasks.TaskResolverBundle, TaskBundleRef: "bundle@sha256:abc"},
		flash:       flash, manifestConfigMap: "manifest", flashAuthSecret: "flash-auth",
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Spec.PipelineRef.Resolver != tektonv1.ResolverName(tasks.TektonResolverBundles) {
		t.Fatalf("bundle resolver missing: %+v", run.Spec.PipelineRef)
	}
	params := planParamValues(run)
	for key, want := range map[string]string{
		"flash-enabled": "true", "flash-image-ref": "registry.example/disk:latest",
		"flash-exporter-selector": "model=board", "flash-cmd": "j storage flash",
		"flash-lease-name": "existing",
	} {
		if params[key] != want {
			t.Errorf("flash param %q = %q, want %q", key, params[key], want)
		}
	}
	if len(run.Spec.Workspaces) != 4 || run.Spec.Workspaces[2].Name != "jumpstarter-client" || run.Spec.Workspaces[3].Secret.SecretName != "flash-auth" {
		t.Fatalf("flash workspaces = %+v", run.Spec.Workspaces)
	}
}

func TestSharedWorkspaceSelectionAndPVCSize(t *testing.T) {
	build := planTestBuild()
	config := &automotivev1alpha1.OperatorConfig{}
	shared, err := sharedWorkspace(build, config)
	if err != nil {
		t.Fatal(err)
	}
	if got := shared.VolumeClaimTemplate.Spec.Resources.Requests.Storage().String(); got != "8Gi" {
		t.Fatalf("default PVC size = %s", got)
	}
	build.Spec.BuildCachePVC = "cache"
	shared, err = sharedWorkspace(build, config)
	if err != nil || shared.PersistentVolumeClaim.ClaimName != "cache" {
		t.Fatalf("cache PVC = %+v, %v", shared, err)
	}
	build.Spec.BuildCachePVC = ""
	build.Spec.AIB.InputFilesServer = true
	build.Status.PVCName = "uploads"
	shared, err = sharedWorkspace(build, config)
	if err != nil || shared.PersistentVolumeClaim.ClaimName != "uploads" {
		t.Fatalf("uploads PVC = %+v, %v", shared, err)
	}
	build.Spec.AIB.InputFilesServer = false
	build.Spec.AIB.GitSource = &automotivev1alpha1.GitSource{URL: "https://example.com/repo.git"}
	shared, err = sharedWorkspace(build, config)
	if err != nil || shared.PersistentVolumeClaim.ClaimName != "uploads" {
		t.Fatalf("git PVC = %+v, %v", shared, err)
	}
	build.Status.PVCName = ""
	config.Spec.OSBuilds = &automotivev1alpha1.OSBuildsConfig{PVCSize: "not-a-size"}
	if _, err := sharedWorkspace(build, config); err == nil {
		t.Fatal("invalid configured PVC size must return an error")
	}
}

func TestResolveFlashTargetValidation(t *testing.T) {
	build := planTestBuild()
	build.Spec.Flash = &automotivev1alpha1.FlashSpec{ClientConfigSecretRef: "client"}
	config := &automotivev1alpha1.OperatorConfig{}
	if _, err := resolveFlashTarget(build, config, ""); err == nil {
		t.Fatal("missing target mapping must fail")
	}
	build.Spec.Flash.ExporterSelector = "serial=1"
	build.Spec.Flash.FlashCmd = "custom command"
	build.Spec.Export = &automotivev1alpha1.ExportSpec{
		UseServiceAccountAuth: true,
		Disk:                  &automotivev1alpha1.DiskExport{OCI: tasks.DefaultInternalRegistryURL + "/demo/disk:latest"},
	}
	if _, err := resolveFlashTarget(build, config, ""); err == nil {
		t.Fatal("internal-registry flash requires an external route")
	}
	flash, err := resolveFlashTarget(build, config, "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if flash.selector != "serial=1" || flash.command != "custom command" || flash.imageRef != "route.example/demo/disk:latest" {
		t.Fatalf("flash target = %+v", flash)
	}
}

func TestFlashOCIAuthSecret(t *testing.T) {
	build := planTestBuild()
	secret := flashOCIAuthSecret(build, []byte("user"), []byte("token"))
	if secret.Name != "demo-flash-oci-auth" || secret.Namespace != "builds" || secret.Type != "Opaque" ||
		string(secret.Data["username"]) != "user" || string(secret.Data["password"]) != "token" {
		t.Fatalf("flash auth secret = %+v", secret)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Kind != "ImageBuild" || secret.OwnerReferences[0].UID != build.UID {
		t.Fatalf("flash auth owner = %+v", secret.OwnerReferences)
	}
}

func TestEnsureFlashOCIAuthUpsertsSecret(t *testing.T) {
	build := planTestBuild()
	build.Spec.SecretRef = "registry-creds"
	registrySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: build.Spec.SecretRef, Namespace: build.Namespace},
		Data:       map[string][]byte{"REGISTRY_USERNAME": []byte("alice"), "REGISTRY_PASSWORD": []byte("first")},
	}
	scheme := newTestSchemeWithTekton()
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(registrySecret).Build()
	reconciler := &ImageBuildReconciler{Client: client, Scheme: scheme, Log: logr.Discard()}
	flash := &flashTarget{imageRef: "registry.example/demo:latest"}
	name, err := reconciler.ensureFlashOCIAuth(t.Context(), build, flash)
	if err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: name, Namespace: build.Namespace}
	if err := client.Get(t.Context(), key, secret); err != nil {
		t.Fatal(err)
	}
	if name != "demo-flash-oci-auth" || string(secret.Data["password"]) != "first" {
		t.Fatalf("created flash auth = %+v", secret)
	}
	registrySecret.Data["REGISTRY_PASSWORD"] = []byte("rotated")
	if err := client.Update(t.Context(), registrySecret); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.ensureFlashOCIAuth(t.Context(), build, flash); err != nil {
		t.Fatal(err)
	}
	if err := client.Get(t.Context(), key, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["password"]) != "rotated" {
		t.Fatalf("flash auth was not refreshed: %+v", secret.Data)
	}
}
