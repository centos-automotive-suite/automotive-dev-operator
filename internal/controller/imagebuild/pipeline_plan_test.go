package imagebuild

import (
	"context"
	"errors"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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
	workspaces := workspaceBindings(build, nil, shared, "demo-manifest", "")
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

func TestGitSourcePipelineWithOCIRepository(t *testing.T) {
	build := planTestBuild()
	build.Spec.AIB.GitSource = &automotivev1alpha1.GitSource{
		URL: "https://git.example.com/os.git", ManifestPath: "images/demo.aib.yml",
	}
	build.Spec.AIB.OCIRepoImages = []string{"quay.io/example/rpms:v1"}
	build.Spec.AIB.CustomDefs = []string{`extra_repos=[{"id":"oci-repo","baseurl":"file:///extra-repos/oci-repo"}]`}
	build.Status.PVCName = "git-checkout"
	if err := automotivev1alpha1.ValidateGitSourceSpec(&build.Spec); err != nil {
		t.Fatal(err)
	}
	run, err := newPipelineRun(pipelineRunInputs{
		build: build, operatorConfig: &automotivev1alpha1.OperatorConfig{}, manifestConfigMap: "manifest",
	})
	if err != nil {
		t.Fatal(err)
	}
	shared := run.Spec.Workspaces[0]
	if shared.PersistentVolumeClaim == nil || shared.PersistentVolumeClaim.ClaimName != "git-checkout" {
		t.Fatalf("Git checkout PVC not used: %+v", shared)
	}
	if got := planParamValues(run)["custom-defines"]; got != build.Spec.AIB.CustomDefs[0] {
		t.Fatalf("OCI repository definition = %q", got)
	}
	for _, volume := range run.Spec.TaskRunTemplate.PodTemplate.Volumes {
		if volume.Name == tasks.OCIRepoVolumeName {
			if volume.Image == nil || volume.Image.Reference != build.Spec.AIB.OCIRepoImages[0] {
				t.Fatalf("OCI repository volume = %+v", volume)
			}
			return
		}
	}
	t.Fatal("OCI repository volume missing")
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
	if _, err := sharedWorkspace(build, config); !errors.Is(err, errTerminalConfig) {
		t.Fatalf("invalid configured PVC size must be terminal, got %v", err)
	}
}

func TestInvalidPVCSizeFailsBeforePipelineSideEffects(t *testing.T) {
	build := newTestImageBuild("invalid-pvc", phaseBuilding, "", 0)
	build.Spec.Architecture = "amd64"
	build.Spec.AIB = &automotivev1alpha1.AIBSpec{Mode: "package", Target: "qemu", Manifest: "name: test\n"}
	build.Spec.Flash = &automotivev1alpha1.FlashSpec{ClientConfigSecretRef: "jumpstarter-client", ExporterSelector: "model=qemu"}
	build.Spec.Export = &automotivev1alpha1.ExportSpec{Disk: &automotivev1alpha1.DiskExport{OCI: "registry.example/disk:latest"}}
	build.Spec.SecretRef = "registry-creds"
	r := newExpiryReconciler(build)
	config := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
		Spec: automotivev1alpha1.OperatorConfigSpec{OSBuilds: &automotivev1alpha1.OSBuildsConfig{
			PVCSize: "not-a-size", ClusterRegistryRoute: "registry.example",
		}},
	}
	if err := r.Create(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	registrySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: build.Spec.SecretRef, Namespace: build.Namespace},
		Data: map[string][]byte{
			"REGISTRY_USERNAME": []byte("alice"), "REGISTRY_PASSWORD": []byte("secret"),
		},
	}
	if err := r.Create(t.Context(), registrySecret); err != nil {
		t.Fatal(err)
	}
	if _, err := r.startNewBuild(t.Context(), &build); err != nil {
		t.Fatal(err)
	}
	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(t.Context(), types.NamespacedName{Name: build.Name, Namespace: build.Namespace}, fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Status.Phase != phaseFailed || !strings.Contains(fresh.Status.Message, "invalid build PVC size") {
		t.Fatalf("invalid PVC size did not fail the build: %+v", fresh.Status)
	}
	flashAuth := &corev1.Secret{}
	if err := r.Get(t.Context(), types.NamespacedName{Name: build.Name + "-flash-oci-auth", Namespace: build.Namespace}, flashAuth); !apierrors.IsNotFound(err) {
		t.Fatalf("flash auth Secret exists or lookup failed: %v", err)
	}
	manifest := &corev1.ConfigMap{}
	if err := r.Get(t.Context(), types.NamespacedName{Name: safeDerivedName(build.Name, "-manifest"), Namespace: build.Namespace}, manifest); !apierrors.IsNotFound(err) {
		t.Fatalf("manifest ConfigMap exists or lookup failed: %v", err)
	}
	runs := &tektonv1.PipelineRunList{}
	if err := r.List(t.Context(), runs); err != nil || len(runs.Items) != 0 {
		t.Fatalf("PipelineRuns after invalid PVC size = %d, %v", len(runs.Items), err)
	}
}

func flashPipelineTestBuild() *automotivev1alpha1.ImageBuild {
	build := planTestBuild()
	build.Spec.AIB.Manifest = "name: test\n"
	build.Spec.Flash = &automotivev1alpha1.FlashSpec{ClientConfigSecretRef: "jumpstarter-client", ExporterSelector: "model=qemu"}
	build.Spec.Export = &automotivev1alpha1.ExportSpec{Disk: &automotivev1alpha1.DiskExport{OCI: "registry.example/disk:latest"}}
	build.Spec.SecretRef = "registry-creds"
	return build
}

func flashPipelineTestReconciler(t *testing.T, build *automotivev1alpha1.ImageBuild, credentials map[string][]byte) *ImageBuildReconciler {
	t.Helper()
	r := newExpiryReconciler(*build)
	config := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
		Spec: automotivev1alpha1.OperatorConfigSpec{OSBuilds: &automotivev1alpha1.OSBuildsConfig{
			PVCSize: "12Gi", ClusterRegistryRoute: "registry.example",
		}},
	}
	if err := r.Create(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	registrySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: build.Spec.SecretRef, Namespace: build.Namespace},
		Data:       credentials,
	}
	if err := r.Create(t.Context(), registrySecret); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCreateBuildPipelineRunFlashAuthWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name        string
		credentials map[string][]byte
		wantAuth    bool
	}{
		{name: "authenticated", credentials: map[string][]byte{"REGISTRY_USERNAME": []byte("alice"), "REGISTRY_PASSWORD": []byte("secret")}, wantAuth: true},
		{name: "anonymous"},
		{name: "incomplete credentials", credentials: map[string][]byte{"REGISTRY_USERNAME": []byte("alice")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := flashPipelineTestBuild()
			r := flashPipelineTestReconciler(t, build, tc.credentials)
			if err := r.createBuildPipelineRun(t.Context(), build); err != nil {
				t.Fatal(err)
			}
			runs := &tektonv1.PipelineRunList{}
			if err := r.List(t.Context(), runs); err != nil || len(runs.Items) != 1 {
				t.Fatalf("PipelineRuns = %d, %v", len(runs.Items), err)
			}
			authWorkspaces := 0
			for _, workspace := range runs.Items[0].Spec.Workspaces {
				if workspace.Name == "flash-oci-auth" {
					authWorkspaces++
					if workspace.Secret == nil || workspace.Secret.SecretName != flashOCIAuthSecretName(build) {
						t.Fatalf("flash auth workspace = %+v", workspace)
					}
				}
				if workspace.Name == "manifest-config-workspace" && (workspace.ConfigMap == nil || workspace.ConfigMap.Name != manifestConfigMapName(build)) {
					t.Fatalf("manifest workspace = %+v", workspace)
				}
			}
			wantCount := 0
			if tc.wantAuth {
				wantCount = 1
			}
			if authWorkspaces != wantCount {
				t.Fatalf("flash auth workspace count = %d, want %d", authWorkspaces, wantCount)
			}
			secret := &corev1.Secret{}
			err := r.Get(t.Context(), types.NamespacedName{Name: flashOCIAuthSecretName(build), Namespace: build.Namespace}, secret)
			if tc.wantAuth && err != nil || !tc.wantAuth && !apierrors.IsNotFound(err) {
				t.Fatalf("flash auth Secret lookup = %v, want auth %t", err, tc.wantAuth)
			}
		})
	}
}

func TestInvalidManifestFailsBeforeFlashSecretWrite(t *testing.T) {
	build := flashPipelineTestBuild()
	build.Spec.AIB.Lockfile = "not-json"
	r := flashPipelineTestReconciler(t, build, map[string][]byte{"REGISTRY_USERNAME": []byte("alice"), "REGISTRY_PASSWORD": []byte("secret")})
	if err := r.createBuildPipelineRun(t.Context(), build); err == nil {
		t.Fatal("invalid lockfile must fail")
	}
	secret := &corev1.Secret{}
	if err := r.Get(t.Context(), types.NamespacedName{Name: flashOCIAuthSecretName(build), Namespace: build.Namespace}, secret); !apierrors.IsNotFound(err) {
		t.Fatalf("flash auth Secret exists or lookup failed: %v", err)
	}
	manifest := &corev1.ConfigMap{}
	if err := r.Get(t.Context(), types.NamespacedName{Name: manifestConfigMapName(build), Namespace: build.Namespace}, manifest); !apierrors.IsNotFound(err) {
		t.Fatalf("manifest ConfigMap exists or lookup failed: %v", err)
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
	secret := flashOCIAuthSecret(build, &flashOCICredentials{username: []byte("user"), password: []byte("token")})
	if secret.Name != "demo-flash-oci-auth" || secret.Namespace != "builds" || secret.Type != "Opaque" ||
		string(secret.Data["username"]) != "user" || string(secret.Data["password"]) != "token" {
		t.Fatalf("flash auth secret = %+v", secret)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Kind != "ImageBuild" || secret.OwnerReferences[0].UID != build.UID {
		t.Fatalf("flash auth owner = %+v", secret.OwnerReferences)
	}
}

func TestFlashOCICredentialsAndSecretWrite(t *testing.T) {
	build := planTestBuild()
	build.Spec.SecretRef = "registry-creds"
	registrySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: build.Spec.SecretRef, Namespace: build.Namespace},
		Data:       map[string][]byte{"REGISTRY_USERNAME": []byte("alice"), "REGISTRY_PASSWORD": []byte("first")},
	}
	scheme := newTestSchemeWithTekton()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(registrySecret).Build()
	reconciler := &ImageBuildReconciler{Client: fakeClient, Scheme: scheme, Log: logr.Discard()}
	flash := &flashTarget{imageRef: "registry.example/demo:latest"}
	creds, err := reconciler.flashOCICredentials(t.Context(), build, flash)
	if err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: flashOCIAuthSecretName(build), Namespace: build.Namespace}
	if err := fakeClient.Get(t.Context(), key, secret); !apierrors.IsNotFound(err) {
		t.Fatalf("credential resolution wrote a Secret or lookup failed: %v", err)
	}
	if creds == nil {
		t.Fatal("registry credentials were not resolved")
	}
	if err := reconciler.writeFlashOCIAuthSecret(t.Context(), build, creds); err != nil {
		t.Fatal(err)
	}
	if err := fakeClient.Get(t.Context(), key, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["password"]) != "first" {
		t.Fatalf("created flash auth = %+v", secret)
	}
	registrySecret.Data["REGISTRY_PASSWORD"] = []byte("rotated")
	if err := fakeClient.Update(t.Context(), registrySecret); err != nil {
		t.Fatal(err)
	}
	creds, err = reconciler.flashOCICredentials(t.Context(), build, flash)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.writeFlashOCIAuthSecret(t.Context(), build, creds); err != nil {
		t.Fatal(err)
	}
	if err := fakeClient.Get(t.Context(), key, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["password"]) != "rotated" {
		t.Fatalf("flash auth was not refreshed: %+v", secret.Data)
	}
}

func TestFlashOCICredentialsServiceAccount(t *testing.T) {
	tokenErr := errors.New("token request failed")
	for _, tc := range []struct {
		name  string
		token string
		err   error
	}{
		{name: "token", token: "build-token"},
		{name: "empty token"},
		{name: "request error", err: tokenErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := planTestBuild()
			build.Spec.Export = &automotivev1alpha1.ExportSpec{UseServiceAccountAuth: true}
			requested := false
			scheme := newTestSchemeWithTekton()
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
				SubResourceCreate: func(_ context.Context, _ client.Client, name string, obj client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
					requested = true
					if name != "token" || obj.GetName() != automotivev1alpha1.BuildServiceAccountName || obj.GetNamespace() != build.Namespace {
						t.Fatalf("token request target = %s %s/%s", name, obj.GetNamespace(), obj.GetName())
					}
					request, ok := subResource.(*authnv1.TokenRequest)
					if !ok || request.Spec.ExpirationSeconds == nil || *request.Spec.ExpirationSeconds != 4*3600 {
						t.Fatalf("token request = %+v", subResource)
					}
					request.Status.Token = tc.token
					return tc.err
				},
			}).Build()
			r := &ImageBuildReconciler{Client: fakeClient, Scheme: scheme, Log: logr.Discard()}
			creds, err := r.flashOCICredentials(t.Context(), build, &flashTarget{imageRef: "registry.example/disk:latest"})
			if !requested || !errors.Is(err, tc.err) {
				t.Fatalf("token requested = %t, error = %v, want %v", requested, err, tc.err)
			}
			if tc.err != nil || tc.token == "" {
				if creds != nil {
					t.Fatal("failed or empty token must not produce credentials")
				}
			} else if creds == nil || string(creds.username) != "serviceaccount" || string(creds.password) != tc.token {
				t.Fatal("service account credentials were not resolved")
			}
			secrets := &corev1.SecretList{}
			if err := fakeClient.List(t.Context(), secrets); err != nil || len(secrets.Items) != 0 {
				t.Fatalf("Secrets after credential resolution = %d, %v", len(secrets.Items), err)
			}
		})
	}
}
