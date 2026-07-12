package tasks

import (
	"strings"
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
)

const (
	insecureRegistryParam    = "insecure-registry"
	falseString              = "false"
	buildImageTaskName       = "build-automotive-image"
	pushDiskArtifactTaskName = "push-disk-artifact"
)

func TestBuildTaskRef_ClusterResolver(t *testing.T) {
	ref := buildTaskRef("build-automotive-image", "test-ns", nil)

	if ref.Resolver != TaskResolverCluster {
		t.Fatalf("expected cluster resolver, got %q", ref.Resolver)
	}

	params := make(map[string]string)
	for _, p := range ref.Params {
		params[p.Name] = p.Value.StringVal
	}

	if params["name"] != "build-automotive-image" {
		t.Errorf("expected name=build-automotive-image, got %q", params["name"])
	}
	if params["namespace"] != "test-ns" {
		t.Errorf("expected namespace=test-ns, got %q", params["namespace"])
	}
	if params["kind"] != "task" {
		t.Errorf("expected kind=task, got %q", params["kind"])
	}
}

func TestBuildTaskRef_ClusterResolver_NilBuildConfig(t *testing.T) {
	ref := buildTaskRef("push-artifact-registry", "ns", nil)
	if ref.Resolver != TaskResolverCluster {
		t.Fatalf("nil buildConfig should use cluster resolver, got %q", ref.Resolver)
	}
}

func TestBuildTaskRef_ClusterResolver_EmptyTaskResolver(t *testing.T) {
	ref := buildTaskRef("push-artifact-registry", "ns", &BuildConfig{})
	if ref.Resolver != TaskResolverCluster {
		t.Fatalf("empty TaskResolver should use cluster resolver, got %q", ref.Resolver)
	}
}

func TestBuildTaskRef_BundleResolver(t *testing.T) {
	bundleRef := "quay.io/org/tasks@sha256:abc123"
	ref := buildTaskRef("build-automotive-image", "test-ns", &BuildConfig{
		TaskResolver:  TaskResolverBundle,
		TaskBundleRef: bundleRef,
	})

	if ref.Resolver != TektonResolverBundles {
		t.Fatalf("expected bundles resolver, got %q", ref.Resolver)
	}

	params := make(map[string]string)
	for _, p := range ref.Params {
		params[p.Name] = p.Value.StringVal
	}

	if params["bundle"] != bundleRef {
		t.Errorf("expected bundle=%s, got %q", bundleRef, params["bundle"])
	}
	if params["name"] != "build-automotive-image" {
		t.Errorf("expected name=build-automotive-image, got %q", params["name"])
	}
	if params["kind"] != "task" {
		t.Errorf("expected kind=task, got %q", params["kind"])
	}
	// Bundle resolver should NOT have namespace param
	if _, ok := params["namespace"]; ok {
		t.Error("bundle resolver should not have namespace param")
	}
}

func TestBuildTaskRef_BundleResolver_MissingRef(t *testing.T) {
	// TaskResolver=bundle but no TaskBundleRef should fall back to cluster
	ref := buildTaskRef("flash-image", "ns", &BuildConfig{
		TaskResolver: TaskResolverBundle,
	})
	if ref.Resolver != TaskResolverCluster {
		t.Fatalf("bundle resolver with empty ref should fall back to cluster, got %q", ref.Resolver)
	}
}

func TestGenerateTektonPipeline_HasImagesResult(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	var found bool
	for _, r := range pipeline.Spec.Results {
		if r.Name == "IMAGES" {
			found = true
			if r.Value.StringVal != "$(finally.collect-images-result.results.IMAGES)" {
				t.Errorf("IMAGES result value = %q, want finally task reference", r.Value.StringVal)
			}
			break
		}
	}
	if !found {
		t.Fatal("pipeline should have IMAGES result for Tekton Chains")
	}
}

func TestGenerateTektonPipeline_HasFinallyTask(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	if len(pipeline.Spec.Finally) == 0 {
		t.Fatal("pipeline should have finally tasks")
	}

	var collectTask bool
	for _, task := range pipeline.Spec.Finally {
		if task.Name == "collect-images-result" {
			collectTask = true

			// Verify it has the IMAGES result
			if task.TaskSpec == nil {
				t.Fatal("collect-images-result should have inline TaskSpec")
			}
			var hasImagesResult bool
			for _, r := range task.TaskSpec.Results {
				if r.Name == "IMAGES" {
					hasImagesResult = true
				}
			}
			if !hasImagesResult {
				t.Error("collect-images-result task should have IMAGES result")
			}

			// Verify it reads from workspace files (no params or task-result refs)
			if len(task.Params) != 0 {
				t.Errorf("collect-images-result should have no params (reads from workspace), got %d", len(task.Params))
			}
			if len(task.Workspaces) == 0 {
				t.Error("collect-images-result should bind the shared workspace")
			}
			break
		}
	}
	if !collectTask {
		t.Fatal("pipeline should have collect-images-result finally task")
	}
}

func TestGenerateTektonPipeline_IntegrityDigestParam(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	// Find push-disk-artifact task
	for _, task := range pipeline.Spec.Tasks {
		if task.Name == "push-disk-artifact" {
			for _, p := range task.Params {
				if p.Name == "expected-artifact-digest" {
					if p.Value.StringVal != "$(tasks.build-image.results.ARTIFACT_INTEGRITY_DIGEST)" {
						t.Errorf("expected-artifact-digest = %q, want build-image result ref", p.Value.StringVal)
					}
					return
				}
			}
			t.Fatal("push-disk-artifact should have expected-artifact-digest param")
		}
	}
	t.Fatal("pipeline should have push-disk-artifact task")
}

func TestGenerateTektonPipeline_BundleResolver(t *testing.T) {
	bundleRef := "quay.io/org/tasks@sha256:abc123"
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{
		TaskResolver:  TaskResolverBundle,
		TaskBundleRef: bundleRef,
	})

	// All non-inline tasks should use bundles resolver
	for _, task := range pipeline.Spec.Tasks {
		if task.TaskRef == nil {
			continue // skip tasks with inline TaskSpec
		}
		if task.TaskRef.Resolver != TektonResolverBundles {
			t.Errorf("task %q should use bundles resolver, got %q", task.Name, task.TaskRef.Resolver)
		}
	}
}

func TestGenerateTektonPipeline_ClusterResolverDefault(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	for _, task := range pipeline.Spec.Tasks {
		if task.TaskRef == nil {
			continue
		}
		if task.TaskRef.Resolver != TaskResolverCluster {
			t.Errorf("task %q should use cluster resolver by default, got %q", task.Name, task.TaskRef.Resolver)
		}
	}
}

func TestGenerateBuildTask_HasIntegrityDigestResult(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	for _, r := range task.Spec.Results {
		if r.Name == "ARTIFACT_INTEGRITY_DIGEST" {
			return
		}
	}
	t.Fatal("build task should have ARTIFACT_INTEGRITY_DIGEST result")
}

func TestGeneratePushTask_HasExpectedDigestParam(t *testing.T) {
	task := GeneratePushArtifactRegistryTask("test-ns", nil)

	for _, p := range task.Spec.Params {
		if p.Name == "expected-artifact-digest" {
			if p.Default == nil || p.Default.StringVal != "" {
				t.Error("expected-artifact-digest should default to empty string")
			}
			return
		}
	}
	t.Fatal("push task should have expected-artifact-digest param")
}

func TestCollectImagesScript_Format(t *testing.T) {
	// Verify the finally task script reads from workspace files
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	for _, task := range pipeline.Spec.Finally {
		if task.Name == "collect-images-result" {
			if task.TaskSpec == nil {
				t.Fatal("collect-images-result should have inline TaskSpec")
			}
			if len(task.TaskSpec.Steps) == 0 {
				t.Fatal("collect-images-result should have steps")
			}
			script := task.TaskSpec.Steps[0].Script
			if script == "" {
				t.Fatal("collect step should have a script")
			}
			// Verify the script reads from workspace chain result files
			if !strings.Contains(script, "CHAINS_DIR") {
				t.Error("script should define CHAINS_DIR for workspace result files")
			}
			if !strings.Contains(script, "$CHAINS_DIR/container/url") {
				t.Error("script should read container URL from workspace")
			}
			if !strings.Contains(script, "$CHAINS_DIR/disk/url") {
				t.Error("script should read disk URL from workspace")
			}
			return
		}
	}
	t.Fatal("pipeline should have collect-images-result task")
}

func TestInsecureRegistryParam_Pipeline(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	// Pipeline should declare insecure-registry param with default "false"
	var found bool
	for _, p := range pipeline.Spec.Params {
		if p.Name == insecureRegistryParam {
			found = true
			if p.Default == nil || p.Default.StringVal != falseString {
				t.Errorf("%s default = %v, want %s", insecureRegistryParam, p.Default, falseString)
			}
			break
		}
	}
	if !found {
		t.Fatalf("pipeline should declare %s param", insecureRegistryParam)
	}

	// insecure-registry should be forwarded to build-image and push-disk-artifact tasks
	for _, task := range pipeline.Spec.Tasks {
		if task.Name == buildImageTaskName || task.Name == pushDiskArtifactTaskName {
			var paramForwarded bool
			for _, p := range task.Params {
				if p.Name == insecureRegistryParam && p.Value.StringVal == "$(params.insecure-registry)" {
					paramForwarded = true
					break
				}
			}
			if !paramForwarded {
				t.Errorf("task %q should forward %s pipeline param", task.Name, insecureRegistryParam)
			}
		}
	}
}

func TestInsecureRegistryParam_PushTask(t *testing.T) {
	task := GeneratePushArtifactRegistryTask("test-ns", nil)

	for _, p := range task.Spec.Params {
		if p.Name == insecureRegistryParam {
			if p.Default == nil || p.Default.StringVal != "false" {
				t.Errorf("%s default = %v, want \"false\"", insecureRegistryParam, p.Default)
			}
			return
		}
	}
	t.Fatalf("push task should have %s param", insecureRegistryParam)
}

func TestInsecureRegistryParam_BuildTask(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	for _, p := range task.Spec.Params {
		if p.Name == insecureRegistryParam {
			if p.Default == nil || p.Default.StringVal != "false" {
				t.Errorf("%s default = %v, want \"false\"", insecureRegistryParam, p.Default)
			}
			return
		}
	}
	t.Fatalf("build task should have %s param", insecureRegistryParam)
}

func hasParam(params []tektonv1.ParamSpec, name string) bool {
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}

func findPipelineTask(tasks []tektonv1.PipelineTask, name string) *tektonv1.PipelineTask {
	for i := range tasks {
		if tasks[i].Name == name {
			return &tasks[i]
		}
	}
	return nil
}

func taskParamBinding(task *tektonv1.PipelineTask, name string) (string, bool) {
	for _, p := range task.Params {
		if p.Name == name {
			return p.Value.StringVal, true
		}
	}
	return "", false
}

func TestReproducibleParams_PushTask(t *testing.T) {
	task := GeneratePushArtifactRegistryTask("test-ns", nil)

	required := []string{"reproducible", "task-bundle-ref", "custom-defines", "aib-extra-args"}
	for _, name := range required {
		if !hasParam(task.Spec.Params, name) {
			t.Errorf("push-artifact-registry task missing param %q", name)
		}
	}
}

func TestReproducibleParams_Pipeline(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	required := []string{"reproducible", "task-bundle-ref", "custom-defines", "aib-extra-args"}
	for _, name := range required {
		if !hasParam(pipeline.Spec.Params, name) {
			t.Errorf("pipeline missing param %q", name)
		}
	}
}

func TestReproducibleParams_BuildImageBinding(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	buildTask := findPipelineTask(pipeline.Spec.Tasks, PipelineTaskBuildImage)
	if buildTask == nil {
		t.Fatal("pipeline missing build-image task")
	}

	val, ok := taskParamBinding(buildTask, "reproducible")
	if !ok {
		t.Fatal("build-image task missing reproducible param binding")
	}
	if val != "$(params.reproducible)" {
		t.Errorf("build-image reproducible binding = %q, want $(params.reproducible)", val)
	}
}

func TestReproducibleParams_PushDiskArtifactBindings(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	pushTask := findPipelineTask(pipeline.Spec.Tasks, "push-disk-artifact")
	if pushTask == nil {
		t.Fatal("pipeline missing push-disk-artifact task")
	}

	expectedBindings := map[string]string{
		"reproducible":    "$(params.reproducible)",
		"task-bundle-ref": "$(params.task-bundle-ref)",
		"custom-defines":  "$(params.custom-defines)",
		"aib-extra-args":  "$(params.aib-extra-args)",
	}
	for param, wantVal := range expectedBindings {
		got, ok := taskParamBinding(pushTask, param)
		if !ok {
			t.Errorf("push-disk-artifact missing param binding %q", param)
			continue
		}
		if got != wantVal {
			t.Errorf("push-disk-artifact %s = %q, want %q", param, got, wantVal)
		}
	}
}

func TestReproducibleParams_BuildTask(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	if !hasParam(task.Spec.Params, "reproducible") {
		t.Error("build-automotive-image task missing reproducible param")
	}
}

func TestReproducibleParams_PushScript_References(t *testing.T) {
	task := GeneratePushArtifactRegistryTask("test-ns", nil)

	if len(task.Spec.Steps) == 0 {
		t.Fatal("push task has no steps")
	}

	script := task.Spec.Steps[0].Script
	refs := []string{
		"$(params.reproducible)",
		"$(params.task-bundle-ref)",
		"$(params.custom-defines)",
		"$(params.aib-extra-args)",
	}
	for _, ref := range refs {
		if !strings.Contains(script, ref) {
			t.Errorf("push script missing param reference %q", ref)
		}
	}
}

func TestReproducibleParams_BuildScript_References(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	var buildStep string
	for _, s := range task.Spec.Steps {
		if s.Name == buildImageStepName {
			buildStep = s.Script
			break
		}
	}
	if buildStep == "" {
		t.Fatal("build task has no 'build-image' step")
	}

	if !strings.Contains(buildStep, "$(params.reproducible)") {
		t.Error("build script missing $(params.reproducible) reference")
	}
}

func TestPipelineParamSpec_Defaults(t *testing.T) {
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	wantDefaults := map[string]string{
		"reproducible":    "false",
		"task-bundle-ref": "",
		"custom-defines":  "",
		"aib-extra-args":  "",
		"secure-build":    "false",
	}
	for _, p := range pipeline.Spec.Params {
		if expected, ok := wantDefaults[p.Name]; ok {
			if p.Default == nil {
				t.Errorf("pipeline param %q has nil default, want %q", p.Name, expected)
				continue
			}
			if p.Default.StringVal != expected {
				t.Errorf("pipeline param %q default = %q, want %q", p.Name, p.Default.StringVal, expected)
			}
		}
	}
}

func TestPushTask_ParamSpec_Defaults(t *testing.T) {
	task := GeneratePushArtifactRegistryTask("test-ns", nil)

	wantDefaults := map[string]string{
		"reproducible":    "false",
		"task-bundle-ref": "",
		"custom-defines":  "",
		"aib-extra-args":  "",
		"secure-build":    "false",
	}
	for _, p := range task.Spec.Params {
		if expected, ok := wantDefaults[p.Name]; ok {
			if p.Default == nil {
				t.Errorf("push task param %q has nil default, want %q", p.Name, expected)
				continue
			}
			if p.Default.StringVal != expected {
				t.Errorf("push task param %q default = %q, want %q", p.Name, p.Default.StringVal, expected)
			}
		}
	}
}

// TestImagesResultFormat verifies the image@digest format Chains expects
func TestImagesResultFormat(t *testing.T) {
	// Simulate what the collect-images script produces
	containerURL := "registry.example.com/img:v1"
	containerDigest := "sha256:abc123"
	diskURL := "registry.example.com/disk:v1"
	diskDigest := "sha256:def456"

	result := containerURL + "@" + containerDigest + "\n" + diskURL + "@" + diskDigest

	lines := strings.Split(result, "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 image lines, got %d", len(lines))
	}
	for _, line := range lines {
		parts := strings.SplitN(line, "@", 2)
		if len(parts) != 2 {
			t.Errorf("line %q should contain exactly one '@' separator", line)
			continue
		}
		if !strings.HasPrefix(parts[1], "sha256:") {
			t.Errorf("digest %q should start with sha256:", parts[1])
		}
	}
}
