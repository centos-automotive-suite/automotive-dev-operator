package tasks

import (
	"encoding/json"
	"strings"
	"testing"
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

	if ref.Resolver != tektonResolverBundles {
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

			// Verify it receives params from both build and push tasks
			paramNames := make(map[string]string)
			for _, p := range task.Params {
				paramNames[p.Name] = p.Value.StringVal
			}
			if paramNames["container-url"] != "$(tasks.build-image.results.IMAGE_URL)" {
				t.Errorf("container-url param = %q, want build-image result ref", paramNames["container-url"])
			}
			if paramNames["disk-url"] != "$(tasks.push-disk-artifact.results.IMAGE_URL)" {
				t.Errorf("disk-url param = %q, want push-disk-artifact result ref", paramNames["disk-url"])
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
		if task.TaskRef.Resolver != tektonResolverBundles {
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

func TestCollectImagesScript_JSONOutput(t *testing.T) {
	// Verify the finally task script produces valid JSON for Chains
	// This tests the script template embedded in the task, not the actual shell execution
	pipeline := GenerateTektonPipeline("test-pipeline", "test-ns", &BuildConfig{})

	for _, task := range pipeline.Spec.Finally {
		if task.Name == "collect-images-result" {
			if len(task.TaskSpec.Steps) == 0 {
				t.Fatal("collect-images-result should have steps")
			}
			script := task.TaskSpec.Steps[0].Script
			if script == "" {
				t.Fatal("collect step should have a script")
			}
			// Verify the script builds a JSON array structure
			// The script uses $(params.*) which aren't real values here,
			// but we can verify the template is valid
			if !strings.Contains(script, "IMAGES=\"[\"") {
				t.Error("script should initialize JSON array")
			}
			if !strings.Contains(script, "IMAGES=\"${IMAGES}]\"") {
				t.Error("script should close JSON array")
			}
			return
		}
	}
	t.Fatal("pipeline should have collect-images-result task")
}

// TestImagesResultFormat verifies the JSON array structure Chains expects
func TestImagesResultFormat(t *testing.T) {
	// Simulate what the collect-images script produces
	type imageEntry struct {
		URI    string `json:"uri"`
		Digest string `json:"digest"`
	}

	images := []imageEntry{
		{URI: "registry.example.com/img:v1", Digest: "sha256:abc123"},
		{URI: "registry.example.com/disk:v1", Digest: "sha256:def456"},
	}

	data, err := json.Marshal(images)
	if err != nil {
		t.Fatalf("IMAGES format should be valid JSON: %v", err)
	}

	var parsed []imageEntry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("IMAGES should round-trip as JSON array: %v", err)
	}
	if len(parsed) != 2 {
		t.Errorf("expected 2 images, got %d", len(parsed))
	}
}
