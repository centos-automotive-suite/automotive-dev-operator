package tasks

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateSoftwareBuildPipeline_HasCorrectParams(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	wantParams := map[string]bool{
		"containerImage":  false,
		"fetchCommand":    false,
		"prebuildCommand": false,
		"buildCommand":    false,
		"postbuildCommand": false,
		"deployCommand":   false,
	}
	for _, param := range p.Spec.Params {
		if _, ok := wantParams[param.Name]; ok {
			wantParams[param.Name] = true
		}
	}
	for name, found := range wantParams {
		if !found {
			t.Errorf("missing pipeline param %q", name)
		}
	}
}

func TestGenerateSoftwareBuildPipeline_DefaultImage(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	for _, param := range p.Spec.Params {
		if param.Name == "containerImage" {
			if param.Default == nil || param.Default.StringVal != "ubuntu:24.04" {
				t.Fatalf("expected default containerImage ubuntu:24.04, got %v", param.Default)
			}
			return
		}
	}
	t.Fatal("containerImage param not found")
}

func TestGenerateSoftwareBuildPipeline_FiveSequentialTasks(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	if len(p.Spec.Tasks) != 5 {
		t.Fatalf("expected 5 tasks, got %d", len(p.Spec.Tasks))
	}

	expected := []string{"fetch", "prebuild", "build", "postbuild", "deploy"}
	for i, task := range p.Spec.Tasks {
		if task.Name != expected[i] {
			t.Errorf("task %d: got name %q, want %q", i, task.Name, expected[i])
		}
		if i > 0 && (len(task.RunAfter) == 0 || task.RunAfter[0] != expected[i-1]) {
			t.Errorf("task %q should runAfter %q", task.Name, expected[i-1])
		}
	}
}

func TestGenerateSoftwareBuildPipeline_Labels(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	if p.Labels["app.kubernetes.io/managed-by"] != "automotive-dev-operator" {
		t.Errorf("expected managed-by label, got %v", p.Labels)
	}
}

func TestGenerateSoftwareBuildPipeline_Workspace(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	if len(p.Spec.Workspaces) != 1 || p.Spec.Workspaces[0].Name != "shared-workspace" {
		t.Fatalf("expected one workspace named shared-workspace, got %v", p.Spec.Workspaces)
	}
}

func newTestSoftwareBuild() *automotivev1alpha1.SoftwareBuild {
	return &automotivev1alpha1.SoftwareBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build",
			Namespace: "default",
		},
		Spec: automotivev1alpha1.SoftwareBuildSpec{
			Runtime: automotivev1alpha1.SoftwareBuildRuntimeSpec{Image: "ghcr.io/zephyrproject-rtos/ci-base:latest"},
			Stages: automotivev1alpha1.SoftwareBuildPipelineStages{
				Fetch:     automotivev1alpha1.SoftwareBuildStageSpec{Command: "west init -l . && west update"},
				Prebuild:  automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo prebuild"},
				Build:     automotivev1alpha1.SoftwareBuildStageSpec{Command: "west build -b native_sim app"},
				Postbuild: automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo postbuild"},
				Deploy:    automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo deploy"},
			},
		},
	}
}

func TestGenerateSoftwareBuildPipelineRun_PipelineRef(t *testing.T) {
	pr := GenerateSoftwareBuildPipelineRun(newTestSoftwareBuild(), nil)

	if pr.Spec.PipelineRef == nil || pr.Spec.PipelineRef.Name != SoftwareBuildPipelineName {
		t.Fatalf("expected pipelineRef %q, got %v", SoftwareBuildPipelineName, pr.Spec.PipelineRef)
	}
}

func TestGenerateSoftwareBuildPipelineRun_Params(t *testing.T) {
	sb := newTestSoftwareBuild()
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	paramMap := make(map[string]string)
	for _, p := range pr.Spec.Params {
		paramMap[p.Name] = p.Value.StringVal
	}

	if paramMap["containerImage"] != "ghcr.io/zephyrproject-rtos/ci-base:latest" {
		t.Errorf("unexpected containerImage: %s", paramMap["containerImage"])
	}
	if paramMap["buildCommand"] != "west build -b native_sim app" {
		t.Errorf("unexpected buildCommand: %s", paramMap["buildCommand"])
	}
	if paramMap["fetchCommand"] != "west init -l . && west update" {
		t.Errorf("unexpected fetchCommand: %s", paramMap["fetchCommand"])
	}
}

func TestGenerateSoftwareBuildPipelineRun_DefaultImage(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Runtime.Image = ""
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	for _, p := range pr.Spec.Params {
		if p.Name == "containerImage" {
			if p.Value.StringVal != "ubuntu:24.04" {
				t.Fatalf("expected default image ubuntu:24.04, got %q", p.Value.StringVal)
			}
			return
		}
	}
	t.Fatal("containerImage param not found")
}

func TestGenerateSoftwareBuildPipelineRun_Labels(t *testing.T) {
	pr := GenerateSoftwareBuildPipelineRun(newTestSoftwareBuild(), nil)

	if pr.Labels["automotive.sdv.cloud.redhat.com/softwarebuild"] != "test-build" {
		t.Errorf("expected softwarebuild label, got %v", pr.Labels)
	}
}

func TestGenerateSoftwareBuildPipelineRun_Workspace(t *testing.T) {
	pr := GenerateSoftwareBuildPipelineRun(newTestSoftwareBuild(), nil)

	if len(pr.Spec.Workspaces) != 1 {
		t.Fatalf("expected 1 workspace, got %d", len(pr.Spec.Workspaces))
	}
	ws := pr.Spec.Workspaces[0]
	if ws.Name != "shared-workspace" {
		t.Errorf("expected workspace shared-workspace, got %s", ws.Name)
	}
	if ws.VolumeClaimTemplate == nil {
		t.Fatal("expected volumeClaimTemplate")
	}
}

func TestGenerateSoftwareBuildPipelineRun_CustomPVCSize(t *testing.T) {
	sb := newTestSoftwareBuild()
	config := &BuildConfig{PVCSize: "10Gi"}
	pr := GenerateSoftwareBuildPipelineRun(sb, config)

	ws := pr.Spec.Workspaces[0]
	storageReq := ws.VolumeClaimTemplate.Spec.Resources.Requests["storage"]
	if storageReq.String() != "10Gi" {
		t.Errorf("expected PVC size 10Gi, got %s", storageReq.String())
	}
}
