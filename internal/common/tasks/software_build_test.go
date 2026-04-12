package tasks

import (
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateSoftwareBuildPipeline_HasCorrectParams(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	wantParams := map[string]bool{
		"containerImage": false,
		"fetchCommand":   false, "fetchImage": false,
		"prebuildCommand": false, "prebuildImage": false,
		"buildCommand": false, "buildImage": false,
		"postbuildCommand": false, "postbuildImage": false,
		"deployCommand": false, "deployImage": false,
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

func TestGenerateSoftwareBuildPipeline_ConfigDefaultImage(t *testing.T) {
	config := &BuildConfig{DefaultImage: "fedora:40"}
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", config)

	for _, param := range p.Spec.Params {
		if param.Name == "containerImage" {
			if param.Default == nil || param.Default.StringVal != "fedora:40" {
				t.Fatalf("expected config default image fedora:40, got %v", param.Default)
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

func TestGenerateSoftwareBuildPipeline_ImagePullPolicy(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	for _, task := range p.Spec.Tasks {
		if task.TaskSpec == nil {
			t.Errorf("task %q: expected inline TaskSpec", task.Name)
			continue
		}
		for _, step := range task.TaskSpec.Steps {
			if step.ImagePullPolicy != corev1.PullIfNotPresent {
				t.Errorf("task %q step %q: expected ImagePullPolicy IfNotPresent, got %q",
					task.Name, step.Name, step.ImagePullPolicy)
			}
		}
	}
}

func TestGenerateSoftwareBuildPipeline_SecurityContext(t *testing.T) {
	p := GenerateSoftwareBuildPipeline("test-pipe", "ns", nil)

	for _, task := range p.Spec.Tasks {
		if task.TaskSpec == nil {
			continue
		}
		for _, step := range task.TaskSpec.Steps {
			if step.SecurityContext == nil {
				t.Errorf("task %q step %q: expected SecurityContext", task.Name, step.Name)
				continue
			}
			if step.SecurityContext.AllowPrivilegeEscalation == nil || *step.SecurityContext.AllowPrivilegeEscalation {
				t.Errorf("task %q step %q: expected AllowPrivilegeEscalation=false", task.Name, step.Name)
			}
		}
	}
}

func newTestSoftwareBuild() *automotivev1alpha1.SoftwareBuild {
	return &automotivev1alpha1.SoftwareBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-build",
			Namespace:  "default",
			Generation: 1,
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

func TestGenerateSoftwareBuildPipelineRun_DeterministicName(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Generation = 5
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	if pr.Name != "test-build-gen5" {
		t.Errorf("expected deterministic name test-build-gen5, got %q", pr.Name)
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

func TestGenerateSoftwareBuildPipelineRun_ConfigDefaultImage(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Runtime.Image = ""
	config := &BuildConfig{DefaultImage: "fedora:40"}
	pr := GenerateSoftwareBuildPipelineRun(sb, config)

	for _, p := range pr.Spec.Params {
		if p.Name == "containerImage" {
			if p.Value.StringVal != "fedora:40" {
				t.Fatalf("expected config default image fedora:40, got %q", p.Value.StringVal)
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

func TestGenerateSoftwareBuildPipelineRun_InvalidPVCSizeFallback(t *testing.T) {
	sb := newTestSoftwareBuild()
	config := &BuildConfig{PVCSize: "not-a-size"}
	pr := GenerateSoftwareBuildPipelineRun(sb, config)

	ws := pr.Spec.Workspaces[0]
	storageReq := ws.VolumeClaimTemplate.Spec.Resources.Requests["storage"]
	if storageReq.String() != "1Gi" {
		t.Errorf("expected fallback PVC size 1Gi, got %s", storageReq.String())
	}
}

func TestGenerateSoftwareBuildPipelineRun_PVCSource(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Source = automotivev1alpha1.SoftwareBuildSourceSpec{
		Type: automotivev1alpha1.SoftwareBuildSourcePVC,
		PVC:  &automotivev1alpha1.SoftwareBuildPVCSource{ClaimName: "my-workspace"},
	}
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	if len(pr.Spec.Workspaces) != 1 {
		t.Fatalf("expected 1 workspace, got %d", len(pr.Spec.Workspaces))
	}
	ws := pr.Spec.Workspaces[0]
	if ws.VolumeClaimTemplate != nil {
		t.Fatal("PVC source should not use VolumeClaimTemplate")
	}
	if ws.PersistentVolumeClaim == nil {
		t.Fatal("PVC source should use PersistentVolumeClaim binding")
	}
	if ws.PersistentVolumeClaim.ClaimName != "my-workspace" {
		t.Errorf("expected claimName my-workspace, got %s", ws.PersistentVolumeClaim.ClaimName)
	}
	if ws.SubPath != "" {
		t.Errorf("default path should not set SubPath, got %q", ws.SubPath)
	}
}

func TestGenerateSoftwareBuildPipelineRun_PVCSourceWithSubPath(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Source = automotivev1alpha1.SoftwareBuildSourceSpec{
		Type: automotivev1alpha1.SoftwareBuildSourcePVC,
		PVC:  &automotivev1alpha1.SoftwareBuildPVCSource{ClaimName: "my-workspace", Path: "src/project"},
	}
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	ws := pr.Spec.Workspaces[0]
	if ws.SubPath != "src/project" {
		t.Errorf("expected SubPath src/project, got %q", ws.SubPath)
	}
}

func TestGenerateSoftwareBuildPipelineRun_PVCSourceRootPathNoSubPath(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Source = automotivev1alpha1.SoftwareBuildSourceSpec{
		Type: automotivev1alpha1.SoftwareBuildSourcePVC,
		PVC:  &automotivev1alpha1.SoftwareBuildPVCSource{ClaimName: "my-workspace", Path: "/"},
	}
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	ws := pr.Spec.Workspaces[0]
	if ws.SubPath != "" {
		t.Errorf("root path should not set SubPath, got %q", ws.SubPath)
	}
}

func TestGenerateSoftwareBuildPipelineRun_GitSourcePrependsClone(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Source = automotivev1alpha1.SoftwareBuildSourceSpec{
		Type: automotivev1alpha1.SoftwareBuildSourceGit,
		Git: &automotivev1alpha1.SoftwareBuildGitSource{
			URL:      "https://github.com/example/repo",
			Revision: "develop",
		},
	}
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	for _, p := range pr.Spec.Params {
		if p.Name == "fetchCommand" {
			if !strings.Contains(p.Value.StringVal, "git clone") {
				t.Errorf("fetchCommand should contain git clone, got %q", p.Value.StringVal)
			}
			if !strings.Contains(p.Value.StringVal, "'develop'") {
				t.Errorf("fetchCommand should contain quoted revision, got %q", p.Value.StringVal)
			}
			if !strings.Contains(p.Value.StringVal, "'https://github.com/example/repo'") {
				t.Errorf("fetchCommand should contain quoted repo URL, got %q", p.Value.StringVal)
			}
			return
		}
	}
	t.Fatal("fetchCommand param not found")
}

func TestGenerateSoftwareBuildPipelineRun_GitSourceDefaultRevision(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Source = automotivev1alpha1.SoftwareBuildSourceSpec{
		Type: automotivev1alpha1.SoftwareBuildSourceGit,
		Git: &automotivev1alpha1.SoftwareBuildGitSource{
			URL: "https://github.com/example/repo",
		},
	}
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	for _, p := range pr.Spec.Params {
		if p.Name == "fetchCommand" {
			if !strings.Contains(p.Value.StringVal, "'main'") {
				t.Errorf("fetchCommand should default to main revision, got %q", p.Value.StringVal)
			}
			return
		}
	}
	t.Fatal("fetchCommand param not found")
}

func TestGenerateSoftwareBuildPipelineRun_UnsafeRevisionSanitized(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Source = automotivev1alpha1.SoftwareBuildSourceSpec{
		Type: automotivev1alpha1.SoftwareBuildSourceGit,
		Git: &automotivev1alpha1.SoftwareBuildGitSource{
			URL:      "https://github.com/example/repo",
			Revision: "main; rm -rf /",
		},
	}
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	for _, p := range pr.Spec.Params {
		if p.Name == "fetchCommand" {
			if strings.Contains(p.Value.StringVal, "rm -rf") {
				t.Errorf("unsafe revision should be sanitized, got %q", p.Value.StringVal)
			}
			if !strings.Contains(p.Value.StringVal, "'main'") {
				t.Errorf("unsafe revision should fall back to main, got %q", p.Value.StringVal)
			}
			return
		}
	}
	t.Fatal("fetchCommand param not found")
}

func TestGenerateSoftwareBuildPipelineRun_Timeout(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.TimeoutSeconds = 3600
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	if pr.Spec.Timeouts == nil {
		t.Fatal("expected Timeouts to be set")
	}
	if pr.Spec.Timeouts.Pipeline == nil || pr.Spec.Timeouts.Pipeline.Duration.Minutes() != 60 {
		t.Errorf("expected 60min timeout, got %v", pr.Spec.Timeouts.Pipeline)
	}
}

func TestGenerateSoftwareBuildPipelineRun_TimeoutFromConfig(t *testing.T) {
	sb := newTestSoftwareBuild()
	config := &BuildConfig{BuildTimeoutMinutes: 45}
	pr := GenerateSoftwareBuildPipelineRun(sb, config)

	if pr.Spec.Timeouts == nil {
		t.Fatal("expected Timeouts to be set from config")
	}
	if pr.Spec.Timeouts.Pipeline == nil || pr.Spec.Timeouts.Pipeline.Duration.Minutes() != 45 {
		t.Errorf("expected 45min timeout, got %v", pr.Spec.Timeouts.Pipeline)
	}
}

func TestGenerateSoftwareBuildPipelineRun_NoTimeoutWhenZero(t *testing.T) {
	sb := newTestSoftwareBuild()
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	if pr.Spec.Timeouts != nil {
		t.Errorf("expected no Timeouts when zero, got %v", pr.Spec.Timeouts)
	}
}

func TestGenerateSoftwareBuildPipelineRun_ServiceAccountName(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Runtime.ServiceAccountName = "build-sa"
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	if pr.Spec.TaskRunTemplate.ServiceAccountName != "build-sa" {
		t.Errorf("expected ServiceAccountName build-sa, got %q", pr.Spec.TaskRunTemplate.ServiceAccountName)
	}
}

func TestGenerateSoftwareBuildPipelineRun_NoServiceAccountByDefault(t *testing.T) {
	sb := newTestSoftwareBuild()
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	if pr.Spec.TaskRunTemplate.ServiceAccountName != "" {
		t.Errorf("expected empty ServiceAccountName, got %q", pr.Spec.TaskRunTemplate.ServiceAccountName)
	}
}

func TestGenerateSoftwareBuildPipelineRun_PerStageImage(t *testing.T) {
	sb := newTestSoftwareBuild()
	sb.Spec.Stages.Build.Image = "gcc:14"
	pr := GenerateSoftwareBuildPipelineRun(sb, nil)

	paramMap := make(map[string]string)
	for _, p := range pr.Spec.Params {
		paramMap[p.Name] = p.Value.StringVal
	}

	if paramMap["buildImage"] != "gcc:14" {
		t.Errorf("expected buildImage gcc:14, got %q", paramMap["buildImage"])
	}
	if paramMap["fetchImage"] != "$(params.containerImage)" {
		t.Errorf("expected fetchImage to default to containerImage param ref, got %q", paramMap["fetchImage"])
	}
}
