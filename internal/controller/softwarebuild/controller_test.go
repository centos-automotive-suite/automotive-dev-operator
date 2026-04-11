package softwarebuild

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	knativeapis "knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
)

func newSB() *automotivev1alpha1.SoftwareBuild {
	return &automotivev1alpha1.SoftwareBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Generation: 3},
		Spec: automotivev1alpha1.SoftwareBuildSpec{
			Destination: automotivev1alpha1.SoftwareBuildDestinationSpec{
				Path: "/workspace/artifacts",
			},
		},
	}
}

func prWithCondition(status corev1.ConditionStatus, reason, message string) *tektonv1.PipelineRun {
	return &tektonv1.PipelineRun{
		Status: tektonv1.PipelineRunStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{
					{
						Type:    knativeapis.ConditionSucceeded,
						Status:  status,
						Reason:  reason,
						Message: message,
					},
				},
			},
		},
	}
}

func TestSyncStatusFromPipelineRun_Succeeded(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()

	pr := prWithCondition(corev1.ConditionTrue, "Completed", "All tasks finished")
	pr.Status.PipelineRunStatusFields = tektonv1.PipelineRunStatusFields{
		ChildReferences: []tektonv1.ChildStatusReference{
			{Name: "taskrun-build", PipelineTaskName: "build"},
		},
	}

	r.syncStatusFromPipelineRun(sb, pr)

	if sb.Status.Phase != automotivev1alpha1.SoftwareBuildPhaseSucceeded {
		t.Fatalf("expected Succeeded, got %s", sb.Status.Phase)
	}
	if sb.Status.ArtifactURI != "/workspace/artifacts" {
		t.Fatalf("expected artifactURI to be populated")
	}
	if len(sb.Status.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(sb.Status.Stages))
	}
	if sb.Status.Stages[0].Name != "build" {
		t.Errorf("expected stage name build, got %s", sb.Status.Stages[0].Name)
	}
}

func TestSyncStatusFromPipelineRun_Failed(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()

	pr := prWithCondition(corev1.ConditionFalse, "TaskRunFailed", "build task failed")

	r.syncStatusFromPipelineRun(sb, pr)

	if sb.Status.Phase != automotivev1alpha1.SoftwareBuildPhaseFailed {
		t.Fatalf("expected Failed, got %s", sb.Status.Phase)
	}
	if sb.Status.FailureReason != "TaskRunFailed" {
		t.Fatalf("expected FailureReason TaskRunFailed, got %s", sb.Status.FailureReason)
	}
}

func TestSyncStatusFromPipelineRun_Running(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()

	pr := &tektonv1.PipelineRun{
		Status: tektonv1.PipelineRunStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{},
			},
		},
	}

	r.syncStatusFromPipelineRun(sb, pr)

	if sb.Status.Phase != automotivev1alpha1.SoftwareBuildPhaseRunning {
		t.Fatalf("expected Running, got %s", sb.Status.Phase)
	}
}

func TestSyncStatusFromPipelineRun_ConditionSet(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()

	pr := prWithCondition(corev1.ConditionTrue, "Succeeded", "done")

	r.syncStatusFromPipelineRun(sb, pr)

	if len(sb.Status.Conditions) == 0 {
		t.Fatal("expected at least one condition")
	}
	found := false
	for _, c := range sb.Status.Conditions {
		if c.Type == conditionReady {
			found = true
			if c.Status != metav1.ConditionTrue {
				t.Errorf("expected Ready=True, got %s", c.Status)
			}
		}
	}
	if !found {
		t.Fatal("Ready condition not found")
	}
}

func TestSyncStatusFromPipelineRun_FailedConditionSetsReadyFalse(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()

	pr := prWithCondition(corev1.ConditionFalse, "TaskRunFailed", "build step failed")

	r.syncStatusFromPipelineRun(sb, pr)

	if sb.Status.Phase != automotivev1alpha1.SoftwareBuildPhaseFailed {
		t.Fatalf("expected Failed, got %s", sb.Status.Phase)
	}

	found := false
	for _, c := range sb.Status.Conditions {
		if c.Type == conditionReady {
			found = true
			if c.Status != metav1.ConditionFalse {
				t.Errorf("expected Ready=False on failure, got %s", c.Status)
			}
			if c.Reason != "TaskRunFailed" {
				t.Errorf("expected reason TaskRunFailed, got %s", c.Reason)
			}
		}
	}
	if !found {
		t.Fatal("Ready condition not found")
	}
}

func TestSyncStatusFromPipelineRun_ObservedGenerationTracked(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()
	sb.Generation = 7

	pr := prWithCondition(corev1.ConditionTrue, "Completed", "all done")
	r.syncStatusFromPipelineRun(sb, pr)

	for _, c := range sb.Status.Conditions {
		if c.Type == conditionReady {
			if c.ObservedGeneration != 7 {
				t.Errorf("expected ObservedGeneration=7, got %d", c.ObservedGeneration)
			}
			return
		}
	}
	t.Fatal("Ready condition not found")
}

func TestSyncStatusFromPipelineRun_StagesPopulatedFromChildRefs(t *testing.T) {
	r := &SoftwareBuildReconciler{}
	sb := newSB()

	pr := prWithCondition(corev1.ConditionTrue, "Completed", "done")
	pr.Status.PipelineRunStatusFields = tektonv1.PipelineRunStatusFields{
		ChildReferences: []tektonv1.ChildStatusReference{
			{Name: "tr-fetch", PipelineTaskName: "fetch"},
			{Name: "tr-build", PipelineTaskName: "build"},
			{Name: "tr-deploy", PipelineTaskName: "deploy"},
		},
	}

	r.syncStatusFromPipelineRun(sb, pr)

	if len(sb.Status.Stages) != 3 {
		t.Fatalf("expected 3 stages, got %d", len(sb.Status.Stages))
	}

	expectedNames := []string{"fetch", "build", "deploy"}
	for i, s := range sb.Status.Stages {
		if s.Name != expectedNames[i] {
			t.Errorf("stage %d: got %q, want %q", i, s.Name, expectedNames[i])
		}
	}
}
