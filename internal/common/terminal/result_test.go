package terminal

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tekton "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	knative "knative.dev/pkg/apis/duck/v1"
)

func TestFinalizeBoundsAndImmutability(t *testing.T) {
	status := &api.ImageBuildStatus{Flash: &api.FlashOutcomeStatus{Enabled: true, State: "Failed", Message: strings.Repeat("é", 1100), LeaseID: strings.Repeat("x", 300)}}
	for range 70 {
		status.Artifacts = append(status.Artifacts, api.ArtifactStatus{Kind: "s3", URL: "s3://bucket/image", Digest: "etag"})
	}
	Finalize(status, "Failed", strings.Repeat("界", 1200))
	original := status.TerminalResult.DeepCopy()
	if utf8.RuneCountInString(original.Message) != 1024 || len(original.Artifacts) != 64 || original.Artifacts[0].Digest != "" || len(original.Flash.LeaseID) != 253 {
		t.Fatalf("unbounded result: %+v", original)
	}
	status.Artifacts[0].URL = "changed"
	status.Flash.Message = "changed"
	Finalize(status, "Completed", "changed")
	if !reflect.DeepEqual(original, status.TerminalResult) {
		t.Fatal("terminal result mutated")
	}
}

func TestStandaloneFlashCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, reason          string
		done, cancel, success bool
		want                  string
	}{
		{name: "pending cancellation", cancel: true, want: "Pending"},
		{name: "running cancellation", reason: "Running", cancel: true, want: "Running"},
		{name: "condition cancellation", reason: string(tekton.TaskRunReasonCancelled), done: true, want: "Cancelled"},
		{name: "status cancellation", cancel: true, done: true, want: "Cancelled"},
		{name: "failure", reason: "Failed", done: true, want: "Failed"},
		{name: "success wins late intent", cancel: true, success: true, done: true, want: "Completed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &tekton.TaskRun{}
			now := metav1.Now()
			if tc.cancel {
				tr.Spec.Status = tekton.TaskRunSpecStatusCancelled
			}
			if tc.reason == "Running" || tc.done {
				tr.Status.StartTime = &now
			}
			if tc.done {
				tr.Status.CompletionTime = &now
			}
			state := corev1.ConditionFalse
			if tc.success {
				state = corev1.ConditionTrue
			}
			tr.Status.Conditions = knative.Conditions{{Type: "Succeeded", Status: state, Reason: tc.reason}}
			tr.Status.Results = []tekton.TaskRunResult{{Name: "lease-id", Value: tekton.ParamValue{Type: tekton.ParamTypeString, StringVal: "lease"}}}
			phase, _ := TaskPhase(tr)
			if phase != tc.want {
				t.Fatalf("phase %s, want %s", phase, tc.want)
			}
			result := FlashResult(tr)
			if tc.done {
				if result == nil || result.Phase != tc.want || result.Flash.LeaseID != "lease" {
					t.Fatalf("result: %+v", result)
				}
			} else if result != nil {
				t.Fatal("finalized active flash")
			}
		})
	}
}

func TestFlashState(t *testing.T) {
	for phase, want := range map[string]string{
		"Pending":                    "NotStarted",
		"Running":                    "Running",
		api.ImageBuildPhaseCompleted: "Succeeded",
		api.ImageBuildPhaseFailed:    "Failed",
		api.ImageBuildPhaseCancelled: "Cancelled",
	} {
		if got := FlashState(phase); got != want {
			t.Errorf("FlashState(%q) = %q, want %q", phase, got, want)
		}
	}
}
