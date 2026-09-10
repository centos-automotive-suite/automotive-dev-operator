package imagebuild

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/terminal"
	tekton "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	knative "knative.dev/pkg/apis/duck/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func resultTask(name, reason string, values map[string]string) *tekton.TaskRun {
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	tr := &tekton.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test-ns"}}
	tr.Status.StartTime = &now
	if reason != "Running" {
		tr.Status.CompletionTime = &now
	}
	state := corev1.ConditionFalse
	if reason == "Succeeded" {
		state = corev1.ConditionTrue
	}
	if reason == "Running" {
		state = corev1.ConditionUnknown
	}
	tr.Status.Conditions = knative.Conditions{{Type: "Succeeded", Status: state, Reason: reason, Message: reason}}
	for key, value := range values {
		tr.Status.Results = append(tr.Status.Results, tekton.TaskRunResult{Name: key, Value: tekton.ParamValue{Type: tekton.ParamTypeString, StringVal: value}})
	}
	return tr
}

func terminalBuild() *api.ImageBuild {
	return &api.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "result-build", Namespace: "test-ns"},
		Spec:   api.ImageBuildSpec{Flash: &api.FlashSpec{ClientConfigSecretRef: "device"}},
		Status: api.ImageBuildStatus{Phase: phaseBuilding, PipelineRunName: "pipeline"}}
}

func resultPipeline(ib *api.ImageBuild, reason string, children ...*tekton.TaskRun) *tekton.PipelineRun {
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	pr := &tekton.PipelineRun{ObjectMeta: metav1.ObjectMeta{Name: ib.Status.PipelineRunName, Namespace: ib.Namespace}}
	pr.Status.CompletionTime = &now
	state := corev1.ConditionFalse
	if reason == "Succeeded" {
		state = corev1.ConditionTrue
	}
	pr.Status.Conditions = knative.Conditions{{Type: "Succeeded", Status: state, Reason: reason}}
	for _, tr := range children {
		pr.Status.ChildReferences = append(pr.Status.ChildReferences, tekton.ChildStatusReference{Name: tr.Name, PipelineTaskName: tr.Name})
	}
	return pr
}

func TestPipelineTerminalArtifacts(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name, failed string
		count        int
		flash        string
	}{
		{"success", "", 3, "Succeeded"},
		{"build failure", "build-image", 0, "NotStarted"},
		{"disk publication failure", "push-disk-artifact", 1, "NotStarted"},
		{"s3 publication failure", "push-disk-artifact-s3", 2, "NotStarted"},
		{"flash failure after publication", "flash-image", 3, "Failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ib := terminalBuild()
			stages := []string{"build-image", "push-disk-artifact", "push-disk-artifact-s3", "flash-image"}
			values := []map[string]string{{"IMAGE_URL": "registry/container", "IMAGE_DIGEST": digest}, {"IMAGE_URL": "registry/disk"}, {"S3_URL": "s3://bucket/image"}, {"lease-id": "lease-42"}}
			children := []*tekton.TaskRun{}
			for i, stage := range stages {
				reason := "Succeeded"
				v := values[i]
				if stage == tc.failed {
					reason = "Failed"
					if stage != "flash-image" {
						v = nil
					}
				}
				children = append(children, resultTask(stage, reason, v))
				if stage == tc.failed {
					break
				}
			}
			reason := "Succeeded"
			if tc.failed != "" {
				reason = "Failed"
			}
			pr := resultPipeline(ib, reason, children...)
			objects := []client.Object{ib, pr}
			for _, tr := range children {
				objects = append(objects, tr)
			}
			r := newTestReconciler(objects...)
			if _, err := r.checkBuildProgress(context.Background(), ib); err != nil {
				t.Fatal(err)
			}
			result := ib.Status.TerminalResult
			if result == nil || len(result.Artifacts) != tc.count || result.Flash.State != tc.flash {
				t.Fatalf("unexpected result: %+v", result)
			}
			want := phaseCompleted
			if tc.failed != "" {
				want = phaseFailed
			}
			if ib.Status.Phase != want || result.Phase != want || !result.CompletedAt.Equal(pr.Status.CompletionTime) {
				t.Fatalf("terminal status: %+v", ib.Status)
			}
			if tc.count > 0 && result.Artifacts[0].Digest != digest {
				t.Fatal("lost available digest")
			}
			if tc.count > 1 && result.Artifacts[1].Digest != "" {
				t.Fatal("fabricated disk digest")
			}
			if tc.flash != "NotStarted" && result.Flash.LeaseID != "lease-42" {
				t.Fatal("lost flash lease")
			}
		})
	}
}

func TestTerminalCollectionUsesAuthoritativeChildState(t *testing.T) {
	ib := terminalBuild()
	running := resultTask("flash-image", "Running", nil)
	completed := resultTask("flash-image", "Succeeded", map[string]string{"lease-id": "lease-final"})
	pr := resultPipeline(ib, "Succeeded", running)
	r := newTestReconciler(ib, pr, running)
	r.APIReader = newTestReconciler(ib.DeepCopy(), pr.DeepCopy(), completed).Client

	if _, err := r.checkBuildProgress(context.Background(), ib); err != nil {
		t.Fatal(err)
	}
	if ib.Status.TerminalResult == nil || ib.Status.TerminalResult.Flash.State != "Succeeded" ||
		ib.Status.TerminalResult.Flash.LeaseID != "lease-final" {
		t.Fatalf("terminal result did not use authoritative child: %+v", ib.Status.TerminalResult)
	}
}

func TestTerminalCollectionWaitsForAuthoritativeChild(t *testing.T) {
	ib := terminalBuild()
	running := resultTask("flash-image", "Running", nil)
	pr := resultPipeline(ib, "Succeeded", running)
	r := newTestReconciler(ib, pr, running)
	r.APIReader = newTestReconciler(ib.DeepCopy(), pr.DeepCopy(), running.DeepCopy()).Client

	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ib)})
	if err != nil {
		t.Fatal(err)
	}
	stored := &api.ImageBuild{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(ib), stored); err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 5*time.Second || stored.Status.TerminalResult != nil {
		t.Fatalf("result=%+v terminal=%+v", result, stored.Status.TerminalResult)
	}
}

func TestActivePipelineDoesNotPatchStatus(t *testing.T) {
	ib := terminalBuild()
	pr := resultPipeline(ib, "Running")
	pr.Status.CompletionTime = nil
	r := newTestReconciler(ib, pr)
	patched := false
	r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if subResource == "status" {
				patched = true
			}
			return c.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		},
	})

	result, err := r.checkBuildProgress(context.Background(), ib)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 30*time.Second || patched {
		t.Fatalf("result=%+v patched=%t", result, patched)
	}
}

func TestTerminalMissingChildrenAndResults(t *testing.T) {
	ib := terminalBuild()
	ib.Status.Phase = "Pending"
	build := resultTask("build-image", "Succeeded", map[string]string{"IMAGE_URL": "registry/container"})
	pr := resultPipeline(ib, "Failed", build, resultTask("flash-image", "Failed", nil))
	r := newTestReconciler(ib, pr, build)
	ctx := context.Background()
	if err := r.updateStatus(ctx, ib, phaseBuilding, "Building"); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, build); err != nil {
		t.Fatal(err)
	}
	if _, err := r.checkBuildProgress(ctx, ib); err != nil {
		t.Fatal(err)
	}
	result := ib.Status.TerminalResult
	if result == nil || len(result.Artifacts) != 1 || result.Artifacts[0].Digest != "" || result.Flash != nil {
		t.Fatalf("missing children: %+v", result)
	}
}

func TestLegacyTerminalResults(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "flash failure"}[failure], func(t *testing.T) {
			ib := terminalBuild()
			ib.Status.Phase = "Flashing"
			ib.Status.PushTaskRunName = "push"
			ib.Status.FlashTaskRunName = "flash"
			build := resultTask("build-image", "Succeeded", map[string]string{"IMAGE_URL": "registry/container"})
			pr := resultPipeline(ib, "Succeeded", build)
			push := resultTask("push", "Succeeded", map[string]string{"IMAGE_URL": "registry/disk"})
			reason := "Succeeded"
			if failure {
				reason = "Failed"
			}
			flash := resultTask("flash", reason, map[string]string{"lease-id": "legacy-lease"})
			r := newTestReconciler(ib, pr, build, push, flash)
			if _, err := r.handleFlashingState(context.Background(), ib); err != nil {
				t.Fatal(err)
			}
			result := ib.Status.TerminalResult
			if result == nil || len(result.Artifacts) != 2 || result.Flash.LeaseID != "legacy-lease" {
				t.Fatalf("legacy result: %+v", result)
			}
		})
	}
}

func TestCollectNamedStageCapturesOnlySettledCompletion(t *testing.T) {
	ib := terminalBuild()
	ib.Status.Phase = api.ImageBuildPhasePushing
	push := resultTask("push", "Succeeded", nil)
	reader := newTestReconciler(push).Client

	if err := collectNamedStage(context.Background(), reader, ib, push.Name, pipelineTaskPushDisk, false); err != nil {
		t.Fatal(err)
	}
	if ib.Status.CompletionTime != nil {
		t.Fatal("live collection set completion time")
	}
	if err := collectNamedStage(context.Background(), reader, ib, push.Name, pipelineTaskPushDisk, true); err != nil {
		t.Fatal(err)
	}
	if ib.Status.CompletionTime == nil || !ib.Status.CompletionTime.Equal(push.Status.CompletionTime) {
		t.Fatalf("settled completion = %v, want %v", ib.Status.CompletionTime, push.Status.CompletionTime)
	}
}

func TestCancellationWaitsForExecution(t *testing.T) {
	for _, stage := range []string{"Pending", "Building", "Pushing", "Flashing"} {
		t.Run(stage, func(t *testing.T) {
			ib := terminalBuild()
			ib.Status.Phase = stage
			ib.Status.PipelineRunName = ""
			ib.Annotations = map[string]string{terminal.CancellationAnnotation: "true"}
			objects := []client.Object{ib}
			var tr *tekton.TaskRun
			if stage != "Pending" {
				tr = resultTask("active", "Running", nil)
				tr.Labels = map[string]string{api.LabelImageBuildName: ib.Name}
				objects = append(objects, tr)
				if stage == "Pushing" {
					ib.Status.PushTaskRunName = tr.Name
				}
				if stage == "Flashing" {
					ib.Status.FlashTaskRunName = tr.Name
				}
			}
			r := newTestReconciler(objects...)
			ctx := context.Background()
			result, err := r.handleCancellation(ctx, ib)
			if err != nil {
				t.Fatal(err)
			}
			if tr != nil {
				if ib.Status.TerminalResult != nil || ib.Status.CompletionTime != nil || result.RequeueAfter == 0 {
					t.Fatal("cancellation finalized active execution")
				}
				if err := r.Get(ctx, client.ObjectKeyFromObject(tr), tr); err != nil {
					t.Fatal(err)
				}
				if !tr.IsCancelled() {
					t.Fatal("task not cancelled")
				}
				now := metav1.Now()
				tr.Status.CompletionTime = &now
				tr.Status.Conditions[0].Status = corev1.ConditionFalse
				tr.Status.Conditions[0].Reason = string(tekton.TaskRunReasonCancelled)
				if err := r.Status().Update(ctx, tr); err != nil {
					t.Fatal(err)
				}
				if _, err := r.handleCancellation(ctx, ib); err != nil {
					t.Fatal(err)
				}
			}
			if ib.Status.TerminalResult == nil || ib.Status.TerminalResult.Phase != phaseCancelled {
				t.Fatalf("no cancelled result: %+v", ib.Status)
			}
		})
	}
}

func TestExpiryPreservesTerminalResult(t *testing.T) {
	for _, phase := range []string{phaseCompleted, phaseFailed, phaseCancelled} {
		t.Run(phase, func(t *testing.T) {
			ib := terminalBuild()
			ib.Status.PipelineRunName = ""
			r := newTestReconciler(ib)
			ctx := context.Background()
			if err := r.updateStatus(ctx, ib, phase, "original"); err != nil {
				t.Fatal(err)
			}
			original := ib.Status.TerminalResult.DeepCopy()
			if err := r.updateStatus(ctx, ib, api.ImageBuildPhaseExpired, "expired"); err != nil {
				t.Fatal(err)
			}
			if ib.Status.Phase != api.ImageBuildPhaseExpired || !reflect.DeepEqual(original, ib.Status.TerminalResult) {
				t.Fatal("expiry modified terminal record")
			}
		})
	}
}

func TestPipelineCancellationSettlement(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "completed before cancellation"}[success], func(t *testing.T) {
			ib := terminalBuild()
			ib.Annotations = map[string]string{terminal.CancellationAnnotation: "true"}
			child := resultTask("build-image", "Running", map[string]string{"IMAGE_URL": "registry/published"})
			pr := resultPipeline(ib, "Running", child)
			pr.Status.CompletionTime = nil
			r := newTestReconciler(ib, pr, child)
			ctx := context.Background()
			result, err := r.handleCancellation(ctx, ib)
			if err != nil {
				t.Fatal(err)
			}
			if result.RequeueAfter == 0 || ib.Status.TerminalResult != nil {
				t.Fatal("pipeline cancelled before settlement")
			}
			if err := r.Get(ctx, client.ObjectKeyFromObject(pr), pr); err != nil {
				t.Fatal(err)
			}
			if !pr.IsCancelled() {
				t.Fatal("pipeline intent missing")
			}
			now := metav1.Now()
			pr.Status.CompletionTime = &now
			pr.Status.Conditions[0].Reason = string(tekton.PipelineRunReasonCancelled)
			if success {
				pr.Status.Conditions[0].Status = corev1.ConditionTrue
			}
			if err := r.Status().Update(ctx, pr); err != nil {
				t.Fatal(err)
			}
			// A terminal parent must not hide a still-active child during cancellation.
			if result, err := r.handleCancellation(ctx, ib); err != nil || result.RequeueAfter == 0 {
				t.Fatalf("active child: %v %v", result, err)
			}
			if err := r.Get(ctx, client.ObjectKeyFromObject(child), child); err != nil {
				t.Fatal(err)
			}
			child.Status.CompletionTime = &now
			child.Status.Conditions[0].Status = corev1.ConditionFalse
			if err := r.Status().Update(ctx, child); err != nil {
				t.Fatal(err)
			}
			if _, err := r.handleCancellation(ctx, ib); err != nil {
				t.Fatal(err)
			}
			want := phaseCancelled
			if success {
				want = phaseCompleted
			}
			if ib.Status.TerminalResult == nil || ib.Status.TerminalResult.Phase != want || len(ib.Status.TerminalResult.Artifacts) != 1 {
				t.Fatalf("result: %+v", ib.Status.TerminalResult)
			}
		})
	}
}

func TestCancellationSelectsLatestPipelineRun(t *testing.T) {
	ib := terminalBuild()
	ib.Status.PipelineRunName = ""
	old := &tekton.PipelineRun{ObjectMeta: metav1.ObjectMeta{
		Name: "old", Namespace: ib.Namespace, CreationTimestamp: metav1.NewTime(time.Unix(1, 0)),
		Labels: map[string]string{api.LabelImageBuildName: ib.Name},
	}}
	latest := &tekton.PipelineRun{ObjectMeta: metav1.ObjectMeta{
		Name: "latest", Namespace: ib.Namespace, CreationTimestamp: metav1.NewTime(time.Unix(2, 0)),
		Labels: map[string]string{api.LabelImageBuildName: ib.Name},
	}}
	r := newTestReconciler(ib, old, latest)

	if _, err := r.handleCancellation(context.Background(), ib); err != nil {
		t.Fatal(err)
	}
	if ib.Status.PipelineRunName != latest.Name {
		t.Fatalf("PipelineRunName = %q, want %q", ib.Status.PipelineRunName, latest.Name)
	}
}

func TestLegacyPushTerminalResult(t *testing.T) {
	for _, reason := range []string{"Succeeded", "Failed", string(tekton.TaskRunReasonCancelled)} {
		t.Run(reason, func(t *testing.T) {
			ib := terminalBuild()
			ib.Spec.Flash = nil
			ib.Status.Phase = "Pushing"
			ib.Status.PushTaskRunName = "push"
			build := resultTask("build-image", "Succeeded", map[string]string{"IMAGE_URL": "registry/container"})
			pr := resultPipeline(ib, "Succeeded", build)
			push := resultTask("push", reason, nil)
			if reason == "Succeeded" {
				push.Status.Results = []tekton.TaskRunResult{{Name: "IMAGE_URL", Value: tekton.ParamValue{Type: tekton.ParamTypeString, StringVal: "registry/disk"}}}
			}
			r := newTestReconciler(ib, pr, build, push)
			if _, err := r.handlePushingState(context.Background(), ib); err != nil {
				t.Fatal(err)
			}
			want, count := phaseFailed, 1
			if reason == "Succeeded" {
				want, count = phaseCompleted, 2
			}
			if reason == string(tekton.TaskRunReasonCancelled) {
				want = phaseCancelled
			}
			if ib.Status.TerminalResult == nil || ib.Status.TerminalResult.Phase != want || len(ib.Status.TerminalResult.Artifacts) != count {
				t.Fatalf("result: %+v", ib.Status.TerminalResult)
			}
			if reason == string(tekton.TaskRunReasonCancelled) && !strings.HasPrefix(ib.Status.TerminalResult.Message, "Push to registry cancelled") {
				t.Fatalf("cancellation message: %q", ib.Status.TerminalResult.Message)
			}
		})
	}
}

func TestLegacyFlashCancellationMessage(t *testing.T) {
	ib := terminalBuild()
	ib.Status.Phase = api.ImageBuildPhaseFlashing
	ib.Status.FlashTaskRunName = "flash"
	flash := resultTask("flash", string(tekton.TaskRunReasonCancelled), nil)
	r := newTestReconciler(ib, resultPipeline(ib, "Succeeded"), flash)

	if _, err := r.handleFlashingState(context.Background(), ib); err != nil {
		t.Fatal(err)
	}
	if ib.Status.TerminalResult == nil || !strings.HasPrefix(ib.Status.TerminalResult.Message, "Flash to device cancelled") {
		t.Fatalf("cancellation result: %+v", ib.Status.TerminalResult)
	}
}
