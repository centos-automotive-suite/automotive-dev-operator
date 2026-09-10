package imagebuild

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/terminal"
	tekton "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	pipelineTaskPushDisk = "push-disk-artifact"
	pipelineTaskFlash    = "flash-image"
)

var errTerminalResultsPending = stderrors.New("terminal execution results are not settled")

func addArtifact(status *api.ImageBuildStatus, kind, url, digest string) {
	if url == "" {
		return
	}
	for i, existing := range status.Artifacts {
		if existing.Kind == kind && existing.URL == url {
			if digest != "" {
				status.Artifacts[i].Digest = digest
			}
			return
		}
	}
	status.Artifacts = append(status.Artifacts, api.ArtifactStatus{Kind: kind, URL: url, Digest: digest})
}

func observeTask(status *api.ImageBuildStatus, tr *tekton.TaskRun, stage string) {
	switch stage {
	case tasks.PipelineTaskBuildImage:
		addArtifact(status, "container", terminal.TaskResult(tr, "IMAGE_URL"), terminal.TaskResult(tr, "IMAGE_DIGEST"))
		if value := terminal.TaskResult(tr, "automotive-image-builder"); value != "" {
			status.AIBImageUsed = value
		}
		if value := terminal.TaskResult(tr, "builder-image"); value != "" {
			status.BuilderImageUsed = value
		}
	case pipelineTaskPushDisk:
		addArtifact(status, "disk", terminal.TaskResult(tr, "IMAGE_URL"), terminal.TaskResult(tr, "IMAGE_DIGEST"))
	case "push-disk-artifact-s3":
		addArtifact(status, "s3", terminal.TaskResult(tr, "S3_URL"), "")
	case pipelineTaskFlash:
		phase, message := terminal.TaskPhase(tr)
		status.Flash = &api.FlashOutcomeStatus{Enabled: true, State: terminal.FlashState(phase), Message: message, LeaseID: terminal.TaskResult(tr, "lease-id")}
		status.LeaseID = status.Flash.LeaseID
	}
}

// Child results remain usable when aggregate pipeline results are absent because
// a referenced task failed or was skipped. Only emitted URLs prove publication.
func (r *ImageBuildReconciler) collectResults(ctx context.Context, ib *api.ImageBuild, requireSettled bool) error {
	reader := client.Reader(r.Client)
	if r.APIReader != nil {
		reader = r.APIReader
	}
	if ib.Spec.IsFlashEnabled() && ib.Status.Flash == nil {
		ib.Status.Flash = &api.FlashOutcomeStatus{Enabled: true, State: "NotStarted"}
	}
	if ib.Status.PipelineRunName != "" {
		pr := &tekton.PipelineRun{}
		err := reader.Get(ctx, types.NamespacedName{Namespace: ib.Namespace, Name: ib.Status.PipelineRunName}, pr)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
		if err == nil {
			results := map[string]string{}
			for _, result := range pr.Status.Results {
				results[result.Name] = result.Value.StringVal
			}
			addArtifact(&ib.Status, "container", results["container-image-url"], results["container-image-digest"])
			addArtifact(&ib.Status, "disk", results["disk-artifact-url"], results["disk-artifact-digest"])
			addArtifact(&ib.Status, "s3", results["s3-artifact-url"], "")
			if results["builder-image"] != "" {
				ib.Status.BuilderImageUsed = results["builder-image"]
			}
			for _, child := range pr.Status.ChildReferences {
				if child.Kind != "" && child.Kind != "TaskRun" {
					continue
				}
				if err := collectPipelineChild(ctx, reader, ib, child, requireSettled); err != nil {
					return err
				}
			}
			if ib.Status.Phase == phaseBuilding || ib.Status.Phase == phaseCancelled {
				setCompletion(&ib.Status, pr.Status.CompletionTime)
			}
		}
	}
	for _, stage := range []struct{ name, task string }{{ib.Status.PushTaskRunName, pipelineTaskPushDisk}, {ib.Status.FlashTaskRunName, pipelineTaskFlash}} {
		if stage.name == "" {
			continue
		}
		if err := collectNamedStage(ctx, reader, ib, stage.name, stage.task, requireSettled); err != nil {
			return err
		}
	}
	terminal.NormalizeResults(&ib.Status)
	return nil
}

func collectPipelineChild(
	ctx context.Context,
	reader client.Reader,
	ib *api.ImageBuild,
	child tekton.ChildStatusReference,
	requireSettled bool,
) error {
	tr, err := readResultTask(ctx, reader, ib.Namespace, child.Name, requireSettled)
	if err != nil {
		return err
	}
	if tr == nil {
		if child.PipelineTaskName == pipelineTaskFlash && ib.Status.Flash != nil && ib.Status.Flash.State == "NotStarted" {
			ib.Status.Flash = nil
		}
		return nil
	}
	observeTask(&ib.Status, tr, child.PipelineTaskName)
	return nil
}

func collectNamedStage(
	ctx context.Context,
	reader client.Reader,
	ib *api.ImageBuild,
	name, stage string,
	requireSettled bool,
) error {
	tr, err := readResultTask(ctx, reader, ib.Namespace, name, requireSettled)
	if err != nil || tr == nil {
		return err
	}
	observeTask(&ib.Status, tr, stage)
	if stage == pipelineTaskPushDisk {
		observeTask(&ib.Status, tr, "push-disk-artifact-s3")
	}
	if requireSettled && ((ib.Status.Phase == api.ImageBuildPhasePushing && stage == pipelineTaskPushDisk) ||
		(ib.Status.Phase == api.ImageBuildPhaseFlashing && stage == pipelineTaskFlash)) {
		setCompletion(&ib.Status, tr.Status.CompletionTime)
	}
	return nil
}

func readResultTask(
	ctx context.Context,
	reader client.Reader,
	namespace, name string,
	requireSettled bool,
) (*tekton.TaskRun, error) {
	tr := &tekton.TaskRun{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, tr); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if requireSettled && !isTaskRunCompleted(tr) {
		return nil, fmt.Errorf("%w: TaskRun %s", errTerminalResultsPending, tr.Name)
	}
	return tr, nil
}

func setCompletion(status *api.ImageBuildStatus, completed *metav1.Time) {
	if completed != nil && !completed.IsZero() && (status.CompletionTime == nil || completed.After(status.CompletionTime.Time)) {
		status.CompletionTime = completed.DeepCopy()
	}
}

func (r *ImageBuildReconciler) cancellationRuns(ctx context.Context, ib *api.ImageBuild) (*tekton.PipelineRunList, *tekton.TaskRunList, error) {
	prs := &tekton.PipelineRunList{}
	trs := &tekton.TaskRunList{}
	options := []client.ListOption{client.InNamespace(ib.Namespace), client.MatchingLabels{api.LabelImageBuildName: ib.Name}}
	if err := r.List(ctx, prs, options...); err != nil {
		return nil, nil, err
	}
	if err := r.List(ctx, trs, options...); err != nil {
		return nil, nil, err
	}
	if ib.Status.PipelineRunName != "" {
		pr := &tekton.PipelineRun{}
		err := r.Get(ctx, types.NamespacedName{Namespace: ib.Namespace, Name: ib.Status.PipelineRunName}, pr)
		if err != nil && !errors.IsNotFound(err) {
			return nil, nil, err
		}
		if err == nil {
			prs.Items = append(prs.Items, *pr)
		}
	}
	for _, name := range []string{ib.Status.PushTaskRunName, ib.Status.FlashTaskRunName} {
		if name == "" {
			continue
		}
		tr := &tekton.TaskRun{}
		err := r.Get(ctx, types.NamespacedName{Namespace: ib.Namespace, Name: name}, tr)
		if err != nil && !errors.IsNotFound(err) {
			return nil, nil, err
		}
		if err == nil {
			trs.Items = append(trs.Items, *tr)
		}
	}
	for _, pr := range prs.Items {
		for _, child := range pr.Status.ChildReferences {
			if child.Kind != "" && child.Kind != "TaskRun" {
				continue
			}
			tr := &tekton.TaskRun{}
			err := r.Get(ctx, types.NamespacedName{Namespace: ib.Namespace, Name: child.Name}, tr)
			if err != nil && !errors.IsNotFound(err) {
				return nil, nil, err
			}
			if err == nil {
				trs.Items = append(trs.Items, *tr)
			}
		}
	}
	return prs, trs, nil
}

func (r *ImageBuildReconciler) handleCancellation(ctx context.Context, ib *api.ImageBuild) (ctrl.Result, error) {
	prs, trs, err := r.cancellationRuns(ctx, ib)
	if err != nil {
		return ctrl.Result{}, err
	}
	if ib.Status.PipelineRunName == "" && len(prs.Items) > 0 {
		latest := latestPipelineRun(prs.Items)
		if err := r.updateStatus(ctx, ib, ib.Status.Phase, ib.Status.Message, func(fresh *api.ImageBuild) { fresh.Status.PipelineRunName = latest.Name }); err != nil {
			return ctrl.Result{}, err
		}
	}
	active := false
	seen := map[string]bool{}
	for i := range prs.Items {
		pr := &prs.Items[i]
		if seen[pr.Name] {
			continue
		}
		seen[pr.Name] = true
		if pr.Status.CompletionTime != nil && !pr.Status.CompletionTime.IsZero() {
			continue
		}
		active = true
		if !pr.IsCancelled() {
			patch := client.MergeFrom(pr.DeepCopy())
			pr.Spec.Status = tekton.PipelineRunSpecStatusCancelled
			if err := r.Patch(ctx, pr, patch); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	seen = map[string]bool{}
	for i := range trs.Items {
		tr := &trs.Items[i]
		if seen[tr.Name] {
			continue
		}
		seen[tr.Name] = true
		if tr.Status.CompletionTime != nil && !tr.Status.CompletionTime.IsZero() {
			continue
		}
		active = true
		if !tr.IsCancelled() {
			patch := client.MergeFrom(tr.DeepCopy())
			tr.Spec.Status = tekton.TaskRunSpecStatusCancelled
			if err := r.Patch(ctx, tr, patch); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	if active {
		return ctrl.Result{RequeueAfter: time.Second * 5}, nil
	}
	if ib.Status.Phase == phaseBuilding && ib.Status.PipelineRunName != "" {
		for i := range prs.Items {
			if prs.Items[i].Name == ib.Status.PipelineRunName && prs.Items[i].IsSuccessful() {
				return r.checkBuildProgress(ctx, ib)
			}
		}
	}
	for i := range trs.Items {
		tr := &trs.Items[i]
		if !tr.IsSuccessful() {
			continue
		}
		if ib.Status.Phase == api.ImageBuildPhaseFlashing && tr.Name == ib.Status.FlashTaskRunName {
			return r.handleFlashingState(ctx, ib)
		}
		if ib.Status.Phase == api.ImageBuildPhasePushing && tr.Name == ib.Status.PushTaskRunName && !ib.Spec.IsFlashEnabled() {
			return r.handlePushingState(ctx, ib)
		}
	}
	return ctrl.Result{}, r.updateStatus(ctx, ib, phaseCancelled, "Build cancelled by user")
}

func latestPipelineRun(runs []tekton.PipelineRun) *tekton.PipelineRun {
	latest := &runs[0]
	for i := 1; i < len(runs); i++ {
		if runs[i].CreationTimestamp.After(latest.CreationTimestamp.Time) ||
			(runs[i].CreationTimestamp.Equal(&latest.CreationTimestamp) && runs[i].Name > latest.Name) {
			latest = &runs[i]
		}
	}
	return latest
}

func settledTaskStatus(tr *tekton.TaskRun, failureMessage, cancellationMessage string) (string, string) {
	phase, _ := terminal.TaskPhase(tr)
	if phase == api.ImageBuildPhaseCancelled {
		return phase, taskRunFailureMessage(tr, cancellationMessage)
	}
	return phase, failureMessage
}

func pipelineCancelled(pr *tekton.PipelineRun) bool {
	for _, cond := range pr.Status.Conditions {
		if cond.Type == conditionSucceeded && cond.Reason == string(tekton.PipelineRunReasonCancelled) {
			return true
		}
	}
	return false
}
