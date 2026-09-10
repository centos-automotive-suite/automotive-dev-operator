// Package terminal normalizes settled execution results for builds and flashes.
package terminal

import (
	"regexp"
	"strings"
	"unicode/utf8"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tekton "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const CancellationAnnotation = "automotive.sdv.cloud.redhat.com/cancel-requested"

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func Bound(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if utf8.RuneCountInString(value) > limit {
		return string([]rune(value)[:limit])
	}
	return value
}

// Finalize freezes a snapshot once; expiry and subsequent observations cannot replace it.
func Finalize(status *api.ImageBuildStatus, phase, message string) {
	if status.TerminalResult != nil {
		return
	}
	if phase != api.ImageBuildPhaseCompleted && phase != api.ImageBuildPhaseFailed && phase != api.ImageBuildPhaseCancelled {
		return
	}
	if status.CompletionTime == nil || status.CompletionTime.IsZero() {
		now := metav1.Now()
		status.CompletionTime = &now
	}
	NormalizeResults(status)
	status.TerminalResult = &api.BuildTerminalResult{
		Phase: phase, Message: Bound(message, 1024), StartedAt: status.StartTime.DeepCopy(),
		CompletedAt: *status.CompletionTime, Artifacts: append([]api.ArtifactStatus(nil), status.Artifacts...), Flash: status.Flash.DeepCopy(),
	}
}

func TaskResult(tr *tekton.TaskRun, name string) string {
	for _, result := range tr.Status.Results {
		if result.Name == name && (result.Value.Type == "" || result.Value.Type == tekton.ParamTypeString) {
			return result.Value.StringVal
		}
	}
	return ""
}

// TaskPhase treats cancellation spec as intent until Tekton has completed execution.
func TaskPhase(tr *tekton.TaskRun) (phase, message string) {
	if tr.Status.CompletionTime == nil || tr.Status.CompletionTime.IsZero() {
		if tr.Status.StartTime != nil && !tr.Status.StartTime.IsZero() {
			return "Running", "Flash in progress"
		}
		return "Pending", "Waiting to start"
	}
	phase, message = api.ImageBuildPhaseFailed, "Flash failed"
	for _, cond := range tr.Status.Conditions {
		if cond.Type != "Succeeded" {
			continue
		}
		if cond.Status == "True" {
			return api.ImageBuildPhaseCompleted, "Flash completed successfully"
		}
		if cond.Message != "" {
			message = cond.Message
		}
		if cond.Reason == string(tekton.TaskRunReasonTimedOut) || tr.Spec.StatusMessage == tekton.TaskRunCancelledByPipelineTimeoutMsg {
			return api.ImageBuildPhaseFailed, message
		}
		if cond.Reason == string(tekton.TaskRunReasonCancelled) {
			if cond.Message == "" {
				message = "Flash cancelled"
			}
			return api.ImageBuildPhaseCancelled, message
		}
	}
	if tr.IsCancelled() && tr.Spec.StatusMessage != tekton.TaskRunCancelledByPipelineTimeoutMsg {
		phase = api.ImageBuildPhaseCancelled
		if message == "Flash failed" {
			message = "Flash cancelled"
		}
	}
	return phase, message
}

// FlashState maps terminal build phases to the FlashOutcomeStatus vocabulary.
func FlashState(phase string) string {
	switch phase {
	case api.ImageBuildPhaseCompleted:
		return "Succeeded"
	case "Pending":
		return "NotStarted"
	default:
		return phase
	}
}

func FlashResult(tr *tekton.TaskRun) *api.BuildTerminalResult {
	phase, message := TaskPhase(tr)
	status := &api.ImageBuildStatus{StartTime: tr.Status.StartTime, CompletionTime: tr.Status.CompletionTime,
		Flash: &api.FlashOutcomeStatus{Enabled: true, State: FlashState(phase), LeaseID: TaskResult(tr, "lease-id"), Message: message},
	}
	Finalize(status, phase, message)
	return status.TerminalResult
}

// NormalizeResults keeps observations within the status schema bounds.
func NormalizeResults(status *api.ImageBuildStatus) {
	artifacts := make([]api.ArtifactStatus, 0, len(status.Artifacts))
	for _, artifact := range status.Artifacts {
		if artifact.URL == "" || !utf8.ValidString(artifact.URL) || utf8.RuneCountInString(artifact.URL) > 2048 {
			continue
		}
		if artifact.Kind != "container" && artifact.Kind != "disk" && artifact.Kind != "s3" {
			continue
		}
		if !digestPattern.MatchString(artifact.Digest) {
			artifact.Digest = ""
		}
		artifacts = append(artifacts, artifact)
		if len(artifacts) == 64 {
			break
		}
	}
	status.Artifacts = artifacts
	if status.Flash != nil {
		status.Flash = status.Flash.DeepCopy()
		status.Flash.Message = Bound(status.Flash.Message, 1024)
		status.Flash.LeaseID = Bound(status.Flash.LeaseID, 253)
	}
}
