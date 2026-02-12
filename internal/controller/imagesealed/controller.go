/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package imagesealed provides the controller for ImageSealed resources.
package imagesealed

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

// Reconciler reconciles an ImageSealed object
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagesealeds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagesealeds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagesealeds/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;taskruns;pipelineruns,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles reconciliation of ImageSealed resources.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sealed := &automotivev1alpha1.ImageSealed{}
	if err := r.Get(ctx, req.NamespacedName, sealed); err != nil {
		if k8serrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	switch sealed.Status.Phase {
	case "", "Pending":
		return r.handlePending(ctx, sealed)
	case "Running":
		return r.handleRunning(ctx, sealed)
	case "Completed", "Failed":
		return ctrl.Result{}, nil
	default:
		logger.Info("Unknown phase", "phase", sealed.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *Reconciler) handlePending(ctx context.Context, sealed *automotivev1alpha1.ImageSealed) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	stages := sealed.Spec.GetStages()
	if len(stages) == 0 {
		return r.updateStatus(ctx, sealed, "Failed", "spec.operation or spec.stages must be set")
	}
	logger.Info("Starting sealed operation", "name", sealed.Name, "stages", stages)

	if err := r.ensureSealedTasks(ctx, sealed.Namespace); err != nil {
		return r.updateStatus(ctx, sealed, "Failed", fmt.Sprintf("Failed to ensure sealed tasks: %v", err))
	}

	if len(stages) == 1 {
		tr, err := r.createSealedTaskRun(ctx, sealed, stages[0])
		if err != nil {
			return r.updateStatus(ctx, sealed, "Failed", fmt.Sprintf("Failed to create TaskRun: %v", err))
		}
		sealed.Status.TaskRunName = tr.Name
	} else {
		pr, err := r.createSealedPipelineRun(ctx, sealed, stages)
		if err != nil {
			return r.updateStatus(ctx, sealed, "Failed", fmt.Sprintf("Failed to create PipelineRun: %v", err))
		}
		sealed.Status.PipelineRunName = pr.Name
	}

	sealed.Status.StartTime = &metav1.Time{Time: time.Now()}
	sealed.Status.Phase = "Running"
	sealed.Status.Message = "Sealed operation started"
	if err := r.Status().Update(ctx, sealed); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *Reconciler) handleRunning(ctx context.Context, sealed *automotivev1alpha1.ImageSealed) (ctrl.Result, error) {
	if sealed.Status.TaskRunName != "" {
		return r.handleRunningTaskRun(ctx, sealed)
	}
	if sealed.Status.PipelineRunName != "" {
		return r.handleRunningPipelineRun(ctx, sealed)
	}
	return r.updateStatus(ctx, sealed, "Failed", "neither TaskRunName nor PipelineRunName is set")
}

func (r *Reconciler) handleRunningTaskRun(ctx context.Context, sealed *automotivev1alpha1.ImageSealed) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	tr := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: sealed.Status.TaskRunName, Namespace: sealed.Namespace}, tr); err != nil {
		if k8serrors.IsNotFound(err) {
			r.cleanupTransientSecrets(ctx, sealed, logger)
			return r.updateStatus(ctx, sealed, "Failed", "TaskRun not found")
		}
		return ctrl.Result{}, err
	}
	if !tr.IsDone() {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	phase := "Failed"
	message := "Sealed operation failed"
	if tr.IsSuccessful() {
		phase = "Completed"
		message = "Sealed operation completed successfully"
		sealed.Status.OutputRef = sealed.Spec.OutputRef
	}
	r.cleanupTransientSecrets(ctx, sealed, logger)
	sealed.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	return r.updateStatus(ctx, sealed, phase, message)
}

func (r *Reconciler) handleRunningPipelineRun(ctx context.Context, sealed *automotivev1alpha1.ImageSealed) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	pr := &tektonv1.PipelineRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: sealed.Status.PipelineRunName, Namespace: sealed.Namespace}, pr); err != nil {
		if k8serrors.IsNotFound(err) {
			r.cleanupTransientSecrets(ctx, sealed, logger)
			return r.updateStatus(ctx, sealed, "Failed", "PipelineRun not found")
		}
		return ctrl.Result{}, err
	}
	if pr.Status.CompletionTime == nil {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	phase := "Failed"
	message := "Sealed pipeline failed"
	if isPipelineRunSuccessful(pr) {
		phase = "Completed"
		message = "Sealed pipeline completed successfully"
		sealed.Status.OutputRef = sealed.Spec.OutputRef
	}
	r.cleanupTransientSecrets(ctx, sealed, logger)
	sealed.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	return r.updateStatus(ctx, sealed, phase, message)
}

const sealedManagedByLabel = "app.kubernetes.io/managed-by"

func (r *Reconciler) ensureSealedTasks(ctx context.Context, namespace string) error {
	for _, op := range tasks.SealedOperationNames {
		task := tasks.GenerateSealedTaskForOperation(namespace, op)
		if err := r.ensureSealedTask(ctx, task); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) ensureSealedTask(ctx context.Context, task *tektonv1.Task) error {
	existing := &tektonv1.Task{}
	if err := r.Get(ctx, client.ObjectKey{Name: task.Name, Namespace: task.Namespace}, existing); err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Create(ctx, task)
		}
		return err
	}
	expectedManagedBy := task.Labels[sealedManagedByLabel]
	managedBy, managed := existing.Labels[sealedManagedByLabel]
	if !managed {
		return fmt.Errorf("task %s missing %s label; refusing to update", existing.Name, sealedManagedByLabel)
	}
	if managedBy != expectedManagedBy {
		return fmt.Errorf("task %s is managed by %q; refusing to update (expected %q)", existing.Name, managedBy, expectedManagedBy)
	}
	existing.Spec = task.Spec
	return r.Update(ctx, existing)
}

func (r *Reconciler) createSealedTaskRun(ctx context.Context, sealed *automotivev1alpha1.ImageSealed, operation string) (*tektonv1.TaskRun, error) {
	taskRunName := sealed.Name
	existingTR := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: taskRunName, Namespace: sealed.Namespace}, existingTR); err == nil {
		return existingTR, nil
	} else if !k8serrors.IsNotFound(err) {
		return nil, err
	}

	workspaces := []tektonv1.WorkspaceBinding{
		{Name: "shared", EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	if sealed.Spec.SecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name:   "registry-auth",
			Secret: &corev1.SecretVolumeSource{SecretName: sealed.Spec.SecretRef},
		})
	}
	if sealed.Spec.KeySecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name:   "sealing-key",
			Secret: &corev1.SecretVolumeSource{SecretName: sealed.Spec.KeySecretRef},
		})
	}
	if sealed.Spec.KeyPasswordSecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name:   "sealing-key-password",
			Secret: &corev1.SecretVolumeSource{SecretName: sealed.Spec.KeyPasswordSecretRef},
		})
	}

	signedRef := ""
	if operation == "inject-signed" {
		signedRef = sealed.Spec.SignedRef
	}

	params := []tektonv1.Param{
		{Name: "input-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.InputRef}},
		{Name: "output-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.OutputRef}},
		{Name: "signed-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: signedRef}},
		{Name: "aib-image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.GetAIBImage()}},
		{Name: "builder-image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.BuilderImage}},
	}

	tr := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      taskRunName,
			Namespace: sealed.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                "imagesealed-controller",
				tasks.SealedTaskRunLabel:                      sealed.Name,
				"automotive.sdv.cloud.redhat.com/imagesealed": sealed.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageSealed", Name: sealed.Name, UID: sealed.UID, Controller: ptr(true)},
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskRef:    &tektonv1.TaskRef{Name: tasks.SealedTaskName(operation)},
			Params:     params,
			Workspaces: workspaces,
		},
	}
	if err := r.Create(ctx, tr); err != nil {
		return nil, fmt.Errorf("create TaskRun: %w", err)
	}
	return tr, nil
}

func (r *Reconciler) createSealedPipelineRun(ctx context.Context, sealed *automotivev1alpha1.ImageSealed, stages []string) (*tektonv1.PipelineRun, error) {
	prName := sealed.Name
	existing := &tektonv1.PipelineRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: prName, Namespace: sealed.Namespace}, existing); err == nil {
		return existing, nil
	} else if !k8serrors.IsNotFound(err) {
		return nil, err
	}

	workspaces := []tektonv1.WorkspaceBinding{
		{Name: "shared", EmptyDir: &corev1.EmptyDirVolumeSource{}},
		{Name: "registry-auth", EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	if sealed.Spec.SecretRef != "" {
		workspaces[1] = tektonv1.WorkspaceBinding{
			Name:   "registry-auth",
			Secret: &corev1.SecretVolumeSource{SecretName: sealed.Spec.SecretRef},
		}
	}
	if sealed.Spec.KeySecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name:   "sealing-key",
			Secret: &corev1.SecretVolumeSource{SecretName: sealed.Spec.KeySecretRef},
		})
	}
	if sealed.Spec.KeyPasswordSecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name:   "sealing-key-password",
			Secret: &corev1.SecretVolumeSource{SecretName: sealed.Spec.KeyPasswordSecretRef},
		})
	}
	pipelineWorkspaceRefs := []tektonv1.WorkspacePipelineTaskBinding{
		{Name: "shared", Workspace: "shared"},
		{Name: "registry-auth", Workspace: "registry-auth"},
	}
	if sealed.Spec.KeySecretRef != "" {
		pipelineWorkspaceRefs = append(pipelineWorkspaceRefs, tektonv1.WorkspacePipelineTaskBinding{Name: "sealing-key", Workspace: "sealing-key"})
	}
	if sealed.Spec.KeyPasswordSecretRef != "" {
		pipelineWorkspaceRefs = append(pipelineWorkspaceRefs, tektonv1.WorkspacePipelineTaskBinding{Name: "sealing-key-password", Workspace: "sealing-key-password"})
	}

	pipelineTasks := make([]tektonv1.PipelineTask, 0, len(stages))
	for i, op := range stages {
		pt := tektonv1.PipelineTask{
			Name:     fmt.Sprintf("stage-%d", i),
			TaskRef:  &tektonv1.TaskRef{Name: tasks.SealedTaskName(op)},
			Params:   nil,
			RunAfter: nil,
		}
		if i > 0 {
			pt.RunAfter = []string{fmt.Sprintf("stage-%d", i-1)}
		}
		inputRef := ""
		if i == 0 {
			inputRef = sealed.Spec.InputRef
		}
		outputRef := ""
		if i == len(stages)-1 {
			outputRef = sealed.Spec.OutputRef
		}
		signedRef := ""
		if op == "inject-signed" {
			signedRef = sealed.Spec.SignedRef
		}
		pt.Params = []tektonv1.Param{
			{Name: "input-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: inputRef}},
			{Name: "output-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: outputRef}},
			{Name: "signed-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: signedRef}},
			{Name: "aib-image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.GetAIBImage()}},
			{Name: "builder-image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.BuilderImage}},
		}
		pt.Workspaces = pipelineWorkspaceRefs
		pipelineTasks = append(pipelineTasks, pt)
	}

	prWorkspaces := []tektonv1.PipelineWorkspaceDeclaration{{Name: "shared"}, {Name: "registry-auth"}}
	if sealed.Spec.KeySecretRef != "" {
		prWorkspaces = append(prWorkspaces, tektonv1.PipelineWorkspaceDeclaration{Name: "sealing-key"})
	}
	if sealed.Spec.KeyPasswordSecretRef != "" {
		prWorkspaces = append(prWorkspaces, tektonv1.PipelineWorkspaceDeclaration{Name: "sealing-key-password"})
	}

	pr := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prName,
			Namespace: sealed.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                "imagesealed-controller",
				"automotive.sdv.cloud.redhat.com/imagesealed": sealed.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageSealed", Name: sealed.Name, UID: sealed.UID, Controller: ptr(true)},
			},
		},
		Spec: tektonv1.PipelineRunSpec{
			PipelineSpec: &tektonv1.PipelineSpec{
				Workspaces: prWorkspaces,
				Tasks:      pipelineTasks,
			},
			Workspaces: workspaces,
		},
	}
	if err := r.Create(ctx, pr); err != nil {
		return nil, fmt.Errorf("create PipelineRun: %w", err)
	}
	return pr, nil
}

func isPipelineRunSuccessful(pr *tektonv1.PipelineRun) bool {
	for _, c := range pr.Status.Conditions {
		if c.Type == "Succeeded" {
			return c.Status == "True"
		}
	}
	return false
}

func (r *Reconciler) updateStatus(ctx context.Context, sealed *automotivev1alpha1.ImageSealed, phase, message string) (ctrl.Result, error) {
	sealed.Status.Phase = phase
	sealed.Status.Message = message
	if err := r.Status().Update(ctx, sealed); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// cleanupTransientSecrets deletes any transient secrets created for this sealed operation
func (r *Reconciler) cleanupTransientSecrets(ctx context.Context, sealed *automotivev1alpha1.ImageSealed, log logr.Logger) {
	if sealed.Spec.SecretRef != "" {
		r.deleteSecretWithRetry(ctx, sealed.Namespace, sealed.Spec.SecretRef, "registry auth", log)
	}
	if sealed.Spec.KeySecretRef != "" {
		r.deleteSecretWithRetry(ctx, sealed.Namespace, sealed.Spec.KeySecretRef, "seal key", log)
	}
}

// deleteSecretWithRetry attempts to delete a secret with exponential backoff retry
func (r *Reconciler) deleteSecretWithRetry(ctx context.Context, namespace, secretName, secretType string, log logr.Logger) {
	maxRetries := 3
	backoff := 100 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
		}
		err := r.Delete(ctx, secret)
		if err == nil {
			log.Info("Deleted "+secretType+" secret", "secret", secretName)
			return
		}
		if k8serrors.IsNotFound(err) {
			return
		}

		if attempt < maxRetries {
			log.V(1).Info("Retrying secret deletion", "secret", secretName, "attempt", attempt, "error", err.Error())
			time.Sleep(backoff)
			backoff *= 2
		} else {
			log.Error(err, "Failed to delete "+secretType+" secret after retries", "secret", secretName, "attempts", maxRetries)
		}
	}
}

func ptr(b bool) *bool {
	return &b
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageSealed{}).
		Owns(&tektonv1.TaskRun{}).
		Owns(&tektonv1.PipelineRun{}).
		Complete(r)
}
