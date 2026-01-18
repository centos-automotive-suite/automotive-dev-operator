/*
Copyright 2024.

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

package imagereseal

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

// ImageResealReconciler reconciles an ImageReseal object
type ImageResealReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=taskruns,verbs=get;list;watch;create;update;patch;delete

func (r *ImageResealReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the ImageReseal instance
	reseal := &automotivev1alpha1.ImageReseal{}
	if err := r.Get(ctx, req.NamespacedName, reseal); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle based on current phase
	switch reseal.Status.Phase {
	case "", "Pending":
		return r.handlePending(ctx, reseal)
	case "Running":
		return r.handleRunning(ctx, reseal)
	case "Completed", "Failed":
		return ctrl.Result{}, nil
	default:
		logger.Info("Unknown phase", "phase", reseal.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *ImageResealReconciler) handlePending(ctx context.Context, reseal *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Starting reseal operation", "name", reseal.Name)

	// Create the reseal TaskRun
	taskRun, err := r.createResealTaskRun(ctx, reseal)
	if err != nil {
		// Cleanup transient secrets before marking as failed
		r.cleanupTransientSecrets(ctx, reseal, logger)
		return r.updateStatus(ctx, reseal, "Failed", fmt.Sprintf("Failed to create TaskRun: %v", err))
	}

	// Update status using direct assignment for fields that updateStatus doesn't handle
	reseal.Status.TaskRunName = taskRun.Name
	reseal.Status.StartTime = &metav1.Time{Time: time.Now()}
	reseal.Status.Phase = "Running"
	reseal.Status.Message = "Reseal operation started"

	if err := r.Status().Update(ctx, reseal); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *ImageResealReconciler) handleRunning(ctx context.Context, reseal *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if reseal.Status.TaskRunName == "" {
		r.cleanupTransientSecrets(ctx, reseal, logger)
		return r.updateStatus(ctx, reseal, "Failed", "TaskRun name is missing")
	}

	// Check TaskRun status
	taskRun := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: reseal.Status.TaskRunName, Namespace: reseal.Namespace}, taskRun); err != nil {
		if errors.IsNotFound(err) {
			r.cleanupTransientSecrets(ctx, reseal, logger)
			return r.updateStatus(ctx, reseal, "Failed", "TaskRun not found")
		}
		return ctrl.Result{}, err
	}

	// Check if TaskRun is complete
	if taskRun.IsDone() {
		phase := "Failed"
		message := "Reseal operation failed"

		if taskRun.IsSuccessful() {
			logger.Info("Reseal completed successfully", "name", reseal.Name)
			phase = "Completed"
			message = "Reseal operation completed successfully"
			reseal.Status.SealedContainer = reseal.Spec.TargetContainer
		} else {
			logger.Info("Reseal failed", "name", reseal.Name)
		}

		// Cleanup transient secrets before updating status
		r.cleanupTransientSecrets(ctx, reseal, logger)

		reseal.Status.CompletionTime = &metav1.Time{Time: time.Now()}
		return r.updateStatus(ctx, reseal, phase, message)
	}

	// Still running, requeue
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *ImageResealReconciler) createResealTaskRun(ctx context.Context, reseal *automotivev1alpha1.ImageReseal) (*tektonv1.TaskRun, error) {
	// Get the reseal task
	resealTask := tasks.GenerateResealTask(reseal.Namespace)

	// Create or update the Task to ensure embedded scripts are current
	existingTask := &tektonv1.Task{}
	if err := r.Get(ctx, client.ObjectKey{Name: resealTask.Name, Namespace: reseal.Namespace}, existingTask); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, resealTask); err != nil {
				return nil, fmt.Errorf("failed to create reseal task: %w", err)
			}
		} else {
			return nil, err
		}
	} else {
		// Task exists - update its spec to pick up any script changes
		existingTask.Spec = resealTask.Spec
		if err := r.Update(ctx, existingTask); err != nil {
			return nil, fmt.Errorf("failed to update reseal task: %w", err)
		}
	}

	// If a TaskRun already exists for this reseal, reuse it
	existingTaskRun := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-reseal", reseal.Name), Namespace: reseal.Namespace}, existingTaskRun); err == nil {
		return existingTaskRun, nil
	} else if !errors.IsNotFound(err) {
		return nil, err
	}

	// Set default mode if not specified
	mode := reseal.Spec.Mode
	if mode == "" {
		mode = "reseal"
	}

	// Build TaskRun
	taskRunName := fmt.Sprintf("%s-reseal", reseal.Name)
	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      taskRunName,
			Namespace: reseal.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                "imagereseal-controller",
				"automotive.sdv.cloud.redhat.com/imagereseal": reseal.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: automotivev1alpha1.GroupVersion.String(),
					Kind:       "ImageReseal",
					Name:       reseal.Name,
					UID:        reseal.UID,
					Controller: func(b bool) *bool { return &b }(true),
				},
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskRef: &tektonv1.TaskRef{
				Name: resealTask.Name,
			},
			Params: []tektonv1.Param{
				{Name: "source-container", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: reseal.Spec.SourceContainer}},
				{Name: "container-push", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: reseal.Spec.TargetContainer}},
				{Name: "automotive-image-builder", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: reseal.Spec.AutomotiveImageBuilder}},
				{Name: "builder-image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: reseal.Spec.BuilderImage}},
			},
			Workspaces: []tektonv1.WorkspaceBinding{},
		},
	}

	// Add optional workspaces
	optionalWorkspaces := map[string]struct {
		secretName    string
		configMapName string
	}{
		"seal-key":          {secretName: reseal.Spec.SealKeySecretRef},
		"seal-key-password": {secretName: reseal.Spec.SealKeyPasswordSecretRef},
		"registry-auth":     {secretName: reseal.Spec.EnvSecretRef},
	}

	for name, source := range optionalWorkspaces {
		if source.secretName != "" {
			taskRun.Spec.Workspaces = append(taskRun.Spec.Workspaces, tektonv1.WorkspaceBinding{
				Name:   name,
				Secret: &corev1.SecretVolumeSource{SecretName: source.secretName},
			})
		} else if source.configMapName != "" {
			taskRun.Spec.Workspaces = append(taskRun.Spec.Workspaces, tektonv1.WorkspaceBinding{
				Name:      name,
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: source.configMapName}},
			})
		}
	}

	if err := r.Create(ctx, taskRun); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.Get(ctx, client.ObjectKey{Name: taskRunName, Namespace: reseal.Namespace}, existingTaskRun); err == nil {
				return existingTaskRun, nil
			}
		}
		return nil, err
	}

	return taskRun, nil
}

func (r *ImageResealReconciler) updateStatus(ctx context.Context, reseal *automotivev1alpha1.ImageReseal, phase, message string) (ctrl.Result, error) {
	reseal.Status.Phase = phase
	reseal.Status.Message = message
	if phase == "Failed" || phase == "Completed" {
		reseal.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	}
	if err := r.Status().Update(ctx, reseal); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// cleanupTransientSecrets deletes any transient secrets created for this reseal
// Uses retry logic to handle transient API errors
func (r *ImageResealReconciler) cleanupTransientSecrets(ctx context.Context, reseal *automotivev1alpha1.ImageReseal, log logr.Logger) {
	// Cleanup registry auth secret (EnvSecretRef)
	if reseal.Spec.EnvSecretRef != "" {
		r.deleteSecretWithRetry(ctx, reseal.Namespace, reseal.Spec.EnvSecretRef, "registry auth", log)
	}
}

// deleteSecretWithRetry attempts to delete a secret with exponential backoff retry
func (r *ImageResealReconciler) deleteSecretWithRetry(ctx context.Context, namespace, secretName, secretType string, log logr.Logger) {
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
		if errors.IsNotFound(err) {
			// Secret already deleted, no action needed
			return
		}

		if attempt < maxRetries {
			log.V(1).Info("Failed to delete "+secretType+" secret, retrying", "secret", secretName, "attempt", attempt, "error", err.Error())
			time.Sleep(backoff)
			backoff *= 2 // exponential backoff
		} else {
			log.Info("Failed to delete "+secretType+" secret after retries (manual cleanup may be required)", "secret", secretName, "error", err.Error())
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageResealReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageReseal{}).
		Owns(&tektonv1.TaskRun{}).
		Complete(r)
}
