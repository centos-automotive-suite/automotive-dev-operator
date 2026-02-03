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

// Package imagereseal provides the controller for ImageReseal resources.
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

// Reconciler reconciles an ImageReseal object
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=taskruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles reconciliation of ImageReseal resources.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

func (r *Reconciler) handlePending(ctx context.Context, reseal *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Starting reseal operation", "name", reseal.Name)

	// Create the reseal TaskRun
	taskRun, err := r.createResealTaskRun(ctx, reseal)
	if err != nil {
		// Cleanup transient secrets before marking as failed
		r.cleanupTransientSecrets(ctx, reseal, logger)
		return r.updateStatus(ctx, reseal, "Failed", fmt.Sprintf("Failed to create TaskRun: %v", err))
	}

	// Update status
	reseal.Status.TaskRunName = taskRun.Name
	reseal.Status.StartTime = &metav1.Time{Time: time.Now()}
	reseal.Status.Phase = "Running"
	reseal.Status.Message = "Reseal operation started"

	if err := r.Status().Update(ctx, reseal); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *Reconciler) handleRunning(ctx context.Context, reseal *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
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

func (r *Reconciler) createResealTaskRun(ctx context.Context, reseal *automotivev1alpha1.ImageReseal) (*tektonv1.TaskRun, error) {
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
		// Task exists - check if it's managed by us before updating
		managedByLabel := "app.kubernetes.io/managed-by"
		expectedManagedBy := resealTask.Labels[managedByLabel]
		managedBy, managed := existingTask.Labels[managedByLabel]
		if !managed || managedBy != expectedManagedBy {
			if !managed {
				return nil, fmt.Errorf("reseal task %s missing %s label; refusing to update", existingTask.Name, managedByLabel)
			}
			return nil, fmt.Errorf("reseal task %s is managed by %q; refusing to update (expected %q)", existingTask.Name, managedBy, expectedManagedBy)
		}
		existingTask.Spec = resealTask.Spec
		if err := r.Update(ctx, existingTask); err != nil {
			return nil, fmt.Errorf("failed to update reseal task: %w", err)
		}
	}

	// If a TaskRun already exists for this reseal, reuse it
	taskRunName := fmt.Sprintf("%s-reseal", reseal.Name)
	existingTaskRun := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: taskRunName, Namespace: reseal.Namespace}, existingTaskRun); err == nil {
		return existingTaskRun, nil
	} else if !errors.IsNotFound(err) {
		return nil, err
	}

	// Build workspace bindings
	workspaces := []tektonv1.WorkspaceBinding{}

	// Add registry-auth workspace if configured
	if reseal.Spec.EnvSecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name: "registry-auth",
			Secret: &corev1.SecretVolumeSource{
				SecretName: reseal.Spec.EnvSecretRef,
			},
		})
	}

	// Add seal-key workspace if configured
	if reseal.Spec.SealKeySecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name: "seal-key",
			Secret: &corev1.SecretVolumeSource{
				SecretName: reseal.Spec.SealKeySecretRef,
			},
		})
	}

	// Add seal-key-password workspace if configured
	if reseal.Spec.SealKeyPasswordSecretRef != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name: "seal-key-password",
			Secret: &corev1.SecretVolumeSource{
				SecretName: reseal.Spec.SealKeyPasswordSecretRef,
			},
		})
	}

	// Build TaskRun
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
				{
					Name: "source-container",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: reseal.Spec.SourceContainer,
					},
				},
				{
					Name: "container-push",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: reseal.Spec.TargetContainer,
					},
				},
				{
					Name: "builder-image",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: reseal.Spec.BuilderImage,
					},
				},
				{
					Name: "automotive-image-builder",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: reseal.Spec.GetAIBImage(),
					},
				},
			},
			Workspaces: workspaces,
		},
	}

	if err := r.Create(ctx, taskRun); err != nil {
		return nil, fmt.Errorf("failed to create TaskRun: %w", err)
	}

	return taskRun, nil
}

func (r *Reconciler) updateStatus(ctx context.Context, reseal *automotivev1alpha1.ImageReseal, phase, message string) (ctrl.Result, error) {
	reseal.Status.Phase = phase
	reseal.Status.Message = message

	if err := r.Status().Update(ctx, reseal); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// cleanupTransientSecrets deletes any transient secrets created for this reseal
func (r *Reconciler) cleanupTransientSecrets(ctx context.Context, reseal *automotivev1alpha1.ImageReseal, log logr.Logger) {
	// Cleanup env secret if it was created transiently
	if reseal.Spec.EnvSecretRef != "" {
		r.deleteSecretWithRetry(ctx, reseal.Namespace, reseal.Spec.EnvSecretRef, "registry auth", log)
	}
	if reseal.Spec.SealKeySecretRef != "" {
		r.deleteSecretWithRetry(ctx, reseal.Namespace, reseal.Spec.SealKeySecretRef, "seal key", log)
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
		if errors.IsNotFound(err) {
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

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageReseal{}).
		Owns(&tektonv1.TaskRun{}).
		Complete(r)
}
