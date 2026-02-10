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
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;taskruns,verbs=get;list;watch;create;update;patch;delete

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
	logger.Info("Starting sealed operation", "name", sealed.Name, "operation", sealed.Spec.Operation)

	taskRun, err := r.createSealedTaskRun(ctx, sealed)
	if err != nil {
		return r.updateStatus(ctx, sealed, "Failed", fmt.Sprintf("Failed to create TaskRun: %v", err))
	}

	sealed.Status.TaskRunName = taskRun.Name
	sealed.Status.StartTime = &metav1.Time{Time: time.Now()}
	sealed.Status.Phase = "Running"
	sealed.Status.Message = "Sealed operation started"

	if err := r.Status().Update(ctx, sealed); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *Reconciler) handleRunning(ctx context.Context, sealed *automotivev1alpha1.ImageSealed) (ctrl.Result, error) {
	if sealed.Status.TaskRunName == "" {
		return r.updateStatus(ctx, sealed, "Failed", "TaskRun name is missing")
	}

	taskRun := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: sealed.Status.TaskRunName, Namespace: sealed.Namespace}, taskRun); err != nil {
		if k8serrors.IsNotFound(err) {
			return r.updateStatus(ctx, sealed, "Failed", "TaskRun not found")
		}
		return ctrl.Result{}, err
	}

	if !taskRun.IsDone() {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	phase := "Failed"
	message := "Sealed operation failed"
	if taskRun.IsSuccessful() {
		phase = "Completed"
		message = "Sealed operation completed successfully"
		sealed.Status.OutputRef = sealed.Spec.OutputRef
	}
	sealed.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	return r.updateStatus(ctx, sealed, phase, message)
}

const sealedManagedByLabel = "app.kubernetes.io/managed-by"

func (r *Reconciler) createSealedTaskRun(ctx context.Context, sealed *automotivev1alpha1.ImageSealed) (*tektonv1.TaskRun, error) {
	taskRunName := sealed.Name
	existingTR := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: taskRunName, Namespace: sealed.Namespace}, existingTR); err == nil {
		return existingTR, nil
	} else if !k8serrors.IsNotFound(err) {
		return nil, err
	}

	sealedTask := tasks.GenerateSealedTask(sealed.Namespace)
	if err := r.ensureSealedTask(ctx, sealedTask); err != nil {
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

	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      taskRunName,
			Namespace: sealed.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                "imagesealed-controller",
				tasks.SealedTaskRunLabel:                      sealed.Name,
				"automotive.sdv.cloud.redhat.com/imagesealed": sealed.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: automotivev1alpha1.GroupVersion.String(),
					Kind:       "ImageSealed",
					Name:       sealed.Name,
					UID:        sealed.UID,
					Controller: ptr(true),
				},
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskRef: &tektonv1.TaskRef{Name: sealedTask.Name},
			Params: []tektonv1.Param{
				{Name: "operation", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.Operation}},
				{Name: "input-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.InputRef}},
				{Name: "output-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.OutputRef}},
				{Name: "signed-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.SignedRef}},
				{Name: "aib-image", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.GetAIBImage()}},
			},
			Workspaces: workspaces,
		},
	}

	if err := r.Create(ctx, taskRun); err != nil {
		return nil, fmt.Errorf("create TaskRun: %w", err)
	}
	return taskRun, nil
}

// ensureSealedTask creates the sealed-operation Task if missing, or updates it if we manage it.
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

func (r *Reconciler) updateStatus(ctx context.Context, sealed *automotivev1alpha1.ImageSealed, phase, message string) (ctrl.Result, error) {
	sealed.Status.Phase = phase
	sealed.Status.Message = message
	if err := r.Status().Update(ctx, sealed); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func ptr(b bool) *bool {
	return &b
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageSealed{}).
		Owns(&tektonv1.TaskRun{}).
		Complete(r)
}
