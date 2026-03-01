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
	"strings"
	"time"

	"github.com/containers/image/v5/docker"
	containertypes "github.com/containers/image/v5/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	pod "github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

const (
	phasePending   = "Pending"
	phaseRunning   = "Running"
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
)

// Reconciler reconciles an ImageReseal object
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=imagereseals/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;taskruns;pipelineruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile handles reconciliation of ImageReseal resources.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sealed := &automotivev1alpha1.ImageReseal{}
	if err := r.Get(ctx, req.NamespacedName, sealed); err != nil {
		if k8serrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	switch sealed.Status.Phase {
	case "", phasePending:
		return r.handlePending(ctx, sealed)
	case phaseRunning:
		return r.handleRunning(ctx, sealed)
	case phaseCompleted, phaseFailed:
		return ctrl.Result{}, nil
	default:
		logger.Info("Unknown phase", "phase", sealed.Status.Phase)
		return ctrl.Result{}, nil
	}
}

func (r *Reconciler) handlePending(ctx context.Context, sealed *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	stages := sealed.Spec.GetStages()
	if len(stages) == 0 {
		return r.updateStatus(ctx, sealed, phaseFailed, "spec.operation or spec.stages must be set")
	}
	if err := validateStages(stages); err != nil {
		return r.updateStatus(ctx, sealed, phaseFailed, err.Error())
	}
	logger.Info("Starting reseal operation", "name", sealed.Name, "stages", stages)

	// Auto-detect architecture from source container image if not specified
	if sealed.Spec.Architecture == "" && sealed.Spec.InputRef != "" {
		arch, err := r.detectImageArch(ctx, sealed.Spec.InputRef, sealed.Namespace, sealed.Spec.SecretRef)
		if err != nil {
			logger.Info("Could not auto-detect architecture from source image, will rely on node detection", "error", err)
		} else if arch != "" {
			logger.Info("Auto-detected architecture from source image", "arch", arch)
			sealed.Spec.Architecture = arch
		}
	}

	if err := r.ensureSealedTasks(ctx, sealed.Namespace); err != nil {
		return r.updateStatus(ctx, sealed, phaseFailed, fmt.Sprintf("Failed to ensure reseal tasks: %v", err))
	}

	if len(stages) == 1 {
		tr, err := r.createSealedTaskRun(ctx, sealed, stages[0])
		if err != nil {
			return r.updateStatus(ctx, sealed, phaseFailed, fmt.Sprintf("Failed to create TaskRun: %v", err))
		}
		sealed.Status.TaskRunName = tr.Name
	} else {
		pr, err := r.createSealedPipelineRun(ctx, sealed, stages)
		if err != nil {
			return r.updateStatus(ctx, sealed, phaseFailed, fmt.Sprintf("Failed to create PipelineRun: %v", err))
		}
		sealed.Status.PipelineRunName = pr.Name
	}

	sealed.Status.StartTime = &metav1.Time{Time: time.Now()}
	sealed.Status.Phase = phaseRunning
	if len(stages) == 1 {
		sealed.Status.Message = fmt.Sprintf("Running - %s started", stages[0])
	} else {
		sealed.Status.Message = fmt.Sprintf("Running - pipeline started (%s)", strings.Join(stages, ", "))
	}
	if err := r.Status().Update(ctx, sealed); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *Reconciler) handleRunning(ctx context.Context, sealed *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	if sealed.Status.TaskRunName != "" {
		return r.handleRunningTaskRun(ctx, sealed)
	}
	if sealed.Status.PipelineRunName != "" {
		return r.handleRunningPipelineRun(ctx, sealed)
	}
	return r.updateStatus(ctx, sealed, phaseFailed, "neither TaskRunName nor PipelineRunName is set")
}

func (r *Reconciler) handleRunningTaskRun(ctx context.Context, sealed *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	tr := &tektonv1.TaskRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: sealed.Status.TaskRunName, Namespace: sealed.Namespace}, tr); err != nil {
		if k8serrors.IsNotFound(err) {
			r.cleanupTransientSecrets(ctx, sealed, logger)
			return r.updateStatus(ctx, sealed, phaseFailed, "TaskRun not found")
		}
		return ctrl.Result{}, err
	}
	if !tr.IsDone() {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	phase := phaseFailed
	message := "Operation failed"
	if tr.IsSuccessful() {
		phase = phaseCompleted
		message = "Operation completed successfully"
		sealed.Status.OutputRef = sealed.Spec.OutputRef
	}
	r.cleanupTransientSecrets(ctx, sealed, logger)
	sealed.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	return r.updateStatus(ctx, sealed, phase, message)
}

func (r *Reconciler) handleRunningPipelineRun(ctx context.Context, sealed *automotivev1alpha1.ImageReseal) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	pr := &tektonv1.PipelineRun{}
	if err := r.Get(ctx, client.ObjectKey{Name: sealed.Status.PipelineRunName, Namespace: sealed.Namespace}, pr); err != nil {
		if k8serrors.IsNotFound(err) {
			r.cleanupTransientSecrets(ctx, sealed, logger)
			return r.updateStatus(ctx, sealed, phaseFailed, "PipelineRun not found")
		}
		return ctrl.Result{}, err
	}
	if pr.Status.CompletionTime == nil {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	phase := phaseFailed
	message := "Pipeline failed"
	if isPipelineRunSuccessful(pr) {
		phase = phaseCompleted
		message = "Pipeline completed successfully"
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

func (r *Reconciler) createSealedTaskRun(ctx context.Context, sealed *automotivev1alpha1.ImageReseal, operation string) (*tektonv1.TaskRun, error) {
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
		{Name: "architecture", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.Architecture}},
	}

	trSpec := tektonv1.TaskRunSpec{
		TaskRef:    &tektonv1.TaskRef{Name: tasks.SealedTaskName(operation)},
		Params:     params,
		Workspaces: workspaces,
	}
	if nodeArch := archToNodeArch(sealed.Spec.Architecture); nodeArch != "" {
		trSpec.PodTemplate = &pod.Template{
			NodeSelector: map[string]string{corev1.LabelArchStable: nodeArch},
		}
	}
	tr := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      taskRunName,
			Namespace: sealed.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                "automotive-dev-operator",
				tasks.SealedTaskRunLabel:                      sealed.Name,
				"automotive.sdv.cloud.redhat.com/imagereseal": sealed.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageReseal", Name: sealed.Name, UID: sealed.UID, Controller: ptr(true)},
			},
		},
		Spec: trSpec,
	}
	if err := r.Create(ctx, tr); err != nil {
		return nil, fmt.Errorf("create TaskRun: %w", err)
	}
	return tr, nil
}

func (r *Reconciler) createSealedPipelineRun(ctx context.Context, sealed *automotivev1alpha1.ImageReseal, stages []string) (*tektonv1.PipelineRun, error) {
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
			{Name: "architecture", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sealed.Spec.Architecture}},
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

	prSpec := tektonv1.PipelineRunSpec{
		PipelineSpec: &tektonv1.PipelineSpec{
			Workspaces: prWorkspaces,
			Tasks:      pipelineTasks,
		},
		Workspaces: workspaces,
	}
	if nodeArch := archToNodeArch(sealed.Spec.Architecture); nodeArch != "" {
		prSpec.TaskRunTemplate = tektonv1.PipelineTaskRunTemplate{
			PodTemplate: &pod.Template{
				NodeSelector: map[string]string{corev1.LabelArchStable: nodeArch},
			},
		}
	}
	pr := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prName,
			Namespace: sealed.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/imagereseal": sealed.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageReseal", Name: sealed.Name, UID: sealed.UID, Controller: ptr(true)},
			},
		},
		Spec: prSpec,
	}
	if err := r.Create(ctx, pr); err != nil {
		return nil, fmt.Errorf("create PipelineRun: %w", err)
	}
	return pr, nil
}

// archToNodeArch maps ImageReseal.Spec.Architecture to Kubernetes node label (kubernetes.io/arch).
func archToNodeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

// validateStages checks that every entry in stages is a known sealed operation.
func validateStages(stages []string) error {
	valid := make(map[string]bool, len(tasks.SealedOperationNames))
	for _, op := range tasks.SealedOperationNames {
		valid[op] = true
	}
	for _, s := range stages {
		if !valid[s] {
			return fmt.Errorf("invalid operation %q; must be one of %v", s, tasks.SealedOperationNames)
		}
	}
	return nil
}

func isPipelineRunSuccessful(pr *tektonv1.PipelineRun) bool {
	for _, c := range pr.Status.Conditions {
		if c.Type == "Succeeded" {
			return c.Status == "True"
		}
	}
	return false
}

func (r *Reconciler) updateStatus(ctx context.Context, sealed *automotivev1alpha1.ImageReseal, phase, message string) (ctrl.Result, error) {
	sealed.Status.Phase = phase
	sealed.Status.Message = message
	if err := r.Status().Update(ctx, sealed); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// transientLabel is the label used to mark secrets that were created by the API server
// and should be cleaned up after the sealed operation completes.
const transientLabel = "automotive.sdv.cloud.redhat.com/transient"

func (r *Reconciler) cleanupTransientSecrets(ctx context.Context, sealed *automotivev1alpha1.ImageReseal, log logr.Logger) {
	for _, ref := range []struct {
		name       string
		secretType string
	}{
		{sealed.Spec.SecretRef, "registry auth"},
		{sealed.Spec.KeySecretRef, "seal key"},
		{sealed.Spec.KeyPasswordSecretRef, "seal key password"},
	} {
		if ref.name == "" {
			continue
		}
		if r.isTransientSecret(ctx, sealed.Namespace, ref.name) {
			r.deleteSecretWithRetry(ctx, sealed.Namespace, ref.name, ref.secretType, log)
		} else {
			log.V(1).Info("Skipping deletion of user-provided secret", "secret", ref.name, "type", ref.secretType)
		}
	}
}

func (r *Reconciler) isTransientSecret(ctx context.Context, namespace, name string) bool {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, secret); err != nil {
		return false
	}
	return secret.Labels[transientLabel] == "true"
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

// detectImageArch inspects a container image and returns its architecture (e.g. "amd64", "arm64").
// Uses registry credentials from SecretRef when available.
func (r *Reconciler) detectImageArch(ctx context.Context, imageRef, namespace, secretRef string) (string, error) {
	sysCtx := &containertypes.SystemContext{
		DockerInsecureSkipTLSVerify: containertypes.OptionalBoolTrue,
	}

	if secretRef != "" {
		auth, err := r.readRegistryAuth(ctx, namespace, secretRef)
		if err == nil && auth != nil {
			sysCtx.DockerAuthConfig = auth
		}
	}

	ref, err := docker.ParseReference("//" + imageRef)
	if err != nil {
		return "", fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}

	img, err := ref.NewImage(ctx, sysCtx)
	if err != nil {
		return "", fmt.Errorf("open image %q: %w", imageRef, err)
	}
	defer func() { _ = img.Close() }()

	info, err := img.Inspect(ctx)
	if err != nil {
		return "", fmt.Errorf("inspect image %q: %w", imageRef, err)
	}
	return info.Architecture, nil
}

// readRegistryAuth reads registry credentials (REGISTRY_USERNAME / REGISTRY_PASSWORD) from a secret.
func (r *Reconciler) readRegistryAuth(ctx context.Context, namespace, secretName string) (*containertypes.DockerAuthConfig, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: namespace}, secret); err != nil {
		return nil, err
	}
	username := string(secret.Data["REGISTRY_USERNAME"])
	password := string(secret.Data["REGISTRY_PASSWORD"])
	if username != "" && password != "" {
		return &containertypes.DockerAuthConfig{Username: username, Password: password}, nil
	}
	return nil, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageReseal{}).
		Owns(&tektonv1.TaskRun{}).
		Owns(&tektonv1.PipelineRun{}).
		Complete(r)
}
