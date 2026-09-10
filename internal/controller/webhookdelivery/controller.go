// Package webhookdelivery creates durable terminal-event snapshots.
package webhookdelivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/terminal"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const orphanCallbackTimeout = 2 * time.Minute

type subjectKind string

const (
	imageBuildSubject subjectKind = "imagebuild"
	flashSubject      subjectKind = "flash"
)

// Reconciler manages delivery intent and frozen event snapshots.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

type subjectReconciler struct {
	*Reconciler
	kind subjectKind
}

type callbackSecretReconciler struct {
	*Reconciler
}

type permanentPreparationError struct {
	err error
}

func (e *permanentPreparationError) Error() string {
	return e.err.Error()
}

func (e *permanentPreparationError) Unwrap() error {
	return e.err
}

func permanentPreparationErrorf(format string, args ...any) error {
	return &permanentPreparationError{err: fmt.Errorf(format, args...)}
}

func deliveryTerminal(delivery *automotivev1alpha1.WebhookDelivery) bool {
	return delivery.Status.State == automotivev1alpha1.DeliveryDelivered ||
		delivery.Status.State == automotivev1alpha1.DeliveryFailed
}

func deliveryPreparationComplete(delivery *automotivev1alpha1.WebhookDelivery) bool {
	return delivery.Status.Snapshot != nil || deliveryTerminal(delivery)
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=webhookdeliveries,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=webhookdeliveries/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds,verbs=get;list;watch
// +kubebuilder:rbac:groups=tekton.dev,namespace=system,resources=taskruns,verbs=get;list;watch
// +kubebuilder:rbac:groups=tekton.dev,namespace=system,resources=taskruns/finalizers,verbs=update
// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=get;list;watch;update;patch;delete

func (r *subjectReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	switch r.kind {
	case imageBuildSubject:
		return r.reconcileBuild(ctx, req.NamespacedName)
	case flashSubject:
		return r.reconcileFlash(ctx, req.NamespacedName)
	default:
		return ctrl.Result{}, nil
	}
}

func (r *Reconciler) reconcileBuild(ctx context.Context, key types.NamespacedName) (ctrl.Result, error) {
	build := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, key, build); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if build.Spec.CallbackSecretRef == "" || build.Status.TerminalResult == nil {
		return ctrl.Result{}, nil
	}
	delivery, err := r.ensureDeliveryIntent(ctx, build, build.Spec.CallbackSecretRef)
	if err != nil {
		if delivery != nil {
			return ctrl.Result{}, r.recordPreparationFailure(ctx, delivery, err)
		}
		return ctrl.Result{}, err
	}
	if deliveryPreparationComplete(delivery) {
		return ctrl.Result{}, nil
	}
	if err := r.ensureCallbackOwner(
		ctx,
		build.Namespace,
		build.Spec.CallbackSecretRef,
		notifications.SubjectImageBuild,
		build.Name,
		build.UID,
		build,
	); err != nil {
		return ctrl.Result{}, r.recordPreparationFailure(ctx, delivery, err)
	}

	result := build.Status.TerminalResult.DeepCopy()
	eventTime := result.CompletedAt.DeepCopy()
	event := notifications.TerminalEvent{
		APIVersion: notifications.APIVersion,
		ID:         notifications.EventID(string(build.UID)),
		Type:       notifications.BuildTerminal,
		Time:       *eventTime,
		Build: &notifications.BuildEvent{
			Name:                build.Name,
			ExternalID:          build.Spec.ExternalID,
			TraceID:             build.Annotations[automotivev1alpha1.AnnotationTraceID],
			BuildTerminalResult: *result,
		},
	}
	if err := r.freezeDelivery(ctx, delivery, event); err != nil {
		return ctrl.Result{}, r.recordPreparationFailure(ctx, delivery, err)
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) reconcileFlash(ctx context.Context, key types.NamespacedName) (ctrl.Result, error) {
	taskRun := &tektonv1.TaskRun{}
	if err := r.Get(ctx, key, taskRun); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	callbackSecretRef := taskRun.Annotations[notifications.AnnotationCallbackSecretRef]
	if taskRun.Labels[labels.FlashTaskRun] == "" || callbackSecretRef == "" {
		return ctrl.Result{}, nil
	}
	result := terminal.FlashResult(taskRun)
	if result == nil {
		return ctrl.Result{}, r.ensureCallbackOwner(
			ctx,
			taskRun.Namespace,
			callbackSecretRef,
			notifications.SubjectTaskRun,
			taskRun.Name,
			taskRun.UID,
			taskRun,
		)
	}
	delivery, err := r.ensureDeliveryIntent(ctx, taskRun, callbackSecretRef)
	if err != nil {
		if delivery != nil {
			return ctrl.Result{}, r.recordPreparationFailure(ctx, delivery, err)
		}
		return ctrl.Result{}, err
	}
	if deliveryPreparationComplete(delivery) {
		return ctrl.Result{}, nil
	}
	if err := r.ensureCallbackOwner(
		ctx,
		taskRun.Namespace,
		callbackSecretRef,
		notifications.SubjectTaskRun,
		taskRun.Name,
		taskRun.UID,
		taskRun,
	); err != nil {
		return ctrl.Result{}, r.recordPreparationFailure(ctx, delivery, err)
	}
	event := notifications.TerminalEvent{
		APIVersion: notifications.APIVersion,
		ID:         notifications.EventID(string(taskRun.UID)),
		Type:       notifications.FlashTerminal,
		Time:       result.CompletedAt,
		Flash: &notifications.FlashEvent{
			Name:        taskRun.Name,
			Phase:       result.Phase,
			Message:     result.Message,
			ExternalID:  taskRun.Annotations[notifications.AnnotationExternalID],
			TraceID:     taskRun.Annotations[automotivev1alpha1.AnnotationTraceID],
			ImageRef:    terminal.Bound(taskRun.Annotations[labels.ImageRef], 2048),
			LeaseID:     result.Flash.LeaseID,
			StartedAt:   result.StartedAt,
			CompletedAt: result.CompletedAt,
		},
	}
	if err := r.freezeDelivery(ctx, delivery, event); err != nil {
		return ctrl.Result{}, r.recordPreparationFailure(ctx, delivery, err)
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) ensureCallbackOwner(
	ctx context.Context,
	namespace, secretName, kind, subjectName string,
	subjectUID types.UID,
	owner client.Object,
) error {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, secret); err != nil {
		return fmt.Errorf("get callback secret: %w", err)
	}
	if secret.Labels[notifications.LabelCallbackSecret] != labels.ValueTrue ||
		secret.Annotations[notifications.AnnotationCallbackSubjectKind] != kind ||
		secret.Annotations[notifications.AnnotationCallbackSubjectName] != subjectName {
		return permanentPreparationErrorf("callback secret %q does not belong to %s %q", secretName, kind, subjectName)
	}
	if len(secret.Data[notifications.CallbackURLKey]) == 0 ||
		len(secret.Data[notifications.CallbackURLKey]) > 2048 ||
		len(secret.Data[notifications.CallbackHMACKey]) < 32 ||
		len(secret.Data[notifications.CallbackHMACKey]) > 4096 {
		return permanentPreparationErrorf("callback secret %q has invalid data", secretName)
	}
	annotatedUID := secret.Annotations[notifications.AnnotationCallbackSubjectUID]
	if annotatedUID != "" && annotatedUID != string(subjectUID) {
		return permanentPreparationErrorf("callback secret %q belongs to a replaced subject", secretName)
	}
	if metav1.IsControlledBy(secret, owner) && annotatedUID == string(subjectUID) {
		return nil
	}
	patch := client.MergeFromWithOptions(secret.DeepCopy(), client.MergeFromWithOptimisticLock{})
	if err := controllerutil.SetControllerReference(owner, secret, r.Scheme); err != nil {
		return permanentPreparationErrorf("set callback secret owner: %w", err)
	}
	secret.Annotations[notifications.AnnotationCallbackSubjectUID] = string(subjectUID)
	if err := r.Patch(ctx, secret, patch); err != nil {
		return fmt.Errorf("adopt callback secret: %w", err)
	}
	return nil
}

func (r *Reconciler) ensureDeliveryIntent(
	ctx context.Context,
	owner client.Object,
	callbackSecretRef string,
) (*automotivev1alpha1.WebhookDelivery, error) {
	if owner.GetUID() == "" {
		return nil, k8serrors.NewBadRequest("delivery subject UID is empty")
	}
	apiVersion := automotivev1alpha1.GroupVersion.String()
	kind := notifications.SubjectImageBuild
	if _, ok := owner.(*tektonv1.TaskRun); ok {
		apiVersion = "tekton.dev/v1"
		kind = notifications.SubjectTaskRun
	}
	name := notifications.DeliveryName(string(owner.GetUID()))
	delivery := &automotivev1alpha1.WebhookDelivery{}
	key := types.NamespacedName{Namespace: owner.GetNamespace(), Name: name}
	err := r.Get(ctx, key, delivery)
	if k8serrors.IsNotFound(err) {
		delivery = &automotivev1alpha1.WebhookDelivery{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: owner.GetNamespace()},
			Spec: automotivev1alpha1.WebhookDeliverySpec{
				Subject: automotivev1alpha1.DeliverySubject{
					APIVersion: apiVersion,
					Kind:       kind,
					Name:       owner.GetName(),
					UID:        owner.GetUID(),
				},
				CallbackSecretRef: callbackSecretRef,
			},
		}
		if err := controllerutil.SetControllerReference(owner, delivery, r.Scheme); err != nil {
			return nil, fmt.Errorf("set delivery owner: %w", err)
		}
		createErr := r.Create(ctx, delivery)
		if createErr != nil && !k8serrors.IsAlreadyExists(createErr) {
			return nil, fmt.Errorf("create delivery: %w", createErr)
		}
		if k8serrors.IsAlreadyExists(createErr) {
			if err := r.Get(ctx, key, delivery); err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}
	if delivery.Spec.Subject.UID != owner.GetUID() || delivery.Spec.CallbackSecretRef != callbackSecretRef {
		return delivery, permanentPreparationErrorf("delivery %q has conflicting immutable intent", delivery.Name)
	}
	return delivery, nil
}

func (r *Reconciler) freezeDelivery(
	ctx context.Context,
	delivery *automotivev1alpha1.WebhookDelivery,
	event notifications.TerminalEvent,
) error {
	if delivery.Status.Snapshot != nil {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal terminal event: %w", err)
	}
	if len(body) > notifications.MaxPayloadBytes {
		return permanentPreparationErrorf("terminal event exceeds %d bytes", notifications.MaxPayloadBytes)
	}
	delivery.Status.State = automotivev1alpha1.DeliveryPending
	delivery.Status.LastError = ""
	delivery.Status.Snapshot = &automotivev1alpha1.WebhookEventSnapshot{
		ID: event.ID, Type: event.Type, Time: event.Time, Body: body,
	}
	// Use Update so required zero-valued status fields such as attempts are sent
	// when status is initialized for the first time. A merge patch omits unchanged
	// zero values and is rejected by CRD validation because attempts is required.
	if err := r.Status().Update(ctx, delivery); err != nil {
		return fmt.Errorf("freeze terminal event: %w", err)
	}
	return nil
}

func (r *Reconciler) recordPreparationFailure(
	ctx context.Context,
	delivery *automotivev1alpha1.WebhookDelivery,
	cause error,
) error {
	if deliveryTerminal(delivery) {
		return nil
	}
	var permanent *permanentPreparationError
	if errors.As(cause, &permanent) {
		delivery.Status.State = automotivev1alpha1.DeliveryFailed
	} else {
		delivery.Status.State = automotivev1alpha1.DeliveryPending
	}
	delivery.Status.LastError = terminal.Bound(cause.Error(), 1024)
	if err := r.Status().Update(ctx, delivery); err != nil {
		return fmt.Errorf("%v; record delivery preparation failure: %w", cause, err)
	}
	if permanent != nil {
		return nil
	}
	return cause
}

func (r *callbackSecretReconciler) ensureReferencedCallbackOwner(
	ctx context.Context,
	secret *corev1.Secret,
	kind, name string,
	subjectUID types.UID,
	owner client.Object,
) error {
	err := r.ensureCallbackOwner(ctx, secret.Namespace, secret.Name, kind, name, subjectUID, owner)
	var permanent *permanentPreparationError
	if errors.As(err, &permanent) {
		r.Log.Error(err, "callback secret requires manual repair",
			"secret", client.ObjectKeyFromObject(secret), "subjectKind", kind, "subjectName", name)
		return nil
	}
	return err
}

func (r *callbackSecretReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if secret.Labels[notifications.LabelCallbackSecret] != labels.ValueTrue || len(secret.OwnerReferences) != 0 {
		return ctrl.Result{}, nil
	}
	kind := secret.Annotations[notifications.AnnotationCallbackSubjectKind]
	name := secret.Annotations[notifications.AnnotationCallbackSubjectName]
	switch kind {
	case notifications.SubjectImageBuild:
		build := &automotivev1alpha1.ImageBuild{}
		err := r.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: name}, build)
		if err == nil && build.Spec.CallbackSecretRef == secret.Name {
			return ctrl.Result{}, r.ensureReferencedCallbackOwner(ctx, secret, kind, name, build.UID, build)
		}
		if err != nil && !k8serrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	case notifications.SubjectTaskRun:
		taskRun := &tektonv1.TaskRun{}
		err := r.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: name}, taskRun)
		if err == nil && taskRun.Annotations[notifications.AnnotationCallbackSecretRef] == secret.Name {
			return ctrl.Result{}, r.ensureReferencedCallbackOwner(ctx, secret, kind, name, taskRun.UID, taskRun)
		}
		if err != nil && !k8serrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	remaining := orphanCallbackTimeout - time.Since(secret.CreationTimestamp.Time)
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, nil
	}
	if err := r.Delete(ctx, secret); err != nil && !k8serrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers build, standalone-flash, and orphan-secret reconciliation.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	options := controller.Options{MaxConcurrentReconciles: 4}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("imagebuild-webhook-delivery").
		WithOptions(options).
		For(&automotivev1alpha1.ImageBuild{}).
		Owns(&automotivev1alpha1.WebhookDelivery{}).
		Complete(&subjectReconciler{Reconciler: r, kind: imageBuildSubject}); err != nil {
		return err
	}
	flashPredicate := predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetLabels()[labels.FlashTaskRun] != ""
	})
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("flash-webhook-delivery").
		WithOptions(options).
		For(&tektonv1.TaskRun{}, builder.WithPredicates(flashPredicate)).
		Owns(&automotivev1alpha1.WebhookDelivery{}).
		Complete(&subjectReconciler{Reconciler: r, kind: flashSubject}); err != nil {
		return err
	}
	secretPredicate := predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetLabels()[notifications.LabelCallbackSecret] == labels.ValueTrue
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("callback-secret-recovery").
		WithOptions(options).
		For(&corev1.Secret{}, builder.WithPredicates(secretPredicate)).
		Complete(&callbackSecretReconciler{Reconciler: r})
}
