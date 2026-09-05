package imagebuild

import (
	"context"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const callbackInitializationTimeout = 2 * time.Minute

func (r *ImageBuildReconciler) reconcileCallbackInitialization(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (ctrl.Result, bool, error) {
	if imageBuild.Annotations[notifications.AnnotationCallbackInitializing] != labels.ValueTrue {
		return ctrl.Result{}, false, nil
	}

	secret := &corev1.Secret{}
	var err error
	if imageBuild.Spec.CallbackSecretRef != "" {
		err = r.Get(ctx, types.NamespacedName{
			Namespace: imageBuild.Namespace,
			Name:      imageBuild.Spec.CallbackSecretRef,
		}, secret)
	}
	if err == nil && validBuildCallbackSecret(imageBuild, secret) {
		patch := client.MergeFromWithOptions(imageBuild.DeepCopy(), client.MergeFromWithOptimisticLock{})
		delete(imageBuild.Annotations, notifications.AnnotationCallbackInitializing)
		if err := r.Patch(ctx, imageBuild, patch); err != nil {
			return ctrl.Result{}, true, err
		}
		return ctrl.Result{}, true, nil
	}
	if err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, true, err
	}

	remaining := callbackInitializationTimeout - time.Since(imageBuild.CreationTimestamp.Time)
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, true, nil
	}
	if err := r.Delete(ctx, imageBuild); err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, true, err
	}
	return ctrl.Result{}, true, nil
}

func validBuildCallbackSecret(imageBuild *automotivev1alpha1.ImageBuild, secret *corev1.Secret) bool {
	if imageBuild.Spec.CallbackSecretRef == "" || secret.Name != imageBuild.Spec.CallbackSecretRef {
		return false
	}
	if secret.Annotations[notifications.AnnotationCallbackSubjectKind] != notifications.SubjectImageBuild ||
		secret.Annotations[notifications.AnnotationCallbackSubjectName] != imageBuild.Name ||
		secret.Annotations[notifications.AnnotationCallbackSubjectUID] != string(imageBuild.UID) {
		return false
	}
	if len(secret.Data[notifications.CallbackURLKey]) == 0 {
		return false
	}
	keyLength := len(secret.Data[notifications.CallbackHMACKey])
	if keyLength < 32 || keyLength > 4096 {
		return false
	}
	return metav1.IsControlledBy(secret, imageBuild)
}
