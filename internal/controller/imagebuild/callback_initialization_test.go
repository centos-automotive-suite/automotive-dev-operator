package imagebuild

import (
	"context"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func initializingBuild(createdAt time.Time) *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name: "callback-build", Namespace: "test-ns", UID: types.UID("build-uid"),
			CreationTimestamp: metav1.NewTime(createdAt),
			Annotations: map[string]string{
				automotivev1alpha1.AnnotationTraceID:         "trace-id",
				notifications.AnnotationCallbackInitializing: "true",
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			CallbackSecretRef: notifications.CallbackSecretName(notifications.SubjectImageBuild, "callback-build", "build-uid"),
		},
	}
}

func initializedCallbackSecret(build *automotivev1alpha1.ImageBuild) *corev1.Secret {
	controller := true
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: build.Spec.CallbackSecretRef, Namespace: build.Namespace,
			Annotations: map[string]string{
				notifications.AnnotationCallbackSubjectKind: notifications.SubjectImageBuild,
				notifications.AnnotationCallbackSubjectName: build.Name,
				notifications.AnnotationCallbackSubjectUID:  string(build.UID),
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: notifications.SubjectImageBuild,
				Name: build.Name, UID: build.UID, Controller: &controller,
			}},
		},
		Data: map[string][]byte{
			notifications.CallbackURLKey:  []byte("https://receiver.example/hook"),
			notifications.CallbackHMACKey: []byte("01234567890123456789012345678901"),
		},
	}
}

func TestCallbackInitializationRecovery(t *testing.T) {
	ctx := context.Background()
	t.Run("completed secret unblocks on a separate reconcile", func(t *testing.T) {
		build := initializingBuild(time.Now())
		secret := initializedCallbackSecret(build)
		r := newTestReconciler(build, secret)
		result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(build)})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsZero() {
			t.Fatalf("unexpected result: %+v", result)
		}
		stored := &automotivev1alpha1.ImageBuild{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(build), stored); err != nil {
			t.Fatal(err)
		}
		if stored.Annotations[notifications.AnnotationCallbackInitializing] != "" {
			t.Fatal("initialization marker remains")
		}
		if stored.Status.Phase != "" {
			t.Fatal("build started in the marker-removal reconcile")
		}
	})
	t.Run("missing secret waits before timeout", func(t *testing.T) {
		build := initializingBuild(time.Now())
		r := newTestReconciler(build)
		result, initializing, err := r.reconcileCallbackInitialization(ctx, build)
		if err != nil || !initializing || result.RequeueAfter <= 0 {
			t.Fatalf("result=%+v initializing=%v err=%v", result, initializing, err)
		}
		if err := r.Get(ctx, client.ObjectKeyFromObject(build), &automotivev1alpha1.ImageBuild{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing secret removes stale build", func(t *testing.T) {
		build := initializingBuild(time.Now().Add(-callbackInitializationTimeout - time.Second))
		r := newTestReconciler(build)
		if _, initializing, err := r.reconcileCallbackInitialization(ctx, build); err != nil || !initializing {
			t.Fatalf("initializing=%v err=%v", initializing, err)
		}
		if err := r.Get(ctx, client.ObjectKeyFromObject(build), &automotivev1alpha1.ImageBuild{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("stale build remains: %v", err)
		}
	})
	t.Run("foreign secret never unblocks build", func(t *testing.T) {
		build := initializingBuild(time.Now().Add(-callbackInitializationTimeout - time.Second))
		secret := initializedCallbackSecret(build)
		secret.Annotations[notifications.AnnotationCallbackSubjectUID] = "different-uid"
		r := newTestReconciler(build, secret)
		if _, _, err := r.reconcileCallbackInitialization(ctx, build); err != nil {
			t.Fatal(err)
		}
		if err := r.Get(ctx, client.ObjectKeyFromObject(build), &automotivev1alpha1.ImageBuild{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("stale build remains: %v", err)
		}
	})
}
