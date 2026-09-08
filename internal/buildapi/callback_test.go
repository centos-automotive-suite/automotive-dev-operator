package buildapi

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func callbackTestBuild() *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name: "callback-build", Namespace: "test-ns", UID: types.UID("build-uid"),
			Annotations: map[string]string{notifications.AnnotationCallbackInitializing: "true"},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			ExternalID:        "external-id",
			CallbackSecretRef: notifications.CallbackSecretName(notifications.SubjectImageBuild, "callback-build", "build-uid"),
		},
	}
}

func callbackTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func callbackTestValue() *BuildCallback {
	return &BuildCallback{
		URL:    "https://receiver.example/hook",
		Secret: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
	}
}

func TestCompleteBuildCallbackInitialization(t *testing.T) {
	ctx := context.Background()
	t.Run("persists credentials and removes marker", func(t *testing.T) {
		build := callbackTestBuild()
		k8sClient := fake.NewClientBuilder().WithScheme(callbackTestScheme(t)).WithObjects(build).Build()
		if err := completeBuildCallbackInitialization(ctx, k8sClient, build, callbackTestValue()); err != nil {
			t.Fatal(err)
		}
		storedBuild := &automotivev1alpha1.ImageBuild{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(build), storedBuild); err != nil {
			t.Fatal(err)
		}
		if storedBuild.Annotations[notifications.AnnotationCallbackInitializing] != "" {
			t.Fatal("initialization marker remains")
		}
		secret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Namespace: build.Namespace,
			Name:      build.Spec.CallbackSecretRef,
		}, secret); err != nil {
			t.Fatal(err)
		}
		if string(secret.Data[notifications.CallbackURLKey]) != callbackTestValue().URL ||
			string(secret.Data[notifications.CallbackHMACKey]) != "01234567890123456789012345678901" ||
			!metav1.IsControlledBy(secret, build) {
			t.Fatalf("unexpected callback secret: %+v", secret)
		}
	})
	t.Run("secret write failure leaves initialization recoverable", func(t *testing.T) {
		build := callbackTestBuild()
		k8sClient := fake.NewClientBuilder().
			WithScheme(callbackTestScheme(t)).
			WithObjects(build).
			WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, underlying client.WithWatch, object client.Object, options ...client.CreateOption) error {
					if _, ok := object.(*corev1.Secret); ok {
						return errors.New("injected secret failure")
					}
					return underlying.Create(ctx, object, options...)
				},
			}).Build()
		if err := completeBuildCallbackInitialization(ctx, k8sClient, build, callbackTestValue()); err == nil {
			t.Fatal("expected secret failure")
		}
		storedBuild := &automotivev1alpha1.ImageBuild{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(build), storedBuild); err != nil {
			t.Fatal(err)
		}
		if storedBuild.Annotations[notifications.AnnotationCallbackInitializing] != "true" {
			t.Fatal("marker was removed after secret failure")
		}
	})
	t.Run("marker write failure leaves owned credentials recoverable", func(t *testing.T) {
		build := callbackTestBuild()
		markerPatchAttempts := 0
		k8sClient := fake.NewClientBuilder().
			WithScheme(callbackTestScheme(t)).
			WithObjects(build).
			WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(ctx context.Context, underlying client.WithWatch, object client.Object, patch client.Patch, options ...client.PatchOption) error {
					if _, ok := object.(*automotivev1alpha1.ImageBuild); ok {
						markerPatchAttempts++
						if markerPatchAttempts == 1 {
							return errors.New("injected marker failure")
						}
					}
					return underlying.Patch(ctx, object, patch, options...)
				},
			}).Build()
		if err := completeBuildCallbackInitialization(ctx, k8sClient, build, callbackTestValue()); !errors.Is(err, errCallbackInitializationDeferred) {
			t.Fatalf("expected deferred initialization, got %v", err)
		}
		secret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Namespace: build.Namespace,
			Name:      build.Spec.CallbackSecretRef,
		}, secret); err != nil {
			t.Fatal(err)
		}
		if !metav1.IsControlledBy(secret, build) {
			t.Fatal("callback secret cannot be recovered")
		}
		storedBuild := &automotivev1alpha1.ImageBuild{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(build), storedBuild); err != nil {
			t.Fatal(err)
		}
		if storedBuild.Annotations[notifications.AnnotationCallbackInitializing] != "true" {
			t.Fatal("stored marker was removed")
		}
		storedBuild.DeepCopyInto(build)
		if err := completeBuildCallbackInitialization(ctx, k8sClient, build, callbackTestValue()); err != nil {
			t.Fatalf("retry callback initialization: %v", err)
		}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(build), storedBuild); err != nil {
			t.Fatal(err)
		}
		if storedBuild.Annotations[notifications.AnnotationCallbackInitializing] != "" {
			t.Fatal("initialization marker remains after retry")
		}
	})
}

func TestCreateCallbackSecretRejectsConflictingExistingSecret(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Secret)
	}{
		{name: "unowned", mutate: func(secret *corev1.Secret) { secret.OwnerReferences = nil }},
		{name: "mismatched owner", mutate: func(secret *corev1.Secret) { secret.OwnerReferences[0].UID = "other-uid" }},
		{name: "mismatched data", mutate: func(secret *corev1.Secret) {
			secret.Data[notifications.CallbackURLKey] = []byte("https://other.example/hook")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := callbackTestBuild()
			k8sClient := fake.NewClientBuilder().WithScheme(callbackTestScheme(t)).Build()
			secret, err := createCallbackSecret(
				ctx, k8sClient, build.Namespace, build.Spec.CallbackSecretRef,
				notifications.SubjectImageBuild, build.Name, build.UID, callbackTestValue(),
			)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(secret)
			if err := k8sClient.Update(ctx, secret); err != nil {
				t.Fatal(err)
			}
			if _, err := createCallbackSecret(
				ctx, k8sClient, build.Namespace, build.Spec.CallbackSecretRef,
				notifications.SubjectImageBuild, build.Name, build.UID, callbackTestValue(),
			); err == nil {
				t.Fatal("conflicting existing callback secret was accepted")
			}
		})
	}
}

func TestAdoptCallbackSecretRetriesConflict(t *testing.T) {
	ctx := context.Background()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "callback", Namespace: "test-ns"}}
	patchAttempts := 0
	k8sClient := fake.NewClientBuilder().
		WithScheme(callbackTestScheme(t)).
		WithObjects(secret).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, underlying client.WithWatch, object client.Object, patch client.Patch, options ...client.PatchOption) error {
				patchAttempts++
				if patchAttempts == 1 {
					return k8serrors.NewConflict(schema.GroupResource{Resource: "secrets"}, object.GetName(), errors.New("injected conflict"))
				}
				return underlying.Patch(ctx, object, patch, options...)
			},
		}).Build()

	if err := adoptCallbackSecret(ctx, k8sClient, secret, notifications.SubjectTaskRun, "flash", "taskrun-uid"); err != nil {
		t.Fatal(err)
	}
	if patchAttempts != 2 {
		t.Fatalf("patch attempts = %d", patchAttempts)
	}
	stored := &corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(secret), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Annotations[notifications.AnnotationCallbackSubjectUID] != "taskrun-uid" || len(stored.OwnerReferences) != 1 {
		t.Fatalf("callback ownership was not persisted: %+v", stored)
	}
}

func TestRollbackCallbackSubject(t *testing.T) {
	ctx := context.Background()
	build := callbackTestBuild()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "callback", Namespace: build.Namespace}}
	k8sClient := fake.NewClientBuilder().WithScheme(callbackTestScheme(t)).WithObjects(build, secret).Build()
	if err := rollbackCallbackSubject(ctx, k8sClient, build, secret); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(build), &automotivev1alpha1.ImageBuild{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("callback subject remains: %v", err)
	}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("callback secret remains: %v", err)
	}
}
