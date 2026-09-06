package webhookdelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	knativev1 "knative.dev/pkg/apis/duck/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		automotivev1alpha1.AddToScheme,
		tektonv1.AddToScheme,
		corev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func testReconciler(t *testing.T, objects ...client.Object) *Reconciler {
	t.Helper()
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&automotivev1alpha1.WebhookDelivery{}, &automotivev1alpha1.ImageBuild{}, &tektonv1.TaskRun{}).
		WithObjects(objects...).
		Build()
	return &Reconciler{Client: k8sClient, Scheme: scheme, Log: logr.Discard()}
}

func terminalBuild(uid types.UID) *automotivev1alpha1.ImageBuild {
	completed := metav1.NewTime(time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC))
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "image-build",
			Namespace: "test-ns",
			UID:       uid,
			Annotations: map[string]string{
				automotivev1alpha1.AnnotationTraceID: "trace-build",
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			ExternalID:        "external-build",
			CallbackSecretRef: notifications.CallbackSecretName(notifications.SubjectImageBuild, "image-build", string(uid)),
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase: automotivev1alpha1.ImageBuildPhaseCompleted,
			TerminalResult: &automotivev1alpha1.BuildTerminalResult{
				Phase:       automotivev1alpha1.ImageBuildPhaseCompleted,
				Message:     "complete",
				CompletedAt: completed,
				Artifacts: []automotivev1alpha1.ArtifactStatus{{
					Kind: "container", URL: "registry.example/image", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				}},
			},
		},
	}
}

func callbackSecret(subject client.Object, kind string, owned bool) *corev1.Secret {
	uid := ""
	ownerReferences := []metav1.OwnerReference(nil)
	if owned {
		uid = string(subject.GetUID())
		controller := true
		ownerReferences = []metav1.OwnerReference{{
			APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: kind,
			Name: subject.GetName(), UID: subject.GetUID(), Controller: &controller,
		}}
		if kind == notifications.SubjectTaskRun {
			ownerReferences[0].APIVersion = "tekton.dev/v1"
		}
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      notifications.CallbackSecretName(kind, subject.GetName(), string(subject.GetUID())),
			Namespace: subject.GetNamespace(),
			Labels:    map[string]string{notifications.LabelCallbackSecret: labels.ValueTrue},
			Annotations: map[string]string{
				notifications.AnnotationCallbackSubjectKind: kind,
				notifications.AnnotationCallbackSubjectName: subject.GetName(),
				notifications.AnnotationCallbackSubjectUID:  uid,
			},
			OwnerReferences: ownerReferences,
		},
		Data: map[string][]byte{
			notifications.CallbackURLKey:  []byte("https://receiver.example/hook"),
			notifications.CallbackHMACKey: []byte("01234567890123456789012345678901"),
		},
	}
}

func TestBuildDeliverySnapshotSurvivesExpiryAndDuplicateReconcile(t *testing.T) {
	ctx := context.Background()
	build := terminalBuild("build-uid")
	secret := callbackSecret(build, notifications.SubjectImageBuild, true)
	r := testReconciler(t, build, secret)
	reconciler := &subjectReconciler{Reconciler: r, kind: imageBuildSubject}
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(build)}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	delivery := &automotivev1alpha1.WebhookDelivery{}
	deliveryKey := types.NamespacedName{Namespace: build.Namespace, Name: notifications.DeliveryName(string(build.UID))}
	if err := r.Get(ctx, deliveryKey, delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.Status.State != automotivev1alpha1.DeliveryPending || delivery.Status.Snapshot == nil {
		t.Fatalf("delivery not initialized: %+v", delivery.Status)
	}
	originalSnapshot := delivery.Status.Snapshot.DeepCopy()
	var event notifications.TerminalEvent
	if err := json.Unmarshal(originalSnapshot.Body, &event); err != nil {
		t.Fatal(err)
	}
	if event.Build == nil || event.Build.ExternalID != "external-build" || len(event.Build.Artifacts) != 1 {
		t.Fatalf("unexpected event: %+v", event)
	}
	if bytes.Contains(originalSnapshot.Body, secret.Data[notifications.CallbackURLKey]) ||
		bytes.Contains(originalSnapshot.Body, secret.Data[notifications.CallbackHMACKey]) {
		t.Fatal("event snapshot contains callback credentials")
	}

	storedBuild := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(build), storedBuild); err != nil {
		t.Fatal(err)
	}
	storedBuild.Status.Phase = automotivev1alpha1.ImageBuildPhaseExpired
	storedBuild.Status.Message = "expired"
	if err := r.Status().Update(ctx, storedBuild); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, deliveryKey, delivery); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(originalSnapshot, delivery.Status.Snapshot) {
		t.Fatal("duplicate reconcile replaced the frozen snapshot")
	}
}

func TestMissingCredentialsCreateObservableDeliveryIntent(t *testing.T) {
	ctx := context.Background()
	build := terminalBuild("build-uid")
	r := testReconciler(t, build)

	if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(build)); err == nil {
		t.Fatal("expected missing callback credentials to fail preparation")
	}
	delivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: build.Namespace,
		Name:      notifications.DeliveryName(string(build.UID)),
	}, delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.Status.State != automotivev1alpha1.DeliveryPending || delivery.Status.LastError == "" || delivery.Status.Snapshot != nil {
		t.Fatalf("preparation failure is not observable: %+v", delivery.Status)
	}
}

func TestPreparedOrTerminalDeliveryIsNotReprocessed(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		state    automotivev1alpha1.DeliveryState
		snapshot bool
	}{
		{name: "prepared", state: automotivev1alpha1.DeliveryPending, snapshot: true},
		{name: "delivered", state: automotivev1alpha1.DeliveryDelivered, snapshot: true},
		{name: "failed preparation", state: automotivev1alpha1.DeliveryFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := terminalBuild(types.UID(strings.ReplaceAll(tc.name, " ", "-")))
			delivery := &automotivev1alpha1.WebhookDelivery{
				ObjectMeta: metav1.ObjectMeta{
					Name:      notifications.DeliveryName(string(build.UID)),
					Namespace: build.Namespace,
				},
				Spec: automotivev1alpha1.WebhookDeliverySpec{
					Subject: automotivev1alpha1.DeliverySubject{
						APIVersion: automotivev1alpha1.GroupVersion.String(),
						Kind:       notifications.SubjectImageBuild,
						Name:       build.Name,
						UID:        build.UID,
					},
					CallbackSecretRef: build.Spec.CallbackSecretRef,
				},
				Status: automotivev1alpha1.WebhookDeliveryStatus{
					NotificationStatus: automotivev1alpha1.NotificationStatus{State: tc.state},
				},
			}
			if tc.snapshot {
				delivery.Status.Snapshot = &automotivev1alpha1.WebhookEventSnapshot{
					ID:   "event-id",
					Type: notifications.BuildTerminal,
					Time: build.Status.TerminalResult.CompletedAt,
					Body: []byte(`{"id":"event-id"}`),
				}
			}
			r := testReconciler(t, build, delivery)

			if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(build)); err != nil {
				t.Fatalf("completed preparation accessed missing credentials: %v", err)
			}
			stored := &automotivev1alpha1.WebhookDelivery{}
			if err := r.Get(ctx, client.ObjectKeyFromObject(delivery), stored); err != nil {
				t.Fatal(err)
			}
			if stored.Status.State != tc.state {
				t.Fatalf("delivery state changed from %q to %q", tc.state, stored.Status.State)
			}
		})
	}
}

func TestPermanentPreparationFailuresAreTerminal(t *testing.T) {
	ctx := context.Background()
	t.Run("invalid credentials", func(t *testing.T) {
		build := terminalBuild("invalid-secret-uid")
		secret := callbackSecret(build, notifications.SubjectImageBuild, true)
		secret.Data[notifications.CallbackHMACKey] = []byte("short")
		r := testReconciler(t, build, secret)

		if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(build)); err != nil {
			t.Fatalf("permanent failure was requeued: %v", err)
		}
		assertFailedPreparation(t, ctx, r, build, "invalid data")
	})

	t.Run("oversized event", func(t *testing.T) {
		build := terminalBuild("oversized-event-uid")
		build.Status.TerminalResult.Message = strings.Repeat("x", notifications.MaxPayloadBytes)
		secret := callbackSecret(build, notifications.SubjectImageBuild, true)
		r := testReconciler(t, build, secret)

		if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(build)); err != nil {
			t.Fatalf("permanent failure was requeued: %v", err)
		}
		assertFailedPreparation(t, ctx, r, build, "terminal event exceeds")
	})

	t.Run("conflicting delivery intent", func(t *testing.T) {
		build := terminalBuild("conflicting-intent-uid")
		delivery := &automotivev1alpha1.WebhookDelivery{
			ObjectMeta: metav1.ObjectMeta{
				Name:      notifications.DeliveryName(string(build.UID)),
				Namespace: build.Namespace,
			},
			Spec: automotivev1alpha1.WebhookDeliverySpec{
				Subject: automotivev1alpha1.DeliverySubject{
					APIVersion: automotivev1alpha1.GroupVersion.String(),
					Kind:       notifications.SubjectImageBuild,
					Name:       build.Name,
					UID:        build.UID,
				},
				CallbackSecretRef: "another-secret",
			},
		}
		r := testReconciler(t, build, delivery)

		if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(build)); err != nil {
			t.Fatalf("permanent failure was requeued: %v", err)
		}
		assertFailedPreparation(t, ctx, r, build, "conflicting immutable intent")
	})
}

func assertFailedPreparation(
	t *testing.T,
	ctx context.Context,
	r *Reconciler,
	build *automotivev1alpha1.ImageBuild,
	wantError string,
) {
	t.Helper()
	delivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: build.Namespace,
		Name:      notifications.DeliveryName(string(build.UID)),
	}, delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.Status.State != automotivev1alpha1.DeliveryFailed ||
		!strings.Contains(delivery.Status.LastError, wantError) || delivery.Status.Snapshot != nil {
		t.Fatalf("permanent preparation failure is not terminal and observable: %+v", delivery.Status)
	}
}

func TestBuildDeliveryCreatedWhenFirstObservedAfterExpiry(t *testing.T) {
	ctx := context.Background()
	build := terminalBuild("expired-build-uid")
	build.Status.Phase = automotivev1alpha1.ImageBuildPhaseExpired
	build.Status.PreviousPhase = automotivev1alpha1.ImageBuildPhaseFailed
	build.Status.Message = "expired"
	build.Status.TerminalResult.Phase = automotivev1alpha1.ImageBuildPhaseFailed
	build.Status.TerminalResult.Message = "original failure"
	secret := callbackSecret(build, notifications.SubjectImageBuild, true)
	r := testReconciler(t, build, secret)
	if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(build)); err != nil {
		t.Fatal(err)
	}
	delivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: build.Namespace,
		Name:      notifications.DeliveryName(string(build.UID)),
	}, delivery); err != nil {
		t.Fatal(err)
	}
	var event notifications.TerminalEvent
	if err := json.Unmarshal(delivery.Status.Snapshot.Body, &event); err != nil {
		t.Fatal(err)
	}
	if event.Build.Phase != automotivev1alpha1.ImageBuildPhaseFailed || event.Build.Message != "original failure" {
		t.Fatalf("event used display status: %+v", event.Build)
	}
}

func TestDeliveryRecoversMissingSnapshotAndSeparatesReplacement(t *testing.T) {
	ctx := context.Background()
	oldBuild := terminalBuild("old-uid")
	oldSecret := callbackSecret(oldBuild, notifications.SubjectImageBuild, true)
	delivery := &automotivev1alpha1.WebhookDelivery{
		ObjectMeta: metav1.ObjectMeta{
			Name:      notifications.DeliveryName(string(oldBuild.UID)),
			Namespace: oldBuild.Namespace,
		},
		Spec: automotivev1alpha1.WebhookDeliverySpec{
			Subject: automotivev1alpha1.DeliverySubject{
				APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: notifications.SubjectImageBuild,
				Name: oldBuild.Name, UID: oldBuild.UID,
			},
			CallbackSecretRef: oldBuild.Spec.CallbackSecretRef,
		},
	}
	r := testReconciler(t, oldBuild, oldSecret, delivery)
	if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(oldBuild)); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(delivery), delivery); err != nil {
		t.Fatal(err)
	}
	if delivery.Status.Snapshot == nil {
		t.Fatal("snapshot was not recovered")
	}

	newBuild := terminalBuild("new-uid")
	newBuild.Name = oldBuild.Name
	newSecret := callbackSecret(newBuild, notifications.SubjectImageBuild, true)
	newSecret.Name = "new-callback"
	newBuild.Spec.CallbackSecretRef = newSecret.Name
	if err := r.Create(ctx, newBuild); err == nil {
		t.Fatal("fake API allowed replacement before deleting the old subject")
	}
	if err := r.Delete(ctx, oldBuild); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, newBuild); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, newSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileBuild(ctx, client.ObjectKeyFromObject(newBuild)); err != nil {
		t.Fatal(err)
	}
	newDelivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: newBuild.Namespace,
		Name:      notifications.DeliveryName(string(newBuild.UID)),
	}, newDelivery); err != nil {
		t.Fatal(err)
	}
	if newDelivery.Spec.Subject.UID != newBuild.UID || newDelivery.Name == delivery.Name {
		t.Fatalf("replacement reused delivery: %+v", newDelivery.Spec.Subject)
	}
}

func terminalFlash(uid types.UID) *tektonv1.TaskRun {
	completed := metav1.NewTime(time.Date(2026, 9, 6, 11, 0, 0, 0, time.UTC))
	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flash", Namespace: "test-ns", UID: uid,
			Labels: map[string]string{labels.FlashTaskRun: "flash"},
			Annotations: map[string]string{
				notifications.AnnotationCallbackSecretRef: notifications.CallbackSecretName(notifications.SubjectTaskRun, "flash", string(uid)),
				notifications.AnnotationExternalID:        "external-flash",
				automotivev1alpha1.AnnotationTraceID:      "trace-flash",
				labels.ImageRef:                           "registry.example/image@sha256:abc",
			},
		},
	}
	taskRun.Status.StartTime = &completed
	taskRun.Status.CompletionTime = &completed
	taskRun.Status.Results = []tektonv1.TaskRunResult{{
		Name: "lease-id", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "lease-42"},
	}}
	taskRun.Status.Conditions = knativev1.Conditions{{
		Type: "Succeeded", Status: corev1.ConditionFalse,
		Reason: string(tektonv1.TaskRunReasonCancelled), Message: "cancelled",
	}}
	return taskRun
}

func TestStandaloneFlashAdoptsSecretAndFreezesCancellation(t *testing.T) {
	ctx := context.Background()
	taskRun := terminalFlash("flash-uid")
	secret := callbackSecret(taskRun, notifications.SubjectTaskRun, false)
	r := testReconciler(t, taskRun, secret)
	if _, err := r.reconcileFlash(ctx, client.ObjectKeyFromObject(taskRun)); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		t.Fatal(err)
	}
	if !metav1.IsControlledBy(secret, taskRun) || secret.Annotations[notifications.AnnotationCallbackSubjectUID] != string(taskRun.UID) {
		t.Fatal("standalone callback secret was not adopted")
	}
	delivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: taskRun.Namespace,
		Name:      notifications.DeliveryName(string(taskRun.UID)),
	}, delivery); err != nil {
		t.Fatal(err)
	}
	var event notifications.TerminalEvent
	if err := json.Unmarshal(delivery.Status.Snapshot.Body, &event); err != nil {
		t.Fatal(err)
	}
	if event.Flash == nil || event.Flash.Phase != automotivev1alpha1.ImageBuildPhaseCancelled ||
		event.Flash.LeaseID != "lease-42" || event.Flash.ExternalID != "external-flash" {
		t.Fatalf("unexpected flash event: %+v", event.Flash)
	}
}

func TestOrphanCallbackSecretRecovery(t *testing.T) {
	ctx := context.Background()
	t.Run("adopts after TaskRun creation", func(t *testing.T) {
		taskRun := terminalFlash("flash-uid")
		secret := callbackSecret(taskRun, notifications.SubjectTaskRun, false)
		r := testReconciler(t, taskRun, secret)
		reconciler := &callbackSecretReconciler{Reconciler: r}
		if _, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(secret)}); err != nil {
			t.Fatal(err)
		}
		if err := r.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
			t.Fatal(err)
		}
		if !metav1.IsControlledBy(secret, taskRun) {
			t.Fatal("secret was not adopted")
		}
	})
	for _, tc := range []struct {
		name    string
		kind    string
		subject client.Object
	}{
		{name: "retains invalid ImageBuild secret", kind: notifications.SubjectImageBuild, subject: terminalBuild("invalid-build-secret")},
		{name: "retains invalid TaskRun secret", kind: notifications.SubjectTaskRun, subject: terminalFlash("invalid-flash-secret")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := callbackSecret(tc.subject, tc.kind, false)
			secret.CreationTimestamp = metav1.NewTime(time.Now().Add(-orphanCallbackTimeout - time.Second))
			secret.Data[notifications.CallbackHMACKey] = []byte("short")
			r := testReconciler(t, tc.subject, secret)
			reconciler := &callbackSecretReconciler{Reconciler: r}
			request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(secret)}

			if result, err := reconciler.Reconcile(ctx, request); err != nil || result != (reconcile.Result{}) {
				t.Fatalf("permanent validation error was requeued: result=%+v, err=%v", result, err)
			}
			stored := &corev1.Secret{}
			if err := r.Get(ctx, client.ObjectKeyFromObject(secret), stored); err != nil {
				t.Fatalf("referenced secret was deleted: %v", err)
			}
			if len(stored.OwnerReferences) != 0 {
				t.Fatal("invalid secret was adopted")
			}

			stored.Data[notifications.CallbackHMACKey] = []byte("01234567890123456789012345678901")
			if err := r.Update(ctx, stored); err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatal(err)
			}
			if err := r.Get(ctx, client.ObjectKeyFromObject(secret), stored); err != nil {
				t.Fatal(err)
			}
			if !metav1.IsControlledBy(stored, tc.subject) {
				t.Fatal("repaired secret was not adopted")
			}
		})
	}
	t.Run("deletes after timeout without TaskRun", func(t *testing.T) {
		taskRun := terminalFlash("missing-uid")
		secret := callbackSecret(taskRun, notifications.SubjectTaskRun, false)
		secret.CreationTimestamp = metav1.NewTime(time.Now().Add(-orphanCallbackTimeout - time.Second))
		r := testReconciler(t, secret)
		reconciler := &callbackSecretReconciler{Reconciler: r}
		if _, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(secret)}); err != nil {
			t.Fatal(err)
		}
		if err := r.Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("orphan secret remains: %v", err)
		}
	})
}
