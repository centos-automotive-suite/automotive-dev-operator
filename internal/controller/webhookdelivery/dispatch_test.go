package webhookdelivery

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type recordedSender struct {
	results  []attemptResult
	requests []deliveryRequest
}

func (s *recordedSender) Send(_ context.Context, request deliveryRequest) attemptResult {
	request.Key = bytes.Clone(request.Key)
	request.Snapshot = request.Snapshot.DeepCopy()
	s.requests = append(s.requests, request)
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

func pendingDelivery(now time.Time) *automotivev1alpha1.WebhookDelivery {
	return &automotivev1alpha1.WebhookDelivery{
		ObjectMeta: metav1.ObjectMeta{
			Name: "webhook-event", Namespace: "test-ns", CreationTimestamp: metav1.NewTime(now),
		},
		Spec: automotivev1alpha1.WebhookDeliverySpec{
			Subject: automotivev1alpha1.DeliverySubject{
				APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: notifications.SubjectImageBuild,
				Name: "image-build", UID: types.UID("build-uid"),
			},
			CallbackSecretRef: "callback-secret",
		},
		Status: automotivev1alpha1.WebhookDeliveryStatus{
			NotificationStatus: automotivev1alpha1.NotificationStatus{State: automotivev1alpha1.DeliveryPending},
			Snapshot: &automotivev1alpha1.WebhookEventSnapshot{
				ID: "event-id", Type: notifications.BuildTerminal, Time: metav1.NewTime(now), Body: []byte(`{"id":"event-id"}`),
			},
		},
	}
}

func deliveryConfig(maxAttempts, windowSeconds int32, enabled bool) *automotivev1alpha1.OperatorConfig {
	return &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "config-ns"},
		Spec: automotivev1alpha1.OperatorConfigSpec{
			FeatureGates: map[string]bool{string(featuregates.WebhookNotifications): enabled},
			WebhookNotifications: &automotivev1alpha1.WebhookNotificationsConfig{
				TimeoutSeconds: 2, MaxAttempts: maxAttempts, DeliveryWindowSeconds: windowSeconds,
			},
		},
	}
}

func deliverySecret() *corev1.Secret {
	controller := true
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "callback-secret", Namespace: "test-ns",
			Labels: map[string]string{notifications.LabelCallbackSecret: "true"},
			Annotations: map[string]string{
				notifications.AnnotationCallbackSubjectKind: notifications.SubjectImageBuild,
				notifications.AnnotationCallbackSubjectName: "image-build",
				notifications.AnnotationCallbackSubjectUID:  "build-uid",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: notifications.SubjectImageBuild,
				Name: "image-build", UID: "build-uid", Controller: &controller,
			}},
		},
		Data: map[string][]byte{
			notifications.CallbackURLKey:  []byte("https://receiver.example/hook"),
			notifications.CallbackHMACKey: []byte("01234567890123456789012345678901"),
		},
	}
}

func TestDeliveryRejectsReplacementCredentials(t *testing.T) {
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	now := created
	delivery := pendingDelivery(created)
	secret := deliverySecret()
	secret.Annotations[notifications.AnnotationCallbackSubjectUID] = "replacement-uid"
	secret.OwnerReferences[0].UID = "replacement-uid"
	send := &recordedSender{results: []attemptResult{{statusCode: http.StatusNoContent}}}
	r, request := dispatchReconciler(t, send, &now, delivery, deliveryConfig(3, 300, true), secret)

	if _, err := (&deliveryReconciler{Reconciler: r}).Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stored := storedDelivery(t, r, request)
	if stored.Status.State != automotivev1alpha1.DeliveryFailed || stored.Status.Attempts != 0 || len(send.requests) != 0 {
		t.Fatalf("replacement credentials were not rejected: %+v sends=%d", stored.Status, len(send.requests))
	}
}

func TestUnsnapshottedDeliveryExpires(t *testing.T) {
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	now := created.Add(time.Minute)
	delivery := pendingDelivery(created)
	delivery.Status.Snapshot = nil
	delivery.Status.LastError = "callback secret is missing"
	r, request := dispatchReconciler(t, &recordedSender{}, &now, delivery, deliveryConfig(3, 60, true))

	if _, err := (&deliveryReconciler{Reconciler: r}).Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stored := storedDelivery(t, r, request)
	if stored.Status.State != automotivev1alpha1.DeliveryFailed || stored.Status.LastError != "delivery window expired" {
		t.Fatalf("unsnapshotted delivery did not expire: %+v", stored.Status)
	}
}

func dispatchReconciler(t *testing.T, sender sender, now *time.Time, objects ...client.Object) (*Reconciler, reconcile.Request) {
	t.Helper()
	r := testReconciler(t, objects...)
	r.configKey = types.NamespacedName{Name: "config", Namespace: "config-ns"}
	r.sender = sender
	r.now = func() time.Time { return *now }
	r.backoff = func(int32) time.Duration { return time.Second }
	delivery := objects[0].(*automotivev1alpha1.WebhookDelivery)
	return r, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(delivery)}
}

func storedDelivery(t *testing.T, r *Reconciler, request reconcile.Request) *automotivev1alpha1.WebhookDelivery {
	t.Helper()
	delivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(context.Background(), request.NamespacedName, delivery); err != nil {
		t.Fatal(err)
	}
	return delivery
}

func TestDeliveryRetriesStableSnapshotAndCompletes(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	now := created.Add(time.Minute)
	delivery := pendingDelivery(created)
	send := &recordedSender{results: []attemptResult{
		{statusCode: http.StatusServiceUnavailable, retryable: true, errorText: "receiver returned HTTP 503"},
		{statusCode: http.StatusNoContent},
	}}
	r, request := dispatchReconciler(t, send, &now, delivery, deliveryConfig(3, 300, true), deliverySecret())
	reconciler := &deliveryReconciler{Reconciler: r}
	result, err := reconciler.Reconcile(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != time.Second {
		t.Fatalf("retry delay = %v, want 1s", result.RequeueAfter)
	}
	stored := storedDelivery(t, r, request)
	if stored.Status.State != automotivev1alpha1.DeliveryPending || stored.Status.Attempts != 1 ||
		stored.Status.LastHTTPStatus != http.StatusServiceUnavailable || stored.Status.NextAttemptTime == nil {
		t.Fatalf("unexpected retry status: %+v", stored.Status)
	}

	now = now.Add(time.Second)
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	stored = storedDelivery(t, r, request)
	if stored.Status.State != automotivev1alpha1.DeliveryDelivered || stored.Status.Attempts != 2 ||
		stored.Status.LastHTTPStatus != http.StatusNoContent || stored.Status.CompletionTime == nil {
		t.Fatalf("unexpected delivered status: %+v", stored.Status)
	}
	if len(send.requests) != 2 || !bytes.Equal(send.requests[0].Snapshot.Body, send.requests[1].Snapshot.Body) ||
		send.requests[0].Snapshot.ID != send.requests[1].Snapshot.ID {
		t.Fatalf("retry changed the frozen event: %+v", send.requests)
	}
	if !send.requests[1].Timestamp.After(send.requests[0].Timestamp) {
		t.Fatalf("retry timestamp was not refreshed: %+v", send.requests)
	}
}

func TestDeliveryHonorsRetryAfterAndAttemptLimit(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	now := created
	delivery := pendingDelivery(created)
	send := &recordedSender{results: []attemptResult{
		{statusCode: http.StatusTooManyRequests, retryable: true, retryAfter: 30 * time.Second, errorText: "receiver returned HTTP 429"},
		{retryable: true, errorText: "request failed"},
	}}
	r, request := dispatchReconciler(t, send, &now, delivery, deliveryConfig(2, 300, true), deliverySecret())
	reconciler := &deliveryReconciler{Reconciler: r}
	result, err := reconciler.Reconcile(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("Retry-After delay = %v, want 30s", result.RequeueAfter)
	}
	stored := storedDelivery(t, r, request)
	if stored.Status.NextAttemptTime == nil || !stored.Status.NextAttemptTime.Equal(&metav1.Time{Time: now.Add(30 * time.Second)}) {
		t.Fatalf("unexpected next attempt: %v", stored.Status.NextAttemptTime)
	}

	now = now.Add(30 * time.Second)
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	stored = storedDelivery(t, r, request)
	if stored.Status.State != automotivev1alpha1.DeliveryFailed || stored.Status.Attempts != 2 ||
		stored.Status.LastError != "maximum delivery attempts reached: request failed" {
		t.Fatalf("unexpected exhausted status: %+v", stored.Status)
	}
}

func TestDeliveryStopsOnPermanentResponseAndDeadline(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	t.Run("permanent response", func(t *testing.T) {
		now := created
		delivery := pendingDelivery(created)
		send := &recordedSender{results: []attemptResult{{
			statusCode: http.StatusGone, errorText: "receiver returned HTTP 410",
		}}}
		r, request := dispatchReconciler(t, send, &now, delivery, deliveryConfig(8, 300, true), deliverySecret())
		if _, err := (&deliveryReconciler{Reconciler: r}).Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
		stored := storedDelivery(t, r, request)
		if stored.Status.State != automotivev1alpha1.DeliveryFailed || stored.Status.Attempts != 1 ||
			stored.Status.LastHTTPStatus != http.StatusGone {
			t.Fatalf("unexpected permanent failure: %+v", stored.Status)
		}
	})
	t.Run("expired before first attempt", func(t *testing.T) {
		now := created.Add(time.Minute)
		delivery := pendingDelivery(created)
		send := &recordedSender{results: []attemptResult{{statusCode: http.StatusNoContent}}}
		r, request := dispatchReconciler(t, send, &now, delivery, deliveryConfig(8, 60, true), deliverySecret())
		if _, err := (&deliveryReconciler{Reconciler: r}).Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
		stored := storedDelivery(t, r, request)
		if stored.Status.State != automotivev1alpha1.DeliveryFailed || stored.Status.Attempts != 0 ||
			stored.Status.LastError != "delivery window expired" || len(send.requests) != 0 {
			t.Fatalf("unexpected deadline failure: %+v, sends=%d", stored.Status, len(send.requests))
		}
	})
}

func TestFeatureGatePausesAndResumesDelivery(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	now := created
	delivery := pendingDelivery(created)
	config := deliveryConfig(3, 300, false)
	send := &recordedSender{results: []attemptResult{{statusCode: http.StatusAccepted}}}
	r, request := dispatchReconciler(t, send, &now, delivery, config, deliverySecret())
	reconciler := &deliveryReconciler{Reconciler: r}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if len(send.requests) != 0 || storedDelivery(t, r, request).Status.State != automotivev1alpha1.DeliveryPending {
		t.Fatal("disabled feature attempted delivery")
	}

	storedConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), storedConfig); err != nil {
		t.Fatal(err)
	}
	storedConfig.Spec.FeatureGates[string(featuregates.WebhookNotifications)] = true
	if err := r.Update(ctx, storedConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if len(send.requests) != 1 || storedDelivery(t, r, request).Status.State != automotivev1alpha1.DeliveryDelivered {
		t.Fatal("enabled feature did not resume delivery")
	}
}

func TestInterruptedFinalAttemptIsReplayed(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	now := created.Add(time.Second)
	delivery := pendingDelivery(created)
	delivery.Status.State = automotivev1alpha1.DeliveryDelivering
	delivery.Status.Attempts = 1
	delivery.Status.LastAttemptTime = timePointer(created)
	send := &recordedSender{results: []attemptResult{{statusCode: http.StatusNoContent}}}
	r, request := dispatchReconciler(t, send, &now, delivery, deliveryConfig(1, 300, true), deliverySecret())
	if _, err := (&deliveryReconciler{Reconciler: r}).Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	stored := storedDelivery(t, r, request)
	if stored.Status.State != automotivev1alpha1.DeliveryDelivered || stored.Status.Attempts != 1 || len(send.requests) != 1 {
		t.Fatalf("interrupted attempt was not replayed: %+v, sends=%d", stored.Status, len(send.requests))
	}
}

func TestTrustedCABundleLoading(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	pemBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook-ca", Namespace: "config-ns"},
		Data:       map[string]string{"ca-bundle.crt": string(pemBundle)},
	}
	now := time.Now()
	delivery := pendingDelivery(now)
	r, _ := dispatchReconciler(t, &recordedSender{}, &now, delivery, configMap)
	config := effectiveNotificationConfig(&automotivev1alpha1.WebhookNotificationsConfig{
		OutboundPolicy: &automotivev1alpha1.OutboundPolicyConfig{TrustedCAConfigMap: configMap.Name},
	})
	tlsConfig, err := r.tlsConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs}); err != nil {
		t.Fatalf("custom CA was not trusted: %v", err)
	}
}
