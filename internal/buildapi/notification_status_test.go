package buildapi

import (
	"context"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNotificationStatusProjection(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	uid := types.UID("subject-uid")
	delivery := &api.WebhookDelivery{
		ObjectMeta: metav1.ObjectMeta{Name: notifications.DeliveryName(string(uid)), Namespace: "test-ns"},
		Spec:       api.WebhookDeliverySpec{Subject: api.DeliverySubject{UID: uid}},
		Status: api.WebhookDeliveryStatus{NotificationStatus: api.NotificationStatus{
			State: api.DeliveryFailed, Attempts: 3, LastError: "receiver rejected request",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(delivery).Build()

	status, err := getNotificationStatus(context.Background(), k8sClient, "test-ns", uid, true)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != api.DeliveryFailed || status.Attempts != 3 || status.LastError != "receiver rejected request" {
		t.Fatalf("unexpected notification status: %+v", status)
	}
	pending, err := getNotificationStatus(context.Background(), k8sClient, "test-ns", "not-terminal", true)
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != api.DeliveryPending || pending.Attempts != 0 {
		t.Fatalf("unexpected pending status: %+v", pending)
	}
	absent, err := getNotificationStatus(context.Background(), k8sClient, "test-ns", uid, false)
	if err != nil || absent != nil {
		t.Fatalf("callback-free operation returned status=%+v err=%v", absent, err)
	}
}

func TestListNotificationStatuses(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	uid := types.UID("subject-uid")
	delivery := &api.WebhookDelivery{
		ObjectMeta: metav1.ObjectMeta{Name: "delivery", Namespace: "test-ns"},
		Spec:       api.WebhookDeliverySpec{Subject: api.DeliverySubject{UID: uid}},
		Status:     api.WebhookDeliveryStatus{NotificationStatus: api.NotificationStatus{State: api.DeliveryDelivered, Attempts: 1}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(delivery).Build()
	statuses, err := listNotificationStatuses(context.Background(), k8sClient, "test-ns", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := projectedNotification(statuses, uid, true); got.State != api.DeliveryDelivered || got.Attempts != 1 {
		t.Fatalf("unexpected projected status: %+v", got)
	}
	if got := projectedNotification(statuses, "missing", true); got.State != api.DeliveryPending {
		t.Fatalf("unexpected missing-delivery status: %+v", got)
	}
	if got := projectedNotification(statuses, uid, false); got != nil {
		t.Fatalf("callback-free operation returned status: %+v", got)
	}
}
