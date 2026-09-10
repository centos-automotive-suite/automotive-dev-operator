package buildapi

import (
	"context"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func pendingNotification(configured bool) *NotificationStatus {
	if !configured {
		return nil
	}
	return &NotificationStatus{State: automotivev1alpha1.DeliveryPending}
}

func getNotificationStatus(ctx context.Context, k8sClient client.Client, namespace string, subjectUID types.UID, configured bool) (*NotificationStatus, error) {
	if !configured {
		return nil, nil
	}
	delivery := &automotivev1alpha1.WebhookDelivery{}
	err := k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: notifications.DeliveryName(string(subjectUID))}, delivery)
	if k8serrors.IsNotFound(err) {
		return pendingNotification(true), nil
	}
	if err != nil {
		return nil, err
	}
	status := delivery.Status.NotificationStatus
	if status.State == "" {
		status.State = automotivev1alpha1.DeliveryPending
	}
	return &status, nil
}

func listNotificationStatuses(ctx context.Context, k8sClient client.Client, namespace string, needed bool) (map[types.UID]*NotificationStatus, error) {
	statuses := map[types.UID]*NotificationStatus{}
	if !needed {
		return statuses, nil
	}
	deliveries := &automotivev1alpha1.WebhookDeliveryList{}
	if err := k8sClient.List(ctx, deliveries, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	for i := range deliveries.Items {
		delivery := &deliveries.Items[i]
		status := delivery.Status.NotificationStatus
		if status.State == "" {
			status.State = automotivev1alpha1.DeliveryPending
		}
		statuses[delivery.Spec.Subject.UID] = &status
	}
	return statuses, nil
}

func projectedNotification(statuses map[types.UID]*NotificationStatus, subjectUID types.UID, configured bool) *NotificationStatus {
	if !configured {
		return nil
	}
	if status := statuses[subjectUID]; status != nil {
		return status
	}
	return pendingNotification(true)
}
