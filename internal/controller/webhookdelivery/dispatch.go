package webhookdelivery

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	defaultTimeoutSeconds        = 10
	defaultMaxAttempts           = 8
	defaultDeliveryWindowSeconds = 86400
	maxBackoff                   = time.Hour
)

type deliveryReconciler struct {
	*Reconciler
}

func (r *deliveryReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	delivery := &automotivev1alpha1.WebhookDelivery{}
	if err := r.Get(ctx, req.NamespacedName, delivery); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if delivery.Status.State == automotivev1alpha1.DeliveryDelivered ||
		delivery.Status.State == automotivev1alpha1.DeliveryFailed {
		return ctrl.Result{}, nil
	}

	config, enabled, err := r.loadConfig(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !enabled {
		return ctrl.Result{}, nil
	}

	now := r.currentTime()
	deadline := deliveryDeadline(delivery, config)
	if !now.Before(deadline) {
		return ctrl.Result{}, r.failWithoutAttempt(ctx, delivery, now, "delivery window expired")
	}
	if delivery.Status.Snapshot == nil {
		return ctrl.Result{RequeueAfter: min(time.Minute, deadline.Sub(now))}, nil
	}
	if delivery.Status.NextAttemptTime != nil && now.Before(delivery.Status.NextAttemptTime.Time) {
		return ctrl.Result{RequeueAfter: delivery.Status.NextAttemptTime.Sub(now)}, nil
	}
	interruptedAttempt := delivery.Status.State == automotivev1alpha1.DeliveryDelivering
	if delivery.Status.Attempts >= config.MaxAttempts && !interruptedAttempt {
		return ctrl.Result{}, r.failWithoutAttempt(ctx, delivery, now, "maximum delivery attempts reached")
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: delivery.Namespace,
		Name:      delivery.Spec.CallbackSecretRef,
	}, secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("get callback credentials: %w", err)
	}
	if !credentialsMatchDelivery(secret, delivery) {
		return ctrl.Result{}, r.failWithoutAttempt(ctx, delivery, now, "callback credentials do not match delivery subject")
	}
	endpoint := secret.Data[notifications.CallbackURLKey]
	key := secret.Data[notifications.CallbackHMACKey]
	if len(endpoint) == 0 || len(endpoint) > 2048 || len(key) < 32 || len(key) > 4096 {
		return ctrl.Result{}, r.failWithoutAttempt(ctx, delivery, now, "callback credentials are invalid")
	}
	tlsConfig, err := r.tlsConfig(ctx, config)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("load webhook trust configuration: %w", err)
		}
		return ctrl.Result{}, r.failWithoutAttempt(ctx, delivery, now, "trusted CA configuration is invalid")
	}

	attempt := delivery.Status.Attempts
	if !interruptedAttempt || attempt == 0 {
		attempt++
	}
	if err := r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
		status.State = automotivev1alpha1.DeliveryDelivering
		status.Attempts = attempt
		status.LastAttemptTime = timePointer(now)
		status.NextAttemptTime = nil
		status.LastHTTPStatus = 0
		status.LastError = ""
	}); err != nil {
		return ctrl.Result{}, err
	}

	send := r.sender
	if send == nil {
		send = &httpSender{}
	}
	result := send.Send(ctx, deliveryRequest{
		URL: string(endpoint), Key: key, Snapshot: delivery.Status.Snapshot,
		Timestamp: now, Config: config, TLSConfig: tlsConfig,
	})
	return r.finishAttempt(ctx, delivery, config, deadline, attempt, result)
}

func credentialsMatchDelivery(secret *corev1.Secret, delivery *automotivev1alpha1.WebhookDelivery) bool {
	subject := delivery.Spec.Subject
	if secret.Labels[notifications.LabelCallbackSecret] != labels.ValueTrue ||
		secret.Annotations[notifications.AnnotationCallbackSubjectKind] != subject.Kind ||
		secret.Annotations[notifications.AnnotationCallbackSubjectName] != subject.Name ||
		secret.Annotations[notifications.AnnotationCallbackSubjectUID] != string(subject.UID) {
		return false
	}
	for _, owner := range secret.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == subject.APIVersion &&
			owner.Kind == subject.Kind && owner.Name == subject.Name && owner.UID == subject.UID {
			return true
		}
	}
	return false
}

func (r *deliveryReconciler) finishAttempt(
	ctx context.Context,
	delivery *automotivev1alpha1.WebhookDelivery,
	config automotivev1alpha1.WebhookNotificationsConfig,
	deadline time.Time,
	attempt int32,
	result attemptResult,
) (ctrl.Result, error) {
	finished := r.currentTime()
	if result.errorText == "" && result.statusCode >= 200 && result.statusCode < 300 {
		if err := r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
			status.State = automotivev1alpha1.DeliveryDelivered
			status.LastHTTPStatus = result.statusCode
			status.CompletionTime = timePointer(finished)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if !result.retryable {
		if err := r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
			status.State = automotivev1alpha1.DeliveryFailed
			status.LastHTTPStatus = result.statusCode
			status.LastError = result.errorText
			status.CompletionTime = timePointer(finished)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if attempt >= config.MaxAttempts {
		message := "maximum delivery attempts reached"
		if result.errorText != "" {
			message += ": " + result.errorText
		}
		if err := r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
			status.State = automotivev1alpha1.DeliveryFailed
			status.LastHTTPStatus = result.statusCode
			status.LastError = message
			status.CompletionTime = timePointer(finished)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	delay := r.retryBackoff(attempt)
	if result.retryAfter > delay {
		delay = result.retryAfter
	}
	if delay > maxRetryAfter {
		delay = maxRetryAfter
	}
	if !finished.Add(delay).Before(deadline) {
		if err := r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
			status.State = automotivev1alpha1.DeliveryFailed
			status.LastHTTPStatus = result.statusCode
			status.LastError = "delivery window expired: " + result.errorText
			status.CompletionTime = timePointer(finished)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	next := finished.Add(delay)
	if err := r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
		status.State = automotivev1alpha1.DeliveryPending
		status.LastHTTPStatus = result.statusCode
		status.LastError = result.errorText
		status.NextAttemptTime = timePointer(next)
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: delay}, nil
}

func (r *Reconciler) loadConfig(ctx context.Context) (automotivev1alpha1.WebhookNotificationsConfig, bool, error) {
	key := r.configKey
	if key.Name == "" {
		key = types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}
	}
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, key, operatorConfig); err != nil {
		if k8serrors.IsNotFound(err) {
			return effectiveNotificationConfig(nil), false, nil
		}
		return automotivev1alpha1.WebhookNotificationsConfig{}, false, err
	}
	enabled := featuregates.NewFromConfig(&operatorConfig.Spec).Enabled(featuregates.WebhookNotifications)
	return effectiveNotificationConfig(operatorConfig.Spec.WebhookNotifications), enabled, nil
}

func effectiveNotificationConfig(config *automotivev1alpha1.WebhookNotificationsConfig) automotivev1alpha1.WebhookNotificationsConfig {
	if config == nil {
		config = &automotivev1alpha1.WebhookNotificationsConfig{}
	}
	effective := *config
	if effective.TimeoutSeconds == 0 {
		effective.TimeoutSeconds = defaultTimeoutSeconds
	}
	if effective.MaxAttempts == 0 {
		effective.MaxAttempts = defaultMaxAttempts
	}
	if effective.DeliveryWindowSeconds == 0 {
		effective.DeliveryWindowSeconds = defaultDeliveryWindowSeconds
	}
	return effective
}

func deliveryDeadline(delivery *automotivev1alpha1.WebhookDelivery, config automotivev1alpha1.WebhookNotificationsConfig) time.Time {
	started := delivery.CreationTimestamp.Time
	if started.IsZero() && delivery.Status.Snapshot != nil {
		started = delivery.Status.Snapshot.Time.Time
	}
	return started.Add(time.Duration(config.DeliveryWindowSeconds) * time.Second)
}

func (r *Reconciler) currentTime() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

func (r *Reconciler) retryBackoff(attempt int32) time.Duration {
	if r.backoff != nil {
		return r.backoff(attempt)
	}
	exponent := min(max(attempt-1, 0), 12)
	ceiling := min(time.Second*time.Duration(1<<exponent), maxBackoff)
	floor := ceiling / 2
	spread := ceiling - floor
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(spread)+1))
	if err != nil {
		return ceiling
	}
	return floor + time.Duration(random.Int64())
}

func (r *Reconciler) patchState(
	ctx context.Context,
	delivery *automotivev1alpha1.WebhookDelivery,
	mutate func(*automotivev1alpha1.WebhookDeliveryStatus),
) error {
	patch := client.MergeFromWithOptions(delivery.DeepCopy(), client.MergeFromWithOptimisticLock{})
	mutate(&delivery.Status)
	if err := r.Status().Patch(ctx, delivery, patch); err != nil {
		return fmt.Errorf("update webhook delivery status: %w", err)
	}
	return nil
}

func (r *Reconciler) failWithoutAttempt(ctx context.Context, delivery *automotivev1alpha1.WebhookDelivery, now time.Time, message string) error {
	return r.patchState(ctx, delivery, func(status *automotivev1alpha1.WebhookDeliveryStatus) {
		status.State = automotivev1alpha1.DeliveryFailed
		status.LastError = message
		status.NextAttemptTime = nil
		status.CompletionTime = timePointer(now)
	})
}

func timePointer(value time.Time) *metav1.Time {
	timestamp := metav1.NewTime(value)
	return &timestamp
}

func (r *Reconciler) tlsConfig(ctx context.Context, config automotivev1alpha1.WebhookNotificationsConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.OutboundPolicy == nil || config.OutboundPolicy.TrustedCAConfigMap == "" {
		return tlsConfig, nil
	}
	key := r.configKey
	if key.Namespace == "" {
		key.Namespace = controllerutils.OperatorNamespace()
	}
	bundle := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: key.Namespace,
		Name:      config.OutboundPolicy.TrustedCAConfigMap,
	}, bundle); err != nil {
		return nil, err
	}
	data := []byte(bundle.Data["ca-bundle.crt"])
	if len(data) == 0 {
		data = bundle.BinaryData["ca-bundle.crt"]
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(data) == 0 || !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid trusted CA bundle")
	}
	tlsConfig.RootCAs = roots
	return tlsConfig, nil
}

func (r *Reconciler) setupDeliverySender(mgr ctrl.Manager, options controller.Options) error {
	configPredicate := predicate.NewPredicateFuncs(func(object client.Object) bool {
		key := r.configKey
		if key.Name == "" {
			key = types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}
		}
		return object.GetName() == key.Name && object.GetNamespace() == key.Namespace
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("webhook-delivery-sender").
		WithOptions(options).
		For(&automotivev1alpha1.WebhookDelivery{}).
		Watches(
			&automotivev1alpha1.OperatorConfig{},
			handler.EnqueueRequestsFromMapFunc(r.deliveriesForConfig),
			builder.WithPredicates(configPredicate),
		).
		Complete(&deliveryReconciler{Reconciler: r})
}

func (r *Reconciler) deliveriesForConfig(ctx context.Context, _ client.Object) []reconcile.Request {
	deliveries := &automotivev1alpha1.WebhookDeliveryList{}
	if err := r.List(ctx, deliveries); err != nil {
		r.Log.Error(err, "unable to list webhook deliveries after configuration change")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(deliveries.Items))
	for i := range deliveries.Items {
		delivery := &deliveries.Items[i]
		if delivery.Status.Snapshot != nil && delivery.Status.State != automotivev1alpha1.DeliveryDelivered &&
			delivery.Status.State != automotivev1alpha1.DeliveryFailed {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(delivery)})
		}
	}
	return requests
}
