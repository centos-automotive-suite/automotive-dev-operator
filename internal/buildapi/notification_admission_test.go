package buildapi

import (
	"context"
	"os"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestNotificationAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS or run make test for CRD admission tests")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	config := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "notification-defaults", Namespace: "default"},
		Spec:       automotivev1alpha1.OperatorConfigSpec{WebhookNotifications: &automotivev1alpha1.WebhookNotificationsConfig{}},
	}
	if err := k8s.Create(ctx, config); err != nil {
		t.Fatal(err)
	}
	n := config.Spec.WebhookNotifications
	if n.TimeoutSeconds != 10 || n.MaxAttempts != 8 || n.DeliveryWindowSeconds != 86400 {
		t.Fatalf("unexpected notification defaults: %+v", n)
	}
	assertPolicyAdmission := func(t *testing.T, name string, policy automotivev1alpha1.OutboundPolicyConfig, valid bool) {
		candidate := &automotivev1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: automotivev1alpha1.OperatorConfigSpec{WebhookNotifications: &automotivev1alpha1.WebhookNotificationsConfig{
				OutboundPolicy: &policy,
			}},
		}
		err := k8s.Create(ctx, candidate)
		if valid && err != nil {
			t.Fatalf("valid outbound policy: %v", err)
		}
		if !valid && !k8serrors.IsInvalid(err) {
			t.Fatalf("invalid outbound policy: %v", err)
		}
	}
	for _, tc := range []struct {
		name     string
		hostname string
		valid    bool
	}{
		{name: "hostname-valid", hostname: "receiver.example.com", valid: true},
		{name: "hostname-trailing-dot", hostname: "receiver.example.com.", valid: true},
		{name: "hostname-wildcard", hostname: "*.example.com"},
		{name: "hostname-underscore", hostname: "receiver_service.example.com"},
		{name: "hostname-empty-label", hostname: "receiver..example.com"},
		{name: "hostname-leading-hyphen", hostname: "-receiver.example.com"},
		{name: "hostname-trailing-hyphen", hostname: "receiver-.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertPolicyAdmission(t, tc.name, automotivev1alpha1.OutboundPolicyConfig{AllowedHostnames: []string{tc.hostname}}, tc.valid)
		})
	}
	for _, tc := range []struct {
		name  string
		cidr  string
		valid bool
	}{
		{name: "cidr-ipv4", cidr: "10.0.0.0/8", valid: true},
		{name: "cidr-ipv6", cidr: "2001:db8::/32", valid: true},
		{name: "cidr-missing-prefix", cidr: "10.0.0.1"},
		{name: "cidr-invalid-prefix", cidr: "10.0.0.0/33"},
		{name: "cidr-malformed", cidr: "not-a-cidr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertPolicyAdmission(t, tc.name, automotivev1alpha1.OutboundPolicyConfig{AllowedCIDRs: []string{tc.cidr}}, tc.valid)
		})
	}

	build := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "default"},
		Spec: automotivev1alpha1.ImageBuildSpec{
			ExternalID: "pipeline-42", CallbackSecretRef: "build-callback",
			AIB: &automotivev1alpha1.AIBSpec{Distro: "autosd", Target: "qemu", Mode: "bootc", Manifest: "name: example"},
		},
	}
	if err := k8s.Create(ctx, build); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	build.Status.Phase = automotivev1alpha1.ImageBuildPhaseCompleted
	build.Status.TerminalResult = &automotivev1alpha1.BuildTerminalResult{Phase: "Completed", Message: "done", CompletedAt: now}
	if err := k8s.Status().Update(ctx, build); err != nil {
		t.Fatal(err)
	}
	build.Status.Phase = automotivev1alpha1.ImageBuildPhaseExpired
	if err := k8s.Status().Update(ctx, build); err != nil {
		t.Fatal(err)
	}
	changedBuild := build.DeepCopy()
	changedBuild.Status.TerminalResult.Message = "changed"
	if err := k8s.Status().Update(ctx, changedBuild); !k8serrors.IsInvalid(err) {
		t.Fatalf("terminal mutation: %v", err)
	}
	changedBuild = build.DeepCopy()
	changedBuild.Status.TerminalResult = nil
	if err := k8s.Status().Update(ctx, changedBuild); !k8serrors.IsInvalid(err) {
		t.Fatalf("terminal removal: %v", err)
	}

	delivery := &automotivev1alpha1.WebhookDelivery{ObjectMeta: metav1.ObjectMeta{Name: "terminal", Namespace: "default"}, Spec: automotivev1alpha1.WebhookDeliverySpec{
		Subject: automotivev1alpha1.DeliverySubject{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageBuild", Name: build.Name, UID: build.UID}, CallbackSecretRef: "build-callback",
	}}
	if err := k8s.Create(ctx, delivery); err != nil {
		t.Fatal(err)
	}
	delivery.Status.State = automotivev1alpha1.DeliveryPending
	delivery.Status.Snapshot = &automotivev1alpha1.WebhookEventSnapshot{ID: "event-id", Type: "build.terminal", Time: now, Body: []byte(`{"type":"build.terminal"}`)}
	if err := k8s.Status().Update(ctx, delivery); err != nil {
		t.Fatal(err)
	}
	changedDelivery := delivery.DeepCopy()
	changedDelivery.Status.Snapshot.Body = []byte(`{}`)
	if err := k8s.Status().Update(ctx, changedDelivery); !k8serrors.IsInvalid(err) {
		t.Fatalf("snapshot mutation: %v", err)
	}
	changedDelivery = delivery.DeepCopy()
	changedDelivery.Status.Snapshot = nil
	if err := k8s.Status().Update(ctx, changedDelivery); !k8serrors.IsInvalid(err) {
		t.Fatalf("snapshot removal: %v", err)
	}
}
