package containerbuild

import (
	"context"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	shipwrightv1beta1 "github.com/shipwright-io/build/pkg/apis/build/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	utilruntime.Must(shipwrightv1beta1.SchemeBuilder.AddToScheme(scheme))
	return scheme
}

func newExpiryReconciler(objs ...automotivev1alpha1.ContainerBuild) *ContainerBuildReconciler {
	scheme := newTestScheme()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for i := range objs {
		builder = builder.WithStatusSubresource(&objs[i])
		builder = builder.WithObjects(&objs[i])
	}
	return &ContainerBuildReconciler{
		Client:   builder.Build(),
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}
}

func newTestContainerBuildForExpiry(name, phase, ttl string, completedAgo time.Duration) automotivev1alpha1.ContainerBuild {
	now := time.Now()
	cb := automotivev1alpha1.ContainerBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         testNamespace,
			CreationTimestamp: metav1.NewTime(now.Add(-completedAgo - time.Hour)),
		},
		Spec: automotivev1alpha1.ContainerBuildSpec{
			Output: "quay.io/test/image:latest",
			TTL:    ttl,
		},
		Status: automotivev1alpha1.ContainerBuildStatus{
			Phase: phase,
		},
	}
	if phase == phaseCompleted || phase == phaseFailed {
		ct := metav1.NewTime(now.Add(-completedAgo))
		cb.Status.CompletionTime = &ct
	}
	return cb
}

func TestCheckExpiry_ExpiredBuild_TransitionsToExpiredPhase(t *testing.T) {
	cb := newTestContainerBuildForExpiry("expired-build", phaseCompleted, "1h", 2*time.Hour)
	r := newExpiryReconciler(cb)

	_, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expired {
		t.Fatal("expected build to be expired")
	}

	got := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "expired-build", Namespace: testNamespace}, got); err != nil {
		t.Fatalf("ContainerBuild should still exist after expiry: %v", err)
	}
	if got.Status.Phase != phaseExpired {
		t.Errorf("expected phase %q, got %q", phaseExpired, got.Status.Phase)
	}
	if got.Status.PreviousPhase != phaseCompleted {
		t.Errorf("expected previousPhase %q, got %q", phaseCompleted, got.Status.PreviousPhase)
	}
}

func TestCheckExpiry_NotYetExpired(t *testing.T) {
	cb := newTestContainerBuildForExpiry("fresh-build", phaseCompleted, "24h", 1*time.Hour)
	r := newExpiryReconciler(cb)

	result, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("build should not be expired yet")
	}
	if result.RequeueAfter < 22*time.Hour || result.RequeueAfter > 24*time.Hour {
		t.Errorf("expected RequeueAfter ~23h, got %v", result.RequeueAfter)
	}
}

func TestCheckExpiry_NoExpireAnnotation(t *testing.T) {
	cb := newTestContainerBuildForExpiry("pinned-build", phaseCompleted, "1h", 2*time.Hour)
	cb.Annotations = map[string]string{
		automotivev1alpha1.NoExpireAnnotation: "true",
	}
	r := newExpiryReconciler(cb)

	_, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("annotated build should not be expired")
	}
}

func TestCheckExpiry_TTLZeroDisablesExpiry(t *testing.T) {
	cb := newTestContainerBuildForExpiry("forever-build", phaseCompleted, "0", 999*time.Hour)
	r := newExpiryReconciler(cb)

	result, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("TTL=0 build should never expire")
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}
}

func TestCheckExpiry_InProgressNeverExpires(t *testing.T) {
	for _, phase := range []string{phasePending, phaseUploading, phaseBuilding} {
		t.Run(phase, func(t *testing.T) {
			cb := newTestContainerBuildForExpiry("build-"+phase, phase, "30m", 0)
			r := newExpiryReconciler(cb)

			_, expired, err := r.checkExpiry(context.Background(), &cb)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if expired {
				t.Fatalf("in-progress build (phase %s) should never expire", phase)
			}
		})
	}
}

func TestCheckExpiry_FailedBuildExpires(t *testing.T) {
	cb := newTestContainerBuildForExpiry("failed-old", phaseFailed, "1h", 2*time.Hour)
	r := newExpiryReconciler(cb)

	_, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expired {
		t.Fatal("failed build past TTL should expire")
	}

	got := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "failed-old", Namespace: testNamespace}, got); err != nil {
		t.Fatalf("ContainerBuild should still exist: %v", err)
	}
	if got.Status.Phase != phaseExpired {
		t.Errorf("expected phase %q, got %q", phaseExpired, got.Status.Phase)
	}
	if got.Status.PreviousPhase != phaseFailed {
		t.Errorf("expected previousPhase %q, got %q", phaseFailed, got.Status.PreviousPhase)
	}
}

func TestCheckExpiry_SetsExpiresAtInStatus(t *testing.T) {
	cb := newTestContainerBuildForExpiry("with-status", phaseCompleted, "24h", 1*time.Hour)
	r := newExpiryReconciler(cb)

	_, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("build should not be expired")
	}

	got := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "with-status", Namespace: testNamespace}, got); err != nil {
		t.Fatalf("failed to get build: %v", err)
	}
	if got.Status.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set in status")
	}
	expectedExpiry := cb.Status.CompletionTime.Add(24 * time.Hour)
	diff := got.Status.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("ExpiresAt = %v, want ~%v (diff %v)", got.Status.ExpiresAt.Time, expectedExpiry, diff)
	}
}

func TestCheckExpiry_AlreadyExpiredSkipsCheck(t *testing.T) {
	cb := newTestContainerBuildForExpiry("already-expired", phaseExpired, "1h", 2*time.Hour)
	r := newExpiryReconciler(cb)

	result, expired, err := r.checkExpiry(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("already-expired build should not re-trigger expiry")
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue for already-expired build, got %v", result.RequeueAfter)
	}
}

func TestHandleExpiredState_DeletesBuildRun(t *testing.T) {
	cb := newTestContainerBuildForExpiry("my-build", phaseExpired, "1h", 2*time.Hour)
	cb.Status.BuildRunName = "my-build-br"

	br := &shipwrightv1beta1.BuildRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-build-br",
			Namespace: testNamespace,
		},
	}

	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cb, br).
		WithStatusSubresource(&cb).
		Build()

	r := &ContainerBuildReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.handleExpiredState(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}

	got := &shipwrightv1beta1.BuildRun{}
	err = r.Get(context.Background(), types.NamespacedName{Name: "my-build-br", Namespace: testNamespace}, got)
	if !errors.IsNotFound(err) {
		t.Errorf("expected BuildRun to be deleted, got err=%v", err)
	}
}

func TestHandleExpiredState_IdempotentWhenBuildRunAlreadyGone(t *testing.T) {
	cb := newTestContainerBuildForExpiry("clean-build", phaseExpired, "1h", 2*time.Hour)
	cb.Status.BuildRunName = "gone-buildrun"

	r := newExpiryReconciler(cb)

	result, err := r.handleExpiredState(context.Background(), &cb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue when BuildRun already gone, got %v", result.RequeueAfter)
	}
}

func TestHandleExpiredState_PreservesContainerBuildCR(t *testing.T) {
	cb := newTestContainerBuildForExpiry("preserved", phaseExpired, "1h", 2*time.Hour)
	cb.Status.BuildRunName = "preserved-br"

	r := newExpiryReconciler(cb)

	r.handleExpiredState(context.Background(), &cb) //nolint:errcheck

	got := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "preserved", Namespace: testNamespace}, got); err != nil {
		t.Fatalf("ContainerBuild CR should still exist after cleanup: %v", err)
	}
}

func TestResolveEffectiveTTL(t *testing.T) {
	cases := []struct {
		name           string
		specTTL        string
		configBuildTTL string
		hasConfig      bool
		expectedTTL    time.Duration
	}{
		{"spec overrides OperatorConfig", "48h", "72h", true, 48 * time.Hour},
		{"OperatorConfig default", "", "72h", true, 72 * time.Hour},
		{"hardcoded fallback (no config)", "", "", false, 24 * time.Hour},
		{"spec zero disables expiry", "0", "", false, 0},
		{"OperatorConfig zero disables expiry", "", "0", true, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := newTestContainerBuildForExpiry("test-build", phaseCompleted, tc.specTTL, 1*time.Hour)
			scheme := newTestScheme()
			builder := fake.NewClientBuilder().WithScheme(scheme)

			if tc.hasConfig {
				builder = builder.WithObjects(&automotivev1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
					Spec: automotivev1alpha1.OperatorConfigSpec{
						ContainerBuilds: &automotivev1alpha1.ContainerBuildsConfig{
							DefaultBuildTTL: tc.configBuildTTL,
						},
					},
				})
			}

			r := &ContainerBuildReconciler{
				Client: builder.Build(),
				Scheme: scheme,
				Log:    logr.Discard(),
			}

			ttl, err := r.resolveEffectiveTTL(context.Background(), &cb)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ttl != tc.expectedTTL {
				t.Errorf("expected %v, got %v", tc.expectedTTL, ttl)
			}
		})
	}
}

func TestReconcile_ExpiredPhaseCallsCleanup(t *testing.T) {
	cb := newTestContainerBuildForExpiry("reconcile-expired", phaseExpired, "1h", 2*time.Hour)
	cb.Status.BuildRunName = "reconcile-expired-br"

	br := &shipwrightv1beta1.BuildRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reconcile-expired-br",
			Namespace: testNamespace,
		},
	}

	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cb, br).
		WithStatusSubresource(&cb).
		Build()

	r := &ContainerBuildReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "reconcile-expired", Namespace: testNamespace},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := &shipwrightv1beta1.BuildRun{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "reconcile-expired-br", Namespace: testNamespace}, got); !errors.IsNotFound(err) {
		t.Errorf("expected BuildRun to be cleaned up via Reconcile, got err=%v", err)
	}

	gotCB := &automotivev1alpha1.ContainerBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "reconcile-expired", Namespace: testNamespace}, gotCB); err != nil {
		t.Fatalf("ContainerBuild should still exist: %v", err)
	}
}
