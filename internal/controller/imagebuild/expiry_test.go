package imagebuild

import (
	"context"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newExpiryReconciler(objs ...automotivev1alpha1.ImageBuild) *ImageBuildReconciler {
	scheme := newTestSchemeWithTekton()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for i := range objs {
		builder = builder.WithStatusSubresource(&objs[i])
		builder = builder.WithObjects(&objs[i])
	}
	return &ImageBuildReconciler{
		Client:   builder.Build(),
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}
}

func newTestImageBuild(name string, phase string, ttl string, completedAgo time.Duration) automotivev1alpha1.ImageBuild {
	now := time.Now()
	ib := automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "test-ns",
			CreationTimestamp: metav1.NewTime(now.Add(-completedAgo - time.Hour)),
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			TTL: ttl,
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase: phase,
		},
	}
	if phase == phaseCompleted || phase == phaseFailed {
		ct := metav1.NewTime(now.Add(-completedAgo))
		ib.Status.CompletionTime = &ct
	}
	return ib
}

func TestCheckExpiry_ExpiredBuild_TransitionsToExpiredPhase(t *testing.T) {
	ib := newTestImageBuild("expired-build", phaseCompleted, "1h", 2*time.Hour)
	r := newExpiryReconciler(ib)

	_, expired, err := r.checkExpiry(context.Background(), &ib)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expired {
		t.Fatal("expected build to be expired")
	}

	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "expired-build", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("ImageBuild should still exist after expiry: %v", err)
	}
	if got.Status.Phase != automotivev1alpha1.ImageBuildPhaseExpired {
		t.Errorf("expected phase %q, got %q", automotivev1alpha1.ImageBuildPhaseExpired, got.Status.Phase)
	}

	foundProgressing := false
	foundReady := false
	for _, c := range got.Status.Conditions {
		switch c.Type {
		case automotivev1alpha1.ImageBuildConditionProgressing:
			foundProgressing = true
			if c.Status != metav1.ConditionFalse {
				t.Errorf("Progressing condition should be False for expired build, got %s", c.Status)
			}
		case automotivev1alpha1.ImageBuildConditionReady:
			foundReady = true
			if c.Status != metav1.ConditionFalse {
				t.Errorf("Ready condition should be False for expired build, got %s", c.Status)
			}
		}
	}
	if !foundProgressing {
		t.Error("expected Progressing condition to be present")
	}
	if !foundReady {
		t.Error("expected Ready condition to be present")
	}
}

func TestCheckExpiry_NotYetExpired(t *testing.T) {
	ib := newTestImageBuild("fresh-build", phaseCompleted, "24h", 1*time.Hour)
	r := newExpiryReconciler(ib)

	result, expired, err := r.checkExpiry(context.Background(), &ib)
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
	ib := newTestImageBuild("pinned-build", phaseCompleted, "1h", 2*time.Hour)
	ib.Annotations = map[string]string{
		automotivev1alpha1.NoExpireAnnotation: "true",
	}
	r := newExpiryReconciler(ib)

	_, expired, err := r.checkExpiry(context.Background(), &ib)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("pinned build should not be expired")
	}

	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "pinned-build", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("pinned build should still exist: %v", err)
	}
}

func TestCheckExpiry_WorkspaceBuildNeverExpires(t *testing.T) {
	ib := newTestImageBuild("ws-build", phaseCompleted, "1h", 2*time.Hour)
	ib.Spec.Workspace = "my-workspace"
	r := newExpiryReconciler(ib)

	_, expired, err := r.checkExpiry(context.Background(), &ib)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("workspace build should never expire")
	}

	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "ws-build", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("workspace build should still exist: %v", err)
	}
	if got.Status.ExpiresAt != nil {
		t.Error("workspace build should have nil ExpiresAt")
	}
}

func TestCheckExpiry_TTLZeroDisablesExpiry(t *testing.T) {
	ib := newTestImageBuild("forever-build", phaseCompleted, "0", 999*time.Hour)
	r := newExpiryReconciler(ib)

	result, expired, err := r.checkExpiry(context.Background(), &ib)
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
	for _, phase := range []string{
		automotivev1alpha1.ImageBuildPhasePending,
		automotivev1alpha1.ImageBuildPhaseUploading,
		automotivev1alpha1.ImageBuildPhaseBuilding,
		automotivev1alpha1.ImageBuildPhasePushing,
		automotivev1alpha1.ImageBuildPhaseFlashing,
	} {
		t.Run(phase, func(t *testing.T) {
			ib := newTestImageBuild("build-"+phase, phase, "30m", 0)
			ib.CreationTimestamp = metav1.NewTime(time.Now().Add(-2 * time.Hour))
			r := newExpiryReconciler(ib)

			_, expired, err := r.checkExpiry(context.Background(), &ib)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if expired {
				t.Fatalf("in-progress build (phase %s) should never expire regardless of TTL", phase)
			}
		})
	}
}

func TestCheckExpiry_FailedBuildExpires(t *testing.T) {
	ib := newTestImageBuild("failed-old", phaseFailed, "1h", 2*time.Hour)
	r := newExpiryReconciler(ib)

	_, expired, err := r.checkExpiry(context.Background(), &ib)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expired {
		t.Fatal("failed build past TTL should expire")
	}

	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "failed-old", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("ImageBuild should still exist: %v", err)
	}
	if got.Status.Phase != automotivev1alpha1.ImageBuildPhaseExpired {
		t.Errorf("expected phase %q, got %q", automotivev1alpha1.ImageBuildPhaseExpired, got.Status.Phase)
	}
}

func TestCheckExpiry_SetsExpiresAtInStatus(t *testing.T) {
	ib := newTestImageBuild("with-status", phaseCompleted, "24h", 1*time.Hour)
	r := newExpiryReconciler(ib)

	_, expired, err := r.checkExpiry(context.Background(), &ib)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expired {
		t.Fatal("build should not be expired")
	}

	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "with-status", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("failed to get build: %v", err)
	}
	if got.Status.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set in status")
	}
	expectedExpiry := ib.Status.CompletionTime.Add(24 * time.Hour)
	diff := got.Status.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("ExpiresAt = %v, want ~%v (diff %v)", got.Status.ExpiresAt.Time, expectedExpiry, diff)
	}
}

// newExpiredBuildWithResources creates an expired ImageBuild along with its
// owned child resources (PipelineRun, push TaskRun, PVC, manifest ConfigMap)
// for testing cleanup behavior.
func newExpiredBuildWithResources(t *testing.T) (*ImageBuildReconciler, *automotivev1alpha1.ImageBuild) {
	t.Helper()

	ib := newTestImageBuild("my-build", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
	ib.Status.PipelineRunName = "my-build-build-abc"
	ib.Status.PushTaskRunName = "my-build-push-def"
	ib.Status.PVCName = "my-build-pvc"
	ib.Spec.Export = &automotivev1alpha1.ExportSpec{
		Container:             tasks.DefaultInternalRegistryURL + "/test-ns/my-image:latest",
		UseServiceAccountAuth: true,
	}

	ownerRefs := testOwnerRef("my-build")

	pipelineRun := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-build-build-abc", Namespace: "test-ns",
			OwnerReferences: ownerRefs,
		},
	}

	pushTaskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-build-push-def", Namespace: "test-ns",
			OwnerReferences: ownerRefs,
		},
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-build-pvc", Namespace: "test-ns",
			OwnerReferences: ownerRefs,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("1Gi"),
				},
			},
		},
	}

	manifestCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: safeDerivedName("my-build", "-manifest"), Namespace: "test-ns",
			OwnerReferences: ownerRefs,
		},
	}

	scheme := newTestSchemeWithTekton()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&ib, pipelineRun, pushTaskRun, pvc, manifestCM).
		WithStatusSubresource(&ib).
		Build()

	r := &ImageBuildReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}

	return r, &ib
}

func testOwnerRef(buildName string) []metav1.OwnerReference {
	return []metav1.OwnerReference{{
		APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
		Kind:       "ImageBuild",
		Name:       buildName,
		Controller: new(true),
	}}
}

func TestHandleExpiredState_DeletesPipelineRun(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	result := r.handleExpiredState(ctx, ib)
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}

	pr := &tektonv1.PipelineRun{}
	err := r.Get(ctx, types.NamespacedName{Name: "my-build-build-abc", Namespace: "test-ns"}, pr)
	if !errors.IsNotFound(err) {
		t.Errorf("expected PipelineRun to be deleted, got err=%v", err)
	}
}

func TestHandleExpiredState_DeletesPushTaskRun(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	r.handleExpiredState(ctx, ib) //nolint:errcheck

	tr := &tektonv1.TaskRun{}
	err := r.Get(ctx, types.NamespacedName{Name: "my-build-push-def", Namespace: "test-ns"}, tr)
	if !errors.IsNotFound(err) {
		t.Errorf("expected push TaskRun to be deleted, got err=%v", err)
	}
}

func TestHandleExpiredState_DeletesPVC(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	r.handleExpiredState(ctx, ib) //nolint:errcheck

	pvc := &corev1.PersistentVolumeClaim{}
	err := r.Get(ctx, types.NamespacedName{Name: "my-build-pvc", Namespace: "test-ns"}, pvc)
	if !errors.IsNotFound(err) {
		t.Errorf("expected PVC to be deleted, got err=%v", err)
	}
}

func TestHandleExpiredState_DeletesManifestConfigMap(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	r.handleExpiredState(ctx, ib) //nolint:errcheck

	cm := &corev1.ConfigMap{}
	cmName := safeDerivedName("my-build", "-manifest")
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: "test-ns"}, cm)
	if !errors.IsNotFound(err) {
		t.Errorf("expected manifest ConfigMap to be deleted, got err=%v", err)
	}
}

func TestHandleExpiredState_DeletesImageStream(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
	})
	is.SetName("my-image")
	is.SetNamespace("test-ns")
	if err := r.Create(ctx, is); err != nil {
		t.Fatalf("failed to create ImageStream: %v", err)
	}

	r.handleExpiredState(ctx, ib) //nolint:errcheck

	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
	})
	err := r.Get(ctx, types.NamespacedName{Name: "my-image", Namespace: "test-ns"}, got)
	if !errors.IsNotFound(err) {
		t.Errorf("expected ImageStream to be deleted, got err=%v", err)
	}
}

func TestHandleExpiredState_IdempotentWhenResourcesAlreadyGone(t *testing.T) {
	// Build with status refs to resources that don't exist
	ib := newTestImageBuild("clean-build", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
	ib.Status.PipelineRunName = "gone-pipeline"
	ib.Status.PushTaskRunName = "gone-push"
	ib.Status.PVCName = "gone-pvc"

	r := newExpiryReconciler(ib)
	ctx := context.Background()

	result := r.handleExpiredState(ctx, &ib)
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue when resources already gone, got %v", result.RequeueAfter)
	}
}

func TestHandleExpiredState_PreservesImageBuildCR(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	r.handleExpiredState(ctx, ib) //nolint:errcheck

	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: "my-build", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("ImageBuild CR should still exist after cleanup: %v", err)
	}
	if got.Status.Phase != automotivev1alpha1.ImageBuildPhaseExpired {
		t.Errorf("phase should remain %q, got %q", automotivev1alpha1.ImageBuildPhaseExpired, got.Status.Phase)
	}
}

func TestHandleExpiredState_DeletesFlashTaskRun(t *testing.T) {
	r, ib := newExpiredBuildWithResources(t)
	ctx := context.Background()

	// Add a flash TaskRun
	ib.Status.FlashTaskRunName = "my-build-flash-ghi"
	flashTR := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-build-flash-ghi",
			Namespace: "test-ns",
		},
	}
	if err := r.Create(ctx, flashTR); err != nil {
		t.Fatalf("failed to create flash TaskRun: %v", err)
	}

	r.handleExpiredState(ctx, ib) //nolint:errcheck

	tr := &tektonv1.TaskRun{}
	err := r.Get(ctx, types.NamespacedName{Name: "my-build-flash-ghi", Namespace: "test-ns"}, tr)
	if !errors.IsNotFound(err) {
		t.Errorf("expected flash TaskRun to be deleted, got err=%v", err)
	}
}

func TestCheckExpiry_AlreadyExpiredSkipsCheck(t *testing.T) {
	ib := newTestImageBuild("already-expired", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
	r := newExpiryReconciler(ib)

	result, expired, err := r.checkExpiry(context.Background(), &ib)
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

func TestReconcile_ExpiredPhaseCallsCleanup(t *testing.T) {
	ib := newTestImageBuild("reconcile-expired", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
	ib.Status.PipelineRunName = "reconcile-expired-build-abc"
	ib.Status.PVCName = "reconcile-expired-pvc"

	pipelineRun := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reconcile-expired-build-abc",
			Namespace: "test-ns",
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reconcile-expired-pvc",
			Namespace: "test-ns",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("1Gi"),
				},
			},
		},
	}

	scheme := newTestSchemeWithTekton()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&ib, pipelineRun, pvc).
		WithStatusSubresource(&ib).
		Build()

	r := &ImageBuildReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "reconcile-expired", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = result

	// PipelineRun should be cleaned up
	pr := &tektonv1.PipelineRun{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "reconcile-expired-build-abc", Namespace: "test-ns"}, pr); !errors.IsNotFound(err) {
		t.Errorf("expected PipelineRun to be cleaned up via Reconcile, got err=%v", err)
	}

	// ImageBuild should still exist
	got := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "reconcile-expired", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("ImageBuild should still exist: %v", err)
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
			ib := newTestImageBuild("test-build", phaseCompleted, tc.specTTL, 1*time.Hour)
			scheme := newTestSchemeWithTekton()
			builder := fake.NewClientBuilder().WithScheme(scheme)

			if tc.hasConfig {
				builder = builder.WithObjects(&automotivev1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
					Spec: automotivev1alpha1.OperatorConfigSpec{
						OSBuilds: &automotivev1alpha1.OSBuildsConfig{
							DefaultBuildTTL: tc.configBuildTTL,
						},
					},
				})
			}

			r := &ImageBuildReconciler{
				Client: builder.Build(),
				Scheme: scheme,
				Log:    logr.Discard(),
			}

			ttl, err := r.resolveEffectiveTTL(context.Background(), &ib)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ttl != tc.expectedTTL {
				t.Errorf("expected %v, got %v", tc.expectedTTL, ttl)
			}
		})
	}
}

func TestHandleExpiredState_SkipsSharedBuildCachePVC(t *testing.T) {
	ib := newTestImageBuild("cache-build", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
	ib.Spec.BuildCachePVC = "shared-cache"
	ib.Status.PVCName = "shared-cache"

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-cache", Namespace: "test-ns"},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	scheme := newTestSchemeWithTekton()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&ib, pvc).
		WithStatusSubresource(&ib).
		Build()

	r := &ImageBuildReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}

	r.handleExpiredState(context.Background(), &ib) //nolint:errcheck

	got := &corev1.PersistentVolumeClaim{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "shared-cache", Namespace: "test-ns"}, got); err != nil {
		t.Fatalf("shared build-cache PVC should NOT be deleted: %v", err)
	}
}

func TestHandleExpiredState_DeletesMultipleImageStreams(t *testing.T) {
	ib := newTestImageBuild("multi-is-build", automotivev1alpha1.ImageBuildPhaseExpired, "1h", 2*time.Hour)
	ib.Spec.Export = &automotivev1alpha1.ExportSpec{
		Container:             tasks.DefaultInternalRegistryURL + "/test-ns/app-bootc:latest",
		Disk:                  &automotivev1alpha1.DiskExport{OCI: tasks.DefaultInternalRegistryURL + "/test-ns/app-disk:latest"},
		UseServiceAccountAuth: true,
	}

	scheme := newTestSchemeWithTekton()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&ib).
		WithStatusSubresource(&ib).
		Build()

	r := &ImageBuildReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Recorder: record.NewFakeRecorder(10),
	}

	ctx := context.Background()

	for _, name := range []string{"app-bootc", "app-disk"} {
		is := &unstructured.Unstructured{}
		is.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		is.SetName(name)
		is.SetNamespace("test-ns")
		if err := r.Create(ctx, is); err != nil {
			t.Fatalf("failed to create ImageStream %s: %v", name, err)
		}
	}

	r.handleExpiredState(ctx, &ib) //nolint:errcheck

	for _, name := range []string{"app-bootc", "app-disk"} {
		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: "test-ns"}, got)
		if !errors.IsNotFound(err) {
			t.Errorf("expected ImageStream %s to be deleted, got err=%v", name, err)
		}
	}
}
