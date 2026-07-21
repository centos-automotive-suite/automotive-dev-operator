package scheduledimagebuild

import (
	"context"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/catalogimage"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	archX86   = "x86_64"
	archARM   = "aarch64"
	distroASD = "autosd"
	targetQ   = "qemu"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(automotivev1alpha1.AddToScheme(s))
	return s
}

func newReconciler(objs []runtime.Object, now time.Time) *Reconciler {
	scheme := newScheme()
	clock := clocktesting.NewFakeClock(now)

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, obj := range objs {
		builder = builder.WithRuntimeObjects(obj)
	}
	builder = builder.WithStatusSubresource(
		&automotivev1alpha1.ScheduledImageBuild{},
		&automotivev1alpha1.ImageBuild{},
	)
	client := builder.Build()

	return &Reconciler{
		Client:   client,
		Scheme:   scheme,
		Log:      zap.New(zap.UseDevMode(true)),
		Recorder: record.NewFakeRecorder(100),
		Clock:    clock,
	}
}

func baseSIB(name string) *automotivev1alpha1.ScheduledImageBuild {
	return &automotivev1alpha1.ScheduledImageBuild{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
			Kind:       "ScheduledImageBuild",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			UID:               types.UID("test-uid-" + name),
			CreationTimestamp: metav1.NewTime(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
			Generation:        1,
		},
		Spec: automotivev1alpha1.ScheduledImageBuildSpec{
			Schedule:          "0 2 * * *", // daily at 2am
			ConcurrencyPolicy: automotivev1alpha1.ForbidConcurrent,
			ImageBuildTemplate: automotivev1alpha1.ImageBuildTemplateSpec{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Architecture: archX86,
					AIB: &automotivev1alpha1.AIBSpec{
						Distro: distroASD,
						Target: targetQ,
					},
				},
			},
		},
	}
}

func childBuild(sibName, buildName string, phase string, creationTime time.Time) *automotivev1alpha1.ImageBuild {
	build := &automotivev1alpha1.ImageBuild{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
			Kind:       "ImageBuild",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              buildName,
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(creationTime),
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: sibName,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
					Kind:       "ScheduledImageBuild",
					Name:       sibName,
					UID:        types.UID("test-uid-" + sibName),
					Controller: ptr.To(true),
				},
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase: phase,
		},
	}
	if automotivev1alpha1.IsTerminalBuildPhase(phase) {
		build.Status.CompletionTime = &metav1.Time{Time: creationTime.Add(30 * time.Minute)}
	}
	return build
}

func TestReconcile_CreatesImageBuild(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC) // 30 min past 2am
	sib := baseSIB("test-schedule")

	r := newReconciler([]runtime.Object{sib}, now)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-schedule", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if result.RequeueAfter <= 0 {
		t.Error("Expected RequeueAfter > 0")
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list ImageBuilds: %v", err)
	}

	if len(buildList.Items) != 1 {
		t.Fatalf("Expected 1 ImageBuild, got %d", len(buildList.Items))
	}

	build := buildList.Items[0]
	if build.Spec.Architecture != archX86 {
		t.Errorf("Expected architecture %s, got %s", archX86, build.Spec.Architecture)
	}
	if build.Spec.AIB == nil || build.Spec.AIB.Distro != distroASD {
		t.Errorf("Expected distro %s in child build", distroASD)
	}
	if build.Labels[automotivev1alpha1.LabelScheduledImageBuildName] != "test-schedule" {
		t.Errorf("Expected schedule label, got %v", build.Labels)
	}
	if len(build.OwnerReferences) == 0 {
		t.Fatal("Expected owner reference on child build")
	}
	ownerRef := build.OwnerReferences[0]
	if ownerRef.APIVersion != automotivev1alpha1.GroupVersion.String() {
		t.Errorf("Expected owner ref APIVersion %s, got %s", automotivev1alpha1.GroupVersion.String(), ownerRef.APIVersion)
	}
	if ownerRef.Kind != "ScheduledImageBuild" {
		t.Errorf("Expected owner ref Kind ScheduledImageBuild, got %s", ownerRef.Kind)
	}
}

func TestReconcile_Suspended(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-suspend")
	sib.Spec.Suspend = ptr.To(true)

	r := newReconciler([]runtime.Object{sib}, now)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-suspend", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Suspended schedule should not requeue")
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 0 {
		t.Error("Suspended schedule should not create builds")
	}
}

func TestReconcile_ForbidConcurrency(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-forbid")

	activeBuild := childBuild("test-forbid", "test-forbid-active", "Building", now.Add(-20*time.Minute))

	r := newReconciler([]runtime.Object{sib, activeBuild}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-forbid", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 1 {
		t.Errorf("Forbid policy should keep exactly 1 build, got %d", len(buildList.Items))
	}
}

func TestReconcile_ActiveStatusHasGVK(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-gvk")
	sib.Spec.ConcurrencyPolicy = automotivev1alpha1.ForbidConcurrent

	activeBuild := childBuild("test-gvk", "test-gvk-active", "Building", now.Add(-20*time.Minute))

	r := newReconciler([]runtime.Object{sib, activeBuild}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-gvk", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var updated automotivev1alpha1.ScheduledImageBuild
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-gvk", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("Failed to get SIB: %v", err)
	}

	if len(updated.Status.Active) == 0 {
		t.Fatal("Expected at least one active reference")
	}
	ref := updated.Status.Active[0]
	wantAPIVersion := automotivev1alpha1.GroupVersion.String()
	if ref.APIVersion != wantAPIVersion {
		t.Errorf("Expected APIVersion %s, got %q", wantAPIVersion, ref.APIVersion)
	}
	if ref.Kind != "ImageBuild" {
		t.Errorf("Expected Kind ImageBuild, got %q", ref.Kind)
	}
}

func TestReconcile_AllowConcurrency(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-allow")
	sib.Spec.ConcurrencyPolicy = automotivev1alpha1.AllowConcurrent

	activeBuild := childBuild("test-allow", "test-allow-active", "Building", now.Add(-20*time.Minute))

	r := newReconciler([]runtime.Object{sib, activeBuild}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-allow", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 2 {
		t.Errorf("Allow policy should have 2 builds (1 active + 1 new), got %d", len(buildList.Items))
	}
}

func TestReconcile_ReplaceConcurrency(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-replace")
	sib.Spec.ConcurrencyPolicy = automotivev1alpha1.ReplaceConcurrent

	activeBuild := childBuild("test-replace", "test-replace-active", "Building", now.Add(-20*time.Minute))

	r := newReconciler([]runtime.Object{sib, activeBuild}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-replace", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}

	// Old build should be deleted, new one created
	if len(buildList.Items) != 1 {
		t.Errorf("Replace policy should have exactly 1 build (new), got %d", len(buildList.Items))
	}
	if buildList.Items[0].Name == "test-replace-active" {
		t.Error("Old active build should have been replaced")
	}
}

func TestReconcile_HistoryCleanup(t *testing.T) {
	now := time.Date(2025, 1, 2, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-history")
	sib.Spec.SuccessfulBuildsHistoryLimit = ptr.To(int32(1))
	sib.Status.LastScheduleTime = &metav1.Time{Time: now.Add(-time.Hour)}

	old1 := childBuild("test-history", "old-1", automotivev1alpha1.ImageBuildPhaseCompleted, now.Add(-3*time.Hour))
	old2 := childBuild("test-history", "old-2", automotivev1alpha1.ImageBuildPhaseCompleted, now.Add(-2*time.Hour))
	recent := childBuild("test-history", "recent", automotivev1alpha1.ImageBuildPhaseCompleted, now.Add(-1*time.Hour))

	r := newReconciler([]runtime.Object{sib, old1, old2, recent}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-history", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}

	completedCount := 0
	for _, b := range buildList.Items {
		if b.Status.Phase == automotivev1alpha1.ImageBuildPhaseCompleted {
			completedCount++
		}
	}

	// limit=1 means keep 1 completed, but reconcile also creates a new one (non-completed)
	if completedCount > 1 {
		t.Errorf("Expected at most 1 completed build (history limit), got %d", completedCount)
	}
}

func TestReconcile_NoRunBeforeSchedule(t *testing.T) {
	// Schedule is "0 2 * * *" (2am), current time is 1am — no run should happen
	now := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)
	sib := baseSIB("test-not-yet")

	r := newReconciler([]runtime.Object{sib}, now)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-not-yet", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if result.RequeueAfter <= 0 {
		t.Error("Expected RequeueAfter for next schedule")
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 0 {
		t.Errorf("Should not create build before schedule time, got %d", len(buildList.Items))
	}
}

func TestReconcile_StartingDeadline(t *testing.T) {
	// Schedule is "0 2 * * *" (2am). Now is 6am. Deadline is 1 hour.
	// The 2am run is 4 hours ago, beyond 1 hour deadline — should skip.
	now := time.Date(2025, 1, 1, 6, 0, 0, 0, time.UTC)
	sib := baseSIB("test-deadline")
	sib.Spec.StartingDeadlineSeconds = ptr.To(int64(3600)) // 1 hour

	r := newReconciler([]runtime.Object{sib}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-deadline", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 0 {
		t.Errorf("Should not create build beyond starting deadline, got %d", len(buildList.Items))
	}
}

func TestReconcile_InvalidSchedule(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 0, 0, 0, time.UTC)
	sib := baseSIB("test-invalid")
	sib.Spec.Schedule = "not-a-cron"

	r := newReconciler([]runtime.Object{sib}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-invalid", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Expected no error for invalid schedule (handled via condition), got: %v", err)
	}
}

func TestReconcile_InvalidScheduleNoStatusChurn(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 0, 0, 0, time.UTC)
	sib := baseSIB("test-invalid-churn")
	sib.Spec.Schedule = "not-a-cron"

	r := newReconciler([]runtime.Object{sib}, now)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-invalid-churn", Namespace: "default"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("First reconcile failed: %v", err)
	}

	var after1 automotivev1alpha1.ScheduledImageBuild
	if err := r.Get(context.Background(), req.NamespacedName, &after1); err != nil {
		t.Fatalf("Failed to get SIB: %v", err)
	}
	rv1 := after1.ResourceVersion

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Second reconcile failed: %v", err)
	}

	var after2 automotivev1alpha1.ScheduledImageBuild
	if err := r.Get(context.Background(), req.NamespacedName, &after2); err != nil {
		t.Fatalf("Failed to get SIB: %v", err)
	}

	if after2.ResourceVersion != rv1 {
		t.Error("Second reconcile wrote status when nothing changed — causes reconcile churn")
	}
}

func TestReconcile_AutoPublish(t *testing.T) {
	now := time.Date(2025, 1, 2, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-publish")
	sib.Spec.PublishToCatalog = &automotivev1alpha1.PublishToCatalogSpec{
		Enabled: true,
		Tags:    []string{"nightly"},
	}
	sib.Status.LastScheduleTime = &metav1.Time{Time: now.Add(-time.Hour)}

	completedBuild := childBuild("test-publish", "completed-build", automotivev1alpha1.ImageBuildPhaseCompleted, now.Add(-1*time.Hour))

	published := false
	publisher := &mockPublisher{
		publishFn: func(_ context.Context, _ *automotivev1alpha1.ImageBuild, _ string, tags []string, _ *automotivev1alpha1.AuthSecretReference) (*catalogimage.PublishResult, error) {
			published = true
			if len(tags) != 1 || tags[0] != "nightly" {
				t.Errorf("Expected tags [nightly], got %v", tags)
			}
			return &catalogimage.PublishResult{}, nil
		},
	}

	r := newReconciler([]runtime.Object{sib, completedBuild}, now)
	r.Publisher = publisher

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-publish", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if !published {
		t.Error("Expected publisher to be called for completed build")
	}

	var build automotivev1alpha1.ImageBuild
	if err := r.Get(context.Background(), types.NamespacedName{Name: "completed-build", Namespace: "default"}, &build); err != nil {
		t.Fatalf("Failed to get build: %v", err)
	}
	if _, ok := build.Annotations[AnnotationCatalogPublished]; !ok {
		t.Error("Expected catalog-published annotation to be set")
	}
}

func TestReconcile_SkipsAlreadyPublished(t *testing.T) {
	now := time.Date(2025, 1, 2, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-skip-publish")
	sib.Spec.PublishToCatalog = &automotivev1alpha1.PublishToCatalogSpec{Enabled: true}
	sib.Status.LastScheduleTime = &metav1.Time{Time: now.Add(-time.Hour)}

	completedBuild := childBuild("test-skip-publish", "already-published", automotivev1alpha1.ImageBuildPhaseCompleted, now.Add(-1*time.Hour))
	completedBuild.Annotations = map[string]string{AnnotationCatalogPublished: AnnotationCatalogPublishedValue}

	published := false
	publisher := &mockPublisher{
		publishFn: func(_ context.Context, _ *automotivev1alpha1.ImageBuild, _ string, _ []string, _ *automotivev1alpha1.AuthSecretReference) (*catalogimage.PublishResult, error) {
			published = true
			return &catalogimage.PublishResult{}, nil
		},
	}

	r := newReconciler([]runtime.Object{sib, completedBuild}, now)
	r.Publisher = publisher

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-skip-publish", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if published {
		t.Error("Should not publish already-published build")
	}
}

func TestReconcile_TemplateLabelsAndAnnotations(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-meta")
	sib.Spec.ImageBuildTemplate.Metadata = automotivev1alpha1.ScheduledBuildMetadata{
		Labels:      map[string]string{"team": "platform", "env": "staging"},
		Annotations: map[string]string{"note": "nightly"},
	}

	r := newReconciler([]runtime.Object{sib}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-meta", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 1 {
		t.Fatalf("Expected 1 build, got %d", len(buildList.Items))
	}

	build := buildList.Items[0]
	if build.Labels["team"] != "platform" {
		t.Errorf("Expected label team=platform, got %v", build.Labels)
	}
	if build.Labels["env"] != "staging" {
		t.Errorf("Expected label env=staging, got %v", build.Labels)
	}
	if build.Annotations["note"] != "nightly" {
		t.Errorf("Expected annotation note=nightly, got %v", build.Annotations)
	}
}

func TestSafeDerivedName(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		suffix  string
		wantLen bool // check len <= 63
	}{
		{"short name", "my-schedule", "-12345678", false},
		{"long name", "this-is-a-very-long-scheduled-image-build-name-that-exceeds-limits", "-12345678", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeDerivedName(tt.base, tt.suffix)
			if len(result) > maxK8sNameLength {
				t.Errorf("Name too long: %d chars: %s", len(result), result)
			}
			if tt.wantLen && len(result) > maxK8sNameLength {
				t.Errorf("Expected name <= %d chars, got %d", maxK8sNameLength, len(result))
			}
		})
	}
}

func TestClassifyBuilds(t *testing.T) {
	builds := []automotivev1alpha1.ImageBuild{
		{Status: automotivev1alpha1.ImageBuildStatus{Phase: "Building"}},
		{Status: automotivev1alpha1.ImageBuildStatus{Phase: automotivev1alpha1.ImageBuildPhaseCompleted}},
		{Status: automotivev1alpha1.ImageBuildStatus{Phase: "Pending"}},
		{Status: automotivev1alpha1.ImageBuildStatus{Phase: automotivev1alpha1.ImageBuildPhaseFailed}},
	}

	active, finished := classifyBuilds(builds)
	if len(active) != 2 {
		t.Errorf("Expected 2 active, got %d", len(active))
	}
	if len(finished) != 2 {
		t.Errorf("Expected 2 finished, got %d", len(finished))
	}
}

func TestReconcile_BuildFailedVisibility(t *testing.T) {
	now := time.Date(2025, 1, 2, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-fail-visible")
	sib.Status.LastScheduleTime = &metav1.Time{Time: now.Add(-time.Hour)}

	failedBuild := childBuild("test-fail-visible", "failed-build", automotivev1alpha1.ImageBuildPhaseFailed, now.Add(-1*time.Hour))
	failedBuild.Status.Message = "disk space exhausted"

	r := newReconciler([]runtime.Object{sib, failedBuild}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-fail-visible", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var updated automotivev1alpha1.ScheduledImageBuild
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-fail-visible", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("Failed to get SIB: %v", err)
	}

	if updated.Status.LastFailedTime == nil {
		t.Fatal("Expected lastFailedTime to be set")
	}

	var foundCondition bool
	for _, c := range updated.Status.Conditions {
		if c.Type == ConditionLastBuildSucceeded {
			foundCondition = true
			if c.Status != metav1.ConditionFalse {
				t.Errorf("Expected LastBuildSucceeded=False, got %s", c.Status)
			}
			if c.Reason != "BuildFailed" {
				t.Errorf("Expected reason BuildFailed, got %s", c.Reason)
			}
		}
	}
	if !foundCondition {
		t.Error("Expected LastBuildSucceeded condition to be set")
	}
}

func TestReconcile_BuildSucceededCondition(t *testing.T) {
	now := time.Date(2025, 1, 2, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-succeed-cond")
	sib.Status.LastScheduleTime = &metav1.Time{Time: now.Add(-time.Hour)}

	completedBuild := childBuild("test-succeed-cond", "good-build", automotivev1alpha1.ImageBuildPhaseCompleted, now.Add(-1*time.Hour))

	r := newReconciler([]runtime.Object{sib, completedBuild}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-succeed-cond", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var updated automotivev1alpha1.ScheduledImageBuild
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-succeed-cond", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("Failed to get SIB: %v", err)
	}

	var foundCondition bool
	for _, c := range updated.Status.Conditions {
		if c.Type == ConditionLastBuildSucceeded {
			foundCondition = true
			if c.Status != metav1.ConditionTrue {
				t.Errorf("Expected LastBuildSucceeded=True, got %s", c.Status)
			}
			if c.Reason != "BuildSucceeded" {
				t.Errorf("Expected reason BuildSucceeded, got %s", c.Reason)
			}
		}
	}
	if !foundCondition {
		t.Error("Expected LastBuildSucceeded condition to be set")
	}
}

func TestExpandMatrix_NoMatrix(t *testing.T) {
	sib := baseSIB("no-matrix")
	combos := expandMatrix(sib)
	if len(combos) != 1 {
		t.Fatalf("Expected 1 combo (passthrough), got %d", len(combos))
	}
	if combos[0].Architecture != "" || combos[0].Distro != "" || combos[0].Target != "" {
		t.Error("Empty combo should have all zero-value fields")
	}
}

func TestExpandMatrix_ArchOnly(t *testing.T) {
	sib := baseSIB("arch-matrix")
	sib.Spec.Matrix = &automotivev1alpha1.BuildMatrix{
		Architectures: []string{archX86, archARM},
	}
	combos := expandMatrix(sib)
	if len(combos) != 2 {
		t.Fatalf("Expected 2 combos, got %d", len(combos))
	}
	if combos[0].Architecture != archX86 {
		t.Errorf("Expected %s, got %s", archX86, combos[0].Architecture)
	}
	if combos[1].Architecture != archARM {
		t.Errorf("Expected %s, got %s", archARM, combos[1].Architecture)
	}
}

func TestExpandMatrix_CrossProduct(t *testing.T) {
	sib := baseSIB("cross-matrix")
	sib.Spec.Matrix = &automotivev1alpha1.BuildMatrix{
		Architectures: []string{archX86, archARM},
		Targets:       []string{targetQ, "aws"},
	}
	combos := expandMatrix(sib)
	if len(combos) != 4 {
		t.Fatalf("Expected 4 combos (2x2), got %d", len(combos))
	}

	expected := []matrixCombo{
		{Architecture: archX86, Target: targetQ},
		{Architecture: archX86, Target: "aws"},
		{Architecture: archARM, Target: targetQ},
		{Architecture: archARM, Target: "aws"},
	}
	for i, want := range expected {
		got := combos[i]
		if got.Architecture != want.Architecture || got.Target != want.Target {
			t.Errorf("combo[%d]: got {%s, %s}, want {%s, %s}", i, got.Architecture, got.Target, want.Architecture, want.Target)
		}
	}
}

func TestExpandMatrix_AllDimensions(t *testing.T) {
	sib := baseSIB("full-matrix")
	sib.Spec.Matrix = &automotivev1alpha1.BuildMatrix{
		Architectures: []string{archX86, archARM},
		Distros:       []string{distroASD, "cs9"},
		Targets:       []string{targetQ},
	}
	combos := expandMatrix(sib)
	if len(combos) != 4 {
		t.Fatalf("Expected 4 combos (2x2x1), got %d", len(combos))
	}
}

func TestMatrixComboSuffix(t *testing.T) {
	tests := []struct {
		name  string
		combo matrixCombo
		want  string
	}{
		{"empty", matrixCombo{}, ""},
		{"arch only", matrixCombo{Architecture: archX86}, "-x86-64"},
		{"arch+target", matrixCombo{Architecture: archARM, Target: targetQ}, "-aarch64-qemu"},
		{"all", matrixCombo{Architecture: archX86, Distro: distroASD, Target: targetQ}, "-x86-64-autosd-qemu"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.combo.suffix()
			if got != tt.want {
				t.Errorf("suffix() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppendOCITagSuffix(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		suffix string
		want   string
	}{
		{"with tag", "registry.example.com/repo:disk", "-qemu", "registry.example.com/repo:disk-qemu"},
		{"no tag", "registry.example.com/repo", "-qemu", "registry.example.com/repo:latest-qemu"},
		{"port and tag", "registry:5000/ns/repo:latest", "-ebbr", "registry:5000/ns/repo:latest-ebbr"},
		{"port no tag", "registry:5000/ns/repo", "-ebbr", "registry:5000/ns/repo:latest-ebbr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendOCITagSuffix(tt.ref, tt.suffix)
			if got != tt.want {
				t.Errorf("appendOCITagSuffix(%q, %q) = %q, want %q", tt.ref, tt.suffix, got, tt.want)
			}
		})
	}
}

func TestReconcile_MatrixCreatesMultipleBuilds(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-matrix")
	sib.Spec.Matrix = &automotivev1alpha1.BuildMatrix{
		Architectures: []string{archX86, archARM},
	}

	r := newReconciler([]runtime.Object{sib}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-matrix", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 2 {
		t.Fatalf("Expected 2 ImageBuilds from matrix, got %d", len(buildList.Items))
	}

	archSeen := map[string]bool{}
	for _, b := range buildList.Items {
		archSeen[b.Spec.Architecture] = true
		if b.Labels[automotivev1alpha1.LabelScheduledImageBuildName] != "test-matrix" {
			t.Errorf("Missing schedule label on build %s", b.Name)
		}
		if b.Labels[automotivev1alpha1.LabelArchitecture] == "" {
			t.Errorf("Missing architecture label on build %s", b.Name)
		}
	}
	if !archSeen[archX86] || !archSeen[archARM] {
		t.Errorf("Expected both architectures, got %v", archSeen)
	}
}

func TestReconcile_MatrixOverridesTemplateSpec(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-matrix-override")
	sib.Spec.ImageBuildTemplate.Spec.Export = &automotivev1alpha1.ExportSpec{
		UseServiceAccountAuth: true,
		Disk: &automotivev1alpha1.DiskExport{
			OCI: "registry:5000/ns/image:disk",
		},
	}
	sib.Spec.Matrix = &automotivev1alpha1.BuildMatrix{
		Architectures: []string{archARM},
		Targets:       []string{"aws"},
	}

	r := newReconciler([]runtime.Object{sib}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-matrix-override", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 1 {
		t.Fatalf("Expected 1 build, got %d", len(buildList.Items))
	}

	build := buildList.Items[0]
	if build.Spec.Architecture != archARM {
		t.Errorf("Expected architecture aarch64 (overridden), got %s", build.Spec.Architecture)
	}
	if build.Spec.AIB == nil || build.Spec.AIB.Target != "aws" {
		t.Errorf("Expected target aws (overridden), got %v", build.Spec.AIB)
	}
	if build.Spec.AIB.Distro != distroASD {
		t.Errorf("Expected distro autosd (from template), got %s", build.Spec.AIB.Distro)
	}
	expectedOCI := "registry:5000/ns/image:disk-aarch64-aws"
	if build.Spec.Export == nil || build.Spec.Export.Disk == nil || build.Spec.Export.Disk.OCI != expectedOCI {
		got := ""
		if build.Spec.Export != nil && build.Spec.Export.Disk != nil {
			got = build.Spec.Export.Disk.OCI
		}
		t.Errorf("Expected OCI path %s, got %s", expectedOCI, got)
	}
}

func TestReconcile_NoMatrixBackwardCompatible(t *testing.T) {
	now := time.Date(2025, 1, 1, 2, 30, 0, 0, time.UTC)
	sib := baseSIB("test-no-matrix")

	r := newReconciler([]runtime.Object{sib}, now)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-no-matrix", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var buildList automotivev1alpha1.ImageBuildList
	if err := r.List(context.Background(), &buildList); err != nil {
		t.Fatalf("Failed to list: %v", err)
	}
	if len(buildList.Items) != 1 {
		t.Fatalf("Expected exactly 1 build (no matrix), got %d", len(buildList.Items))
	}
	if buildList.Items[0].Spec.Architecture != archX86 {
		t.Errorf("Expected template architecture x86_64, got %s", buildList.Items[0].Spec.Architecture)
	}
}

// mockPublisher implements CatalogPublisher for testing
type mockPublisher struct {
	publishFn func(ctx context.Context, ib *automotivev1alpha1.ImageBuild, name string, tags []string, authSecretRef *automotivev1alpha1.AuthSecretReference) (*catalogimage.PublishResult, error)
}

func (m *mockPublisher) PublishFromImageBuild(ctx context.Context, ib *automotivev1alpha1.ImageBuild, name string, tags []string, authSecretRef *automotivev1alpha1.AuthSecretReference) (*catalogimage.PublishResult, error) {
	if m.publishFn != nil {
		return m.publishFn(ctx, ib, name, tags, authSecretRef)
	}
	return &catalogimage.PublishResult{}, nil
}

var _ CatalogPublisher = &mockPublisher{}
