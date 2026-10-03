package buildercache

import (
	"context"
	"strings"
	"testing"
	"time"

	automotivev1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	imagev1 "github.com/openshift/api/image/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

const testNamespace = "test"
const cacheName = "autosd-arm64-12345678-0123456789abcdef"
const testRepo = "registry.example/test/aib-build"

func digest(c string) string     { return "sha256:" + strings.Repeat(c, 64) }
func pin(c string) string        { return "pin-" + strings.Repeat(c, 64) }
func builderRef(c string) string { return testRepo + "@" + digest(c) }

func retainedStream() *imagev1.ImageStream {
	old := metav1.NewTime(testNow.Add(-40 * 24 * time.Hour))
	s := &imagev1.ImageStream{ObjectMeta: metav1.ObjectMeta{Name: streamName, Namespace: testNamespace},
		Status: imagev1.ImageStreamStatus{DockerImageRepository: testRepo}}
	for name, d := range map[string]string{cacheName: digest("a"), pin("a"): digest("a"), pin("b"): digest("b"), "manual": digest("b")} {
		s.Spec.Tags = append(s.Spec.Tags, imagev1.TagReference{Name: name, Annotations: map[string]string{lastUsedAnnotation: old.Format(time.RFC3339Nano)}})
		s.Status.Tags = append(s.Status.Tags, imagev1.NamedTagEventList{Tag: name, Items: []imagev1.TagEvent{{Image: d, Created: old}}})
	}
	return s
}

func TestRetention(t *testing.T) {
	for _, tc := range []struct {
		name, ttl string
		objects   []client.Object
		change    func(*imagev1.ImageStream)
		want      []string
	}{
		{name: "unreferenced", want: []string{cacheName, pin("a"), pin("b")}},
		{name: "catalog survives deleted build", objects: []client.Object{catalog(builderRef("a"))}, want: []string{cacheName, pin("b")}},
		{name: "build retains exact helper", objects: []client.Object{build("old", builderRef("a"), testNow.Add(-35*24*time.Hour))}, want: nil}, // last use is persisted first
		{name: "active build only protects orphan pins", objects: []client.Object{&automotivev1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "active", Namespace: testNamespace}}}, want: []string{cacheName}},
		{name: "active reseal only protects orphan pins", objects: []client.Object{&automotivev1.ImageReseal{ObjectMeta: metav1.ObjectMeta{Name: "active", Namespace: testNamespace}}}, want: []string{cacheName}},
		{name: "unknown old catalog blocks deletion", objects: []client.Object{catalog("")}},
		{name: "external helper is not ours", objects: []client.Object{catalog("quay.io/other/helper@" + digest("a"))}, want: []string{cacheName, pin("a"), pin("b")}},
		{name: "legacy tag reference retains tag", objects: []client.Object{catalog(testRepo + ":" + cacheName)}, want: []string{pin("b")}},
		{name: "missing historical digest permits cleanup", objects: []client.Object{catalog(builderRef("c"))}, want: []string{cacheName, pin("a"), pin("b")}},
		{name: "cache expiry disabled", ttl: "0", want: []string{pin("a"), pin("b")}},
		{name: "longer configured ttl", ttl: "1440h", want: []string{pin("a"), pin("b")}},
		{name: "new pin grace", change: func(s *imagev1.ImageStream) {
			for i := range s.Spec.Tags {
				if s.Spec.Tags[i].Name == pin("b") {
					s.Spec.Tags[i].Annotations[lastUsedAnnotation] = testNow.Format(time.RFC3339Nano)
				}
			}
		}, want: []string{cacheName, pin("a")}},
		{name: "unresolved old metadata blocks deletion", objects: []client.Object{&automotivev1.CatalogImage{ObjectMeta: metav1.ObjectMeta{Name: "catalog", Namespace: testNamespace}, Status: automotivev1.CatalogImageStatus{RegistryMetadata: &automotivev1.RegistryMetadata{}}}}},
		{name: "confirmed no helper permits deletion", objects: []client.Object{&automotivev1.CatalogImage{ObjectMeta: metav1.ObjectMeta{Name: "catalog", Namespace: testNamespace}, Status: automotivev1.CatalogImageStatus{RegistryMetadata: &automotivev1.RegistryMetadata{BuilderImageResolved: true}}}}, want: []string{cacheName, pin("a"), pin("b")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := retainedStream()
			if tc.change != nil {
				tc.change(s)
			}
			config := &automotivev1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: testNamespace}, Spec: automotivev1.OperatorConfigSpec{OSBuilds: &automotivev1.OSBuildsConfig{BuilderCacheTTL: tc.ttl}}}
			objects := append([]client.Object{s, config}, tc.objects...)
			r, deletes := testReconciler(t, objects...)
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(config)}); err != nil {
				t.Fatal(err)
			}
			if len(*deletes) != len(tc.want) {
				t.Fatalf("deleted %v, want %v", *deletes, tc.want)
			}
			for _, name := range tc.want {
				if !(*deletes)[streamName+":"+name] {
					t.Errorf("did not delete %s", name)
				}
			}
		})
	}
}

func catalog(ref string) *automotivev1.CatalogImage {
	return &automotivev1.CatalogImage{ObjectMeta: metav1.ObjectMeta{Name: "catalog", Namespace: testNamespace}, Spec: automotivev1.CatalogImageSpec{BuilderImage: ref}}
}
func build(name, ref string, completed time.Time) *automotivev1.ImageBuild {
	stamp := metav1.NewTime(completed)
	return &automotivev1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace}, Status: automotivev1.ImageBuildStatus{Phase: automotivev1.ImageBuildPhaseCompleted, BuilderImageUsed: ref, CompletionTime: &stamp}}
}
func testReconciler(t *testing.T, objects ...client.Object) (*Reconciler, *map[string]bool) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := automotivev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := imagev1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	deleted := map[string]bool{}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&automotivev1.OperatorConfig{}).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
			if _, ok := obj.(*imagev1.ImageStreamTag); !ok {
				t.Fatalf("unexpected deletion of %T", obj)
			}
			deleted[obj.GetName()] = true
			return nil
		},
	}).Build()
	return &Reconciler{Client: c, APIReader: c, Now: func() time.Time { return testNow }}, &deleted
}

func TestCleanupConditions(t *testing.T) {
	s := retainedStream()
	s.Status.Tags[0].Items = append(s.Status.Tags[0].Items, imagev1.TagEvent{Image: digest("c")})
	entry := catalog("")
	active := &automotivev1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "active", Namespace: testNamespace}}
	source := build("source", builderRef("c"), testNow.Add(-90*24*time.Hour))
	config := &automotivev1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: testNamespace, Generation: 3},
		Status: automotivev1.OperatorConfigStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", LastTransitionTime: metav1.NewTime(testNow)}}}}
	r, _ := testReconciler(t, s, entry, active, source, config)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(config)}
	check := func(want metav1.ConditionStatus, messages ...string) {
		t.Helper()
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
		if err := r.Get(ctx, req.NamespacedName, config); err != nil {
			t.Fatal(err)
		}
		condition := apimeta.FindStatusCondition(config.Status.Conditions, cleanupCondition)
		if condition == nil || condition.Status != want || condition.ObservedGeneration != 3 {
			t.Fatalf("unexpected cleanup condition: %+v", condition)
		}
		for _, message := range messages {
			if !strings.Contains(condition.Message, message) {
				t.Fatalf("condition %q omits %q", condition.Message, message)
			}
		}
		if !apimeta.IsStatusConditionTrue(config.Status.Conditions, "Ready") {
			t.Fatal("lost another controller's condition")
		}
	}
	check(metav1.ConditionTrue, "catalog helper metadata", "awaiting registry visibility")
	version := config.ResourceVersion
	check(metav1.ConditionTrue)
	if config.ResourceVersion != version {
		t.Fatal("unchanged condition caused another status write")
	}
	entry.Spec.BuilderImage = builderRef("a")
	if err := r.Get(ctx, client.ObjectKeyFromObject(s), s); err != nil {
		t.Fatal(err)
	}
	s.Status.Tags = append(s.Status.Tags, imagev1.NamedTagEventList{Tag: pin("c"), Items: []imagev1.TagEvent{{Image: digest("c")}}})
	for _, obj := range []client.Object{entry, active, s} {
		if err := r.Update(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	check(metav1.ConditionFalse)
	version = config.ResourceVersion
	active.Status.Phase = automotivev1.ImageBuildPhaseCompleted
	if err := r.Update(ctx, active); err != nil {
		t.Fatal(err)
	}
	check(metav1.ConditionFalse)
	if config.ResourceVersion != version {
		t.Fatal("build completion changed the cleanup condition")
	}
}

func TestCleanupConditionConflict(t *testing.T) {
	ctx := context.Background()
	config := &automotivev1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: testNamespace}}
	r, _ := testReconciler(t, config)
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), config); err != nil {
		t.Fatal(err)
	}
	stale := config.DeepCopy()
	apimeta.SetStatusCondition(&config.Status.Conditions, metav1.Condition{
		Type: "Ready", Status: metav1.ConditionTrue, Reason: "ReconcileSucceeded", Message: "Ready",
	})
	if err := r.Status().Update(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err := r.reportCleanup(ctx, stale, nil); !apierrors.IsConflict(err) {
		t.Fatalf("stale status patch must conflict, got %v", err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), config); err != nil {
		t.Fatal(err)
	}
	if err := r.reportCleanup(ctx, config, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(config), config); err != nil {
		t.Fatal(err)
	}
	if !apimeta.IsStatusConditionTrue(config.Status.Conditions, "Ready") ||
		!apimeta.IsStatusConditionFalse(config.Status.Conditions, cleanupCondition) {
		t.Fatalf("retry lost a controller's condition: %+v", config.Status.Conditions)
	}
}

func TestMissingHelperEvents(t *testing.T) {
	for _, obj := range []client.Object{
		catalog(builderRef("c")),
		build("source", builderRef("c"), testNow.Add(-time.Hour)),
		&automotivev1.ImageReseal{ObjectMeta: metav1.ObjectMeta{Name: "reseal", Namespace: testNamespace},
			Spec: automotivev1.ImageResealSpec{BuilderImage: builderRef("c")}, Status: automotivev1.ImageResealStatus{Phase: "Completed"}},
	} {
		t.Run(obj.GetName(), func(t *testing.T) {
			config := &automotivev1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: testNamespace}}
			r, deleted := testReconciler(t, retainedStream(), config, obj)
			recorder := events.NewFakeRecorder(10)
			r.Recorder = recorder
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(config)}); err != nil {
				t.Fatal(err)
			}
			select {
			case event := <-recorder.Events:
				if !strings.Contains(event, "Warning BuilderImageUnavailable") || !strings.Contains(event, builderRef("c")) {
					t.Fatalf("unexpected event: %s", event)
				}
			default:
				t.Fatal("missing helper was not reported")
			}
			if !(*deleted)[streamName+":"+cacheName] {
				t.Fatal("unrecoverable helper blocked cache expiry")
			}
		})
	}
}

func TestBackfillPinsAndCatalogReference(t *testing.T) {
	s := retainedStream()
	// Simulate an older helper present only in cache history, below the newest revisions.
	s.Status.Tags[0].Items = append(s.Status.Tags[0].Items, imagev1.TagEvent{Image: digest("c"), Created: metav1.NewTime(testNow.Add(-90 * 24 * time.Hour))})
	entry := catalog("")
	entry.Status.SourceImageBuild = "source"
	source := build("source", builderRef("c"), testNow.Add(-time.Hour))
	config := &automotivev1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: testNamespace}}
	r, deletes := testReconciler(t, s, entry, source, config)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(config)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(*deletes) != 0 {
		t.Fatalf("deleted before pin observed: %v", *deletes)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(entry), entry); err != nil {
		t.Fatal(err)
	}
	if entry.Spec.BuilderImage != builderRef("c") {
		t.Fatalf("catalog lost helper: %+v", entry.Spec)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(s), s); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tag := range s.Spec.Tags {
		if tag.Name == pin("c") {
			found = tag.From != nil && tag.From.Kind == "ImageStreamImage" && tag.From.Name == streamName+"@"+digest("c")
		}
	}
	if !found {
		t.Fatal("no immutable backfill pin")
	}
	// A spec-only pin is not yet sufficient: wait for the registry-visible history.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(*deletes) != 0 {
		t.Fatal("removed cache before pin appeared in status")
	}
}

func TestLastUseTracksHistoryAndDoesNotRefreshOnReconcile(t *testing.T) {
	s := retainedStream()
	for i := range s.Status.Tags {
		if s.Status.Tags[i].Tag == cacheName {
			s.Status.Tags[i].Items = append(s.Status.Tags[i].Items, imagev1.TagEvent{Image: digest("c")})
		}
	}
	completed := testNow.Add(-2 * time.Hour)
	changed, _ := maintainTags(s, map[string]bool{}, map[string]time.Time{digest("c"): completed}, testNow)
	if !changed {
		t.Fatal("did not record completed use of historical digest")
	}
	for _, tag := range s.Spec.Tags {
		if tag.Name == cacheName && tag.Annotations[lastUsedAnnotation] != completed.Format(time.RFC3339Nano) {
			t.Fatalf("wrong last use: %v", tag.Annotations)
		}
	}
	if changed, _ := maintainTags(s, map[string]bool{}, map[string]time.Time{digest("c"): completed}, testNow.Add(time.Hour)); changed {
		t.Fatal("reconciliation refreshed last use without another build")
	}
}

func TestLegacyTagsReceiveMigrationGrace(t *testing.T) {
	s := retainedStream()
	s.Spec.Tags = nil
	changed, _ := maintainTags(s, map[string]bool{}, nil, testNow)
	if !changed {
		t.Fatal("missing migration annotations")
	}
	for _, tag := range s.Spec.Tags {
		if tag.Annotations[lastUsedAnnotation] != testNow.Format(time.RFC3339Nano) {
			t.Fatalf("no grace for %s", tag.Name)
		}
	}
}
