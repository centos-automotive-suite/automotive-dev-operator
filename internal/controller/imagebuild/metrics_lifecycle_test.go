package imagebuild

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func metricsBuild(name, uid, phase string) *api.ImageBuild {
	build := newImageBuild("package", "lifecycle", "simg", "arm64", timePtr(100), nil)
	build.ObjectMeta = metav1.ObjectMeta{Namespace: "test", Name: name, UID: types.UID(uid)}
	build.Status.Phase = phase
	if api.IsTerminalBuildPhase(phase) {
		build.Status.CompletionTime = timePtr(200)
	}
	return build
}

func testRetainedGauge() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_retained"}, []string{"mode", "distro", "target", "format", "arch", "status"})
}

func retainedSeriesCount(t *testing.T, retained *prometheus.GaugeVec) int {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(retained)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, family := range families {
		count += len(family.Metric)
	}
	return count
}

func TestBuildMetricsHandlerLifecycle(t *testing.T) {
	resetLastBuildSuccessTimestamp(t)
	active := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_active"})
	retained := testRetainedGauge()
	var completions []types.UID
	handler := newBuildMetricsHandler(active, retained, func(build *api.ImageBuild) {
		completions = append(completions, build.UID)
	})
	existing := metricsBuild("existing", "existing", phaseCompleted)
	building := metricsBuild("build", "first", phaseBuilding)
	handler.OnAdd(existing, true)
	handler.OnAdd(building, true)
	if len(completions) != 0 || gaugeValue(active) != 1 || gaugeValue(retained.WithLabelValues(buildMetricLabels(existing, buildStatusSuccess)...)) != 1 {
		t.Fatal("initial replay must restore gauges without counting completions")
	}
	completed := building.DeepCopy()
	completed.Status.Phase = phaseCompleted
	completed.Status.CompletionTime = timePtr(300)
	handler.OnUpdate(building, completed)
	handler.OnUpdate(completed, completed)
	handler.OnAdd(completed, false)
	expired := completed.DeepCopy()
	expired.Status.PreviousPhase = phaseCompleted
	expired.Status.Phase = api.ImageBuildPhaseExpired
	handler.OnUpdate(completed, expired)
	if len(completions) != 1 || gaugeValue(active) != 0 || gaugeValue(retained.WithLabelValues(buildMetricLabels(existing, buildStatusSuccess)...)) != 2 {
		t.Fatal("completion, resync, and expiry must count a UID once")
	}

	// Replacement can arrive as an update before deletion of the old UID.
	recreated := metricsBuild("build", "second", phaseBuilding)
	handler.OnUpdate(expired, recreated)
	handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "test/build", Obj: expired})
	if gaugeValue(active) != 1 || gaugeValue(retained.WithLabelValues(buildMetricLabels(existing, buildStatusSuccess)...)) != 1 {
		t.Fatal("old UID deletion corrupted the replacement's gauges")
	}
	failed := recreated.DeepCopy()
	failed.Status.Phase = phaseFailed
	handler.OnUpdate(recreated, failed)
	handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "test/build", Obj: failed})
	handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "test/build"})
	if len(completions) != 2 || completions[1] != "second" || retainedSeriesCount(t, retained) != 1 {
		t.Fatal("recreated build must count independently and deletion must remove retained state")
	}
	cancelled := metricsBuild("cancelled", "cancelled", phaseCancelled)
	handler.OnAdd(cancelled, false)
	handler.OnUpdate(cancelled, cancelled)
	if len(completions) != 3 || gaugeValue(active) != 0 {
		t.Fatal("terminal additions and cancellations must count once")
	}
	if got := gaugeValue(BuildLastSuccessTimestamp); got != 300 {
		t.Fatalf("failures and deletions changed freshness: %v", got)
	}
	handler.OnDelete(existing)
	handler.OnDelete(cancelled)
	if retainedSeriesCount(t, retained) != 0 {
		t.Fatal("unused retained label combinations remain exported")
	}
}

func TestBuildMetricsHandlerFlashSeries(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			build := metricsBuild("build", "build", phaseBuilding)
			build.Spec.AIB.Target = fmt.Sprintf("flash-series-%t", enabled)
			if enabled {
				build.Spec.Flash = &api.FlashSpec{ClientConfigSecretRef: "client"}
			}
			handler := newBuildMetricsHandler(prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_active"}), testRetainedGauge(), func(*api.ImageBuild) {})
			handler.OnAdd(build, true)
			for _, status := range []string{buildStatusSuccess, buildStatusFailure} {
				if exists := FlashTotal.DeleteLabelValues(build.Spec.GetTarget(), status); exists != enabled {
					t.Fatalf("flash series exists=%t, want %t", exists, enabled)
				}
			}
		})
	}
}

type metricsInformerCache struct {
	ctrlcache.Cache
	informer cache.SharedIndexInformer
}

func (c metricsInformerCache) GetInformer(context.Context, client.Object, ...ctrlcache.InformerGetOption) (ctrlcache.Informer, error) {
	return c.informer, nil
}

func (c metricsInformerCache) WaitForCacheSync(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced)
}

func TestBuildMetricsCancelledDuringStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	informer := cache.NewSharedIndexInformer(nil, &api.ImageBuild{}, 0, cache.Indexers{})
	if err := (&ImageBuildReconciler{}).runBuildMetrics(ctx, metricsInformerCache{informer: informer}); err != nil {
		t.Fatalf("normal startup cancellation was reported as a failure: %v", err)
	}
	if gaugeValue(BuildMetricsReady) != 0 {
		t.Fatal("cancelled startup reported ready metrics")
	}
}

func waitForMetrics(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !condition() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for metrics")
		case <-ticker.C:
		}
	}
}

func startMetricsTracker(t *testing.T, reconciler *ImageBuildReconciler, informerCache metricsInformerCache) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.runBuildMetrics(ctx, informerCache) }()
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("metrics tracker stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("metrics tracker did not stop")
		}
	})
	t.Cleanup(stop)
	waitForMetrics(t, func() bool { return gaugeValue(BuildMetricsReady) == 1 })
	return stop
}

func TestBuildMetricsRestartAndLeaderHandoff(t *testing.T) {
	resetLastBuildSuccessTimestamp(t)
	existing := metricsBuild("existing", "existing", phaseCompleted)
	building := metricsBuild("build", "first", phaseBuilding)
	watcher := watch.NewRaceFreeFake()
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
			return &api.ImageBuildList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []api.ImageBuild{*existing, *building}}, nil
		},
		WatchFuncWithContext: func(_ context.Context, options metav1.ListOptions) (watch.Interface, error) {
			if options.SendInitialEvents != nil && *options.SendInitialEvents {
				watcher.Add(existing.DeepCopy())
				watcher.Add(building.DeepCopy())
				watcher.Action(watch.Bookmark, &api.ImageBuild{ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "1", Annotations: map[string]string{metav1.InitialEventsAnnotationKey: "true"},
				}})
			}
			return watcher, nil
		},
	}, &api.ImageBuild{}, 0, cache.Indexers{})
	cacheCtx, cancelCache := context.WithCancel(context.Background())
	t.Cleanup(cancelCache)
	go informer.Run(cacheCtx.Done())
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reconciler := &ImageBuildReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build(), Log: logr.Discard()}
	informerCache := metricsInformerCache{informer: informer}
	labels := buildMetricLabels(existing, buildStatusSuccess)
	before := counterValue(BuildTotal, labels...)
	stop := startMetricsTracker(t, reconciler, informerCache)
	if got := counterValue(BuildTotal, labels...); got != before {
		t.Fatalf("startup counted retained completions: %v", got-before)
	}
	if gaugeValue(ActiveBuilds) != 1 || gaugeValue(RetainedBuilds.WithLabelValues(labels...)) != 1 {
		t.Fatal("metrics became ready before initial replay restored gauges")
	}

	// This event is sufficient even if the controller crashes after persisting status.
	completed := building.DeepCopy()
	completed.ResourceVersion = "2"
	completed.Status.Phase = phaseCompleted
	completed.Status.CompletionTime = timePtr(300)
	watcher.Modify(completed)
	waitForMetrics(t, func() bool { return counterValue(BuildTotal, labels...) == before+1 })
	stop()
	if gaugeValue(BuildMetricsReady) != 0 {
		t.Fatal("stopped leader still reports ready metrics")
	}

	stopNext := startMetricsTracker(t, reconciler, informerCache)
	if got := counterValue(BuildTotal, labels...); got != before+1 {
		t.Fatalf("new leader replay counted old completions again: %v", got-before)
	}
	if gaugeValue(ActiveBuilds) != 0 || gaugeValue(RetainedBuilds.WithLabelValues(labels...)) != 2 || gaugeValue(BuildLastSuccessTimestamp) != 300 {
		t.Fatal("leader handoff did not recover retained state and freshness")
	}
	watcher.Modify(completed.DeepCopy())
	another := metricsBuild("another", "another", phaseCancelled)
	another.ResourceVersion = "3"
	watcher.Add(another)
	failureLabels := buildMetricLabels(another, buildStatusFailure)
	waitForMetrics(t, func() bool { return gaugeValue(RetainedBuilds.WithLabelValues(failureLabels...)) == 1 })
	if counterValue(BuildTotal, labels...) != before+1 {
		t.Fatal("replay update double-counted completion")
	}
	stopNext()
}

func TestCompletionMetricsUsesFlashOutcome(t *testing.T) {
	for _, state := range []string{"Succeeded", "Failed", "Cancelled", "NotStarted", "Running"} {
		t.Run(state, func(t *testing.T) {
			build := metricsBuild("flash", "flash", phaseFailed)
			build.Spec.AIB.Target = "flash-outcome-" + state
			build.Status.TerminalResult = &api.BuildTerminalResult{Phase: phaseFailed, Flash: &api.FlashOutcomeStatus{Enabled: true, State: state}}
			success := counterValue(FlashTotal, build.Spec.GetTarget(), buildStatusSuccess)
			failure := counterValue(FlashTotal, build.Spec.GetTarget(), buildStatusFailure)
			(&ImageBuildReconciler{}).recordCompletionMetrics(context.Background(), build)
			wantSuccess, wantFailure := float64(0), float64(0)
			switch state {
			case "Succeeded":
				wantSuccess = 1
			case "Failed", "Cancelled":
				wantFailure = 1
			}
			if counterValue(FlashTotal, build.Spec.GetTarget(), buildStatusSuccess)-success != wantSuccess || counterValue(FlashTotal, build.Spec.GetTarget(), buildStatusFailure)-failure != wantFailure {
				t.Fatal("flash metric used build outcome or counted an unstarted operation")
			}
		})
	}
}

func TestCompletionMetricsWithTektonResults(t *testing.T) {
	for _, tc := range []struct {
		name                string
		available, separate bool
	}{
		{name: "pipeline", available: true},
		{name: "missing pipeline"},
		{name: "separate flash", available: true, separate: true},
		{name: "missing separate flash", separate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := metricsBuild("build", "build", phaseCompleted)
			build.Spec.AIB.Target = "tekton-metrics-" + tc.name
			build.Status.PipelineRunName = "pipeline"
			if tc.separate {
				build.Status.FlashTaskRunName = "flash"
			}
			build.Status.Flash = &api.FlashOutcomeStatus{Enabled: true, State: "Succeeded"}
			pipeline := pipelineRunWithTiming(`{"setup_s":2,"build_s":90,"post_build_s":8}`)
			pipeline.Name, pipeline.Namespace = "pipeline", build.Namespace
			pipeline.Status.ChildReferences = []tektonv1.ChildStatusReference{{Name: "flash", PipelineTaskName: "flash-image"}}
			flash := &tektonv1.TaskRun{
				ObjectMeta: metav1.ObjectMeta{Name: "flash", Namespace: build.Namespace, CreationTimestamp: *timePtr(150)},
				Status:     tektonv1.TaskRunStatus{TaskRunStatusFields: tektonv1.TaskRunStatusFields{CompletionTime: timePtr(190)}},
			}
			scheme := runtime.NewScheme()
			if err := tektonv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tc.available {
				builder = builder.WithObjects(pipeline, flash)
			}
			reconciler := &ImageBuildReconciler{Client: builder.Build(), APIReader: fake.NewClientBuilder().WithScheme(scheme).Build()}
			labels := buildMetricLabels(build, buildStatusSuccess)
			phaseLabels := []string{build.Spec.GetMode(), build.Spec.GetDistro(), build.Spec.GetTarget(), "setup"}
			flashLabels := []string{build.Spec.GetTarget(), buildStatusSuccess}
			beforeBuild := counterValue(BuildTotal, labels...)
			beforeFlash := counterValue(FlashTotal, flashLabels...)
			beforeDuration := histogramCount(BuildDuration, labels...)
			beforePhase := histogramCount(BuildPhaseDuration, phaseLabels...)
			beforeFlashDuration := histogramCount(FlashDuration, flashLabels...)
			reconciler.recordCompletionMetrics(context.Background(), build)
			if counterValue(BuildTotal, labels...) != beforeBuild+1 || counterValue(FlashTotal, flashLabels...) != beforeFlash+1 || histogramCount(BuildDuration, labels...) != beforeDuration+1 {
				t.Fatal("missing execution objects must not suppress completion counters or CR duration")
			}
			want := uint64(0)
			if tc.available {
				want = 1
			}
			if histogramCount(BuildPhaseDuration, phaseLabels...) != beforePhase+want || histogramCount(FlashDuration, flashLabels...) != beforeFlashDuration+want {
				t.Fatal("execution timing observations do not match available Tekton results")
			}
		})
	}
}
