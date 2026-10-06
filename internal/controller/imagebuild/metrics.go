package imagebuild

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/terminal"
	"github.com/prometheus/client_golang/prometheus"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	metricsNamespace = "ado"
	metricsSubsystem = "build"

	buildStatusSuccess = "success"
	buildStatusFailure = "failure"
)

var (
	lastBuildSuccessTimestamp atomic.Int64

	// BuildDuration tracks the total build duration in seconds.
	BuildDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "duration_seconds",
			Help:      "End-to-end ImageBuild duration in seconds through terminal completion, including pushing and flashing",
			Buckets:   []float64{30, 60, 120, 180, 240, 300, 420, 600, 900, 1200},
		},
		[]string{"mode", "distro", "target", "format", "arch", "status"},
	)

	// BuildPhaseDuration tracks duration of individual build phases in seconds.
	BuildPhaseDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "phase_duration_seconds",
			Help:      "Duration of individual build phases in seconds",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 180, 240, 300, 600},
		},
		[]string{"mode", "distro", "target", "phase"},
	)

	// BuildTotal counts completions observed after the leader's initial replay.
	BuildTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "total",
			Help:      "Terminal ImageBuild completions observed by this operator process by status, including failures before pipeline creation",
		},
		[]string{"mode", "distro", "target", "format", "arch", "status"},
	)

	RetainedBuilds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "retained",
			Help:      "Number of retained terminal ImageBuild resources by status",
		},
		[]string{"mode", "distro", "target", "format", "arch", "status"},
	)

	BuildMetricsReady = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "metrics_ready",
		Help:      "Whether the leader has replayed existing builds and is tracking metrics",
	})

	// ActiveBuilds tracks the number of ImageBuilds in the Building phase.
	ActiveBuilds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "active",
			Help:      "Number of ImageBuilds in the Building phase",
		},
	)

	// BuildLastSuccessTimestamp is zero until a successful completion is known.
	BuildLastSuccessTimestamp = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_success_timestamp_seconds",
			Help:      "Unix timestamp (seconds) of the most recent successful build",
		},
		func() float64 { return float64(lastBuildSuccessTimestamp.Load()) },
	)

	// FlashTotal counts pipeline-triggered flash operations by status.
	FlashTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "flash",
			Name:      "total",
			Help:      "Settled flash operations observed by this operator process by status",
		},
		[]string{"target", "status"},
	)

	// FlashDuration tracks pipeline flash duration in seconds.
	FlashDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: "flash",
			Name:      "duration_seconds",
			Help:      "Pipeline flash operation duration in seconds",
			Buckets:   []float64{10, 30, 60, 120, 180, 300, 600, 900},
		},
		[]string{"target", "status"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		BuildDuration,
		BuildPhaseDuration,
		BuildTotal,
		ActiveBuilds,
		RetainedBuilds,
		BuildMetricsReady,
		BuildLastSuccessTimestamp,
		FlashTotal,
		FlashDuration,
	)
}

func recordBuildSuccessTimestamp(timestamp time.Time) {
	// Initial replay and live events can report completions out of order.
	unix := timestamp.Unix()
	for previous := lastBuildSuccessTimestamp.Load(); unix > previous; previous = lastBuildSuccessTimestamp.Load() {
		if lastBuildSuccessTimestamp.CompareAndSwap(previous, unix) {
			return
		}
	}
}

func newActiveBuildsHandler(gauge prometheus.Gauge) cache.ResourceEventHandler {
	// Informer notifications are ordered. Track names so replays and updates
	// replacing a deleted build with a new UID cannot double-count a build.
	active := make(map[types.NamespacedName]struct{})
	observe := func(obj any) {
		build, ok := obj.(*automotivev1alpha1.ImageBuild)
		if !ok {
			return
		}
		key := types.NamespacedName{Namespace: build.Namespace, Name: build.Name}
		if build.Status.Phase == phaseBuilding {
			active[key] = struct{}{}
		} else {
			delete(active, key)
		}
		gauge.Set(float64(len(active)))
	}
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    observe,
		UpdateFunc: func(_, obj any) { observe(obj) },
		DeleteFunc: func(obj any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				return
			}
			namespace, name, err := cache.SplitMetaNamespaceKey(key)
			if err != nil {
				return
			}
			delete(active, types.NamespacedName{Namespace: namespace, Name: name})
			gauge.Set(float64(len(active)))
		},
	}
}

func buildMetricStatus(b *automotivev1alpha1.ImageBuild) string {
	phase := b.Status.Phase
	if b.Status.TerminalResult != nil {
		phase = b.Status.TerminalResult.Phase
	}
	if phase == automotivev1alpha1.ImageBuildPhaseExpired {
		if b.Status.PreviousPhase != "" {
			phase = b.Status.PreviousPhase
		} else {
			return buildStatusSuccess
		}
	}
	if phase == automotivev1alpha1.ImageBuildPhaseCompleted {
		return buildStatusSuccess
	}
	return buildStatusFailure
}

func buildMetricLabels(b *automotivev1alpha1.ImageBuild, status string) []string {
	return []string{b.Spec.GetMode(), b.Spec.GetDistro(), b.Spec.GetTarget(), b.Spec.GetExportFormat(), b.Spec.Architecture, status}
}

func buildCompletionTime(b *automotivev1alpha1.ImageBuild) *metav1.Time {
	if b.Status.TerminalResult != nil {
		return &b.Status.TerminalResult.CompletedAt
	}
	return b.Status.CompletionTime
}

func newBuildMetricsHandler(active prometheus.Gauge, retained *prometheus.GaugeVec, completed func(*automotivev1alpha1.ImageBuild)) cache.ResourceEventHandler {
	type observedBuild struct {
		uid       types.UID
		completed bool
		labels    []string
	}
	active.Set(0)
	retained.Reset()
	observed := make(map[types.NamespacedName]observedBuild)
	retainedCounts := make(map[[6]string]int)
	adjustRetained := func(labels []string, delta int) {
		key := [6]string(labels)
		count := retainedCounts[key] + delta
		if count == 0 {
			delete(retainedCounts, key)
			retained.DeleteLabelValues(labels...)
			return
		}
		retainedCounts[key] = count
		retained.WithLabelValues(labels...).Set(float64(count))
	}
	activeHandler := newActiveBuildsHandler(active)
	observe := func(obj any, initial bool) {
		b, ok := obj.(*automotivev1alpha1.ImageBuild)
		if !ok {
			return
		}
		key := types.NamespacedName{Namespace: b.Namespace, Name: b.Name}
		previous, exists := observed[key]
		alreadyCompleted := exists && previous.uid == b.UID && previous.completed
		terminal := automotivev1alpha1.IsTerminalBuildPhase(b.Status.Phase)
		var labels []string
		if terminal {
			labels = buildMetricLabels(b, buildMetricStatus(b))
		}
		if !slices.Equal(previous.labels, labels) {
			if previous.labels != nil {
				adjustRetained(previous.labels, -1)
			}
			if labels != nil {
				adjustRetained(labels, 1)
			}
		}
		// Create zero-valued series before completion, including the opposite outcome.
		for _, status := range []string{buildStatusSuccess, buildStatusFailure} {
			BuildTotal.WithLabelValues(buildMetricLabels(b, status)...)
			if b.Spec.IsFlashEnabled() {
				FlashTotal.WithLabelValues(b.Spec.GetTarget(), status)
			}
		}
		observed[key] = observedBuild{uid: b.UID, completed: alreadyCompleted || terminal, labels: labels}
		if timestamp := buildCompletionTime(b); terminal && buildMetricStatus(b) == buildStatusSuccess && timestamp != nil {
			recordBuildSuccessTimestamp(timestamp.Time)
		}
		if terminal && !initial && !alreadyCompleted {
			completed(b)
		}
	}
	return cache.ResourceEventHandlerDetailedFuncs{
		AddFunc: func(obj any, initial bool) {
			activeHandler.OnAdd(obj, initial)
			observe(obj, initial)
		},
		UpdateFunc: func(oldObj, newObj any) {
			activeHandler.OnUpdate(oldObj, newObj)
			observe(newObj, false)
		},
		DeleteFunc: func(obj any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				return
			}
			namespace, name, err := cache.SplitMetaNamespaceKey(key)
			if err != nil {
				return
			}
			id := types.NamespacedName{Namespace: namespace, Name: name}
			previous, exists := observed[id]
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			if b, ok := obj.(*automotivev1alpha1.ImageBuild); ok && exists && b.UID != previous.uid {
				return
			}
			if previous.labels != nil {
				adjustRetained(previous.labels, -1)
			}
			delete(observed, id)
			activeHandler.OnDelete(cache.DeletedFinalStateUnknown{Key: key})
		},
	}
}

func (r *ImageBuildReconciler) recordCompletionMetrics(ctx context.Context, b *automotivev1alpha1.ImageBuild) {
	// Counters and wall-clock duration remain available if Tekton objects are gone.
	var pipelineRun *tektonv1.PipelineRun
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if b.Status.PipelineRunName != "" {
		pr := &tektonv1.PipelineRun{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.PipelineRunName}, pr); err == nil {
			pipelineRun = pr
		}
	}
	recordBuildMetrics(b, pipelineRun, buildMetricStatus(b))
	flash := b.Status.Flash
	if b.Status.TerminalResult != nil {
		flash = b.Status.TerminalResult.Flash
	}
	if flash == nil || !flash.Enabled {
		return
	}
	var status string
	switch flash.State {
	case terminal.FlashState(automotivev1alpha1.ImageBuildPhaseCompleted):
		status = buildStatusSuccess
	case terminal.FlashState(automotivev1alpha1.ImageBuildPhaseFailed), terminal.FlashState(automotivev1alpha1.ImageBuildPhaseCancelled):
		status = buildStatusFailure
	default:
		return
	}
	FlashTotal.WithLabelValues(b.Spec.GetTarget(), status).Inc()
	if b.Status.FlashTaskRunName != "" {
		tr := &tektonv1.TaskRun{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: b.Status.FlashTaskRunName}, tr); err == nil {
			recordFlashDuration(b, tr, status)
		}
	} else if pipelineRun != nil {
		r.recordPipelineFlashDuration(ctx, b, pipelineRun, status)
	}
}

func (r *ImageBuildReconciler) trackBuildMetrics(mgr ctrl.Manager) manager.RunnableFunc {
	return func(ctx context.Context) error {
		return r.runBuildMetrics(ctx, mgr.GetCache())
	}
}

func (r *ImageBuildReconciler) runBuildMetrics(ctx context.Context, informerCache ctrlcache.Cache) error {
	BuildMetricsReady.Set(0)
	if !informerCache.WaitForCacheSync(ctx) {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("cache sync failed")
	}
	informer, err := informerCache.GetInformer(ctx, &automotivev1alpha1.ImageBuild{})
	if err != nil {
		return fmt.Errorf("failed to get ImageBuild informer: %w", err)
	}
	handler, err := informer.AddEventHandler(newBuildMetricsHandler(ActiveBuilds, RetainedBuilds, func(b *automotivev1alpha1.ImageBuild) {
		r.recordCompletionMetrics(ctx, b)
	}))
	if err != nil {
		return fmt.Errorf("failed to register build metrics handler: %w", err)
	}
	defer func() {
		BuildMetricsReady.Set(0)
		if err := informer.RemoveEventHandler(handler); err != nil {
			r.Log.Error(err, "Failed to remove build metrics handler")
		}
	}()
	// Cache sync alone does not guarantee this listener has consumed its replay.
	if !cache.WaitForCacheSync(ctx.Done(), handler.HasSynced) {
		return nil
	}
	BuildMetricsReady.Set(1)
	<-ctx.Done()
	return nil
}
