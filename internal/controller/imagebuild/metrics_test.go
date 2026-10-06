package imagebuild

import (
	"fmt"
	"sync"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

func gaugeValue(g prometheus.Metric) float64 {
	m := &io_prometheus_client.Metric{}
	if err := g.Write(m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

func resetLastBuildSuccessTimestamp(t *testing.T) {
	t.Helper()
	previous := lastBuildSuccessTimestamp.Swap(0)
	t.Cleanup(func() { lastBuildSuccessTimestamp.Store(previous) })
}

func TestBuildMetricsHandlerLastSuccessTimestamp(t *testing.T) {
	resetLastBuildSuccessTimestamp(t)
	handler := newBuildMetricsHandler(prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_active"}), testRetainedGauge(), func(build *automotivev1alpha1.ImageBuild) {
		recordBuildMetrics(build, nil, buildMetricStatus(build))
	})
	completed := metav1.NewTime(time.Unix(100, 0))
	older := metav1.NewTime(time.Unix(50, 0))
	later := metav1.NewTime(time.Unix(200, 0))
	for _, step := range []struct {
		name   string
		status string
		end    *metav1.Time
		want   float64
	}{
		{"failure before success", buildStatusFailure, &later, 0},
		{"success uses completion time", buildStatusSuccess, &completed, 100},
		{"older success", buildStatusSuccess, &older, 100},
		{"failure after success", buildStatusFailure, &later, 100},
		{"newer success", buildStatusSuccess, &later, 200},
		{"success without completion time", buildStatusSuccess, nil, 200},
	} {
		t.Run(step.name, func(t *testing.T) {
			build := newImageBuild("package", "ebbr", "simg", "arm64", nil, step.end)
			build.Name = step.name
			build.Status.Phase = phaseFailed
			if step.status == buildStatusSuccess {
				build.Status.Phase = phaseCompleted
			}
			handler.OnAdd(build, false)
			if got := gaugeValue(BuildLastSuccessTimestamp); got != step.want {
				t.Fatalf("last success timestamp = %v, want %v", got, step.want)
			}
		})
	}
}

func TestReplayRestoresLastSuccessTimestamp(t *testing.T) {
	type seedRow struct {
		phase, previous string
		completion      *metav1.Time
	}
	for _, tc := range []struct {
		name string
		want float64
		rows []seedRow
	}{
		{name: "empty"},
		{name: "no successful completion", rows: []seedRow{
			{phaseCompleted, "", nil},
			{phaseFailed, "", timePtr(300)},
			{phaseBuilding, "", timePtr(400)},
			{automotivev1alpha1.ImageBuildPhaseExpired, phaseFailed, timePtr(500)},
		}},
		{name: "unordered successes", want: 200, rows: []seedRow{
			{automotivev1alpha1.ImageBuildPhaseExpired, phaseCompleted, timePtr(200)},
			{phaseCompleted, "", timePtr(100)},
			{phaseCompleted, "", nil},
			{phaseFailed, "", timePtr(300)},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetLastBuildSuccessTimestamp(t)
			var builds []automotivev1alpha1.ImageBuild
			for _, row := range tc.rows {
				build := newImageBuild("package", "ebbr", "simg", "arm64", nil, row.completion)
				build.Status.Phase = row.phase
				build.Status.PreviousPhase = row.previous
				builds = append(builds, *build)
			}
			replayBuildMetrics(t, builds)
			if got := gaugeValue(BuildLastSuccessTimestamp); got != tc.want {
				t.Fatalf("seeded last success timestamp = %v, want %v", got, tc.want)
			}
			recordBuildSuccessTimestamp(time.Unix(1000, 0))
			replayBuildMetrics(t, builds)
			if got := gaugeValue(BuildLastSuccessTimestamp); got != 1000 {
				t.Fatalf("startup seeding overwrote newer live completion: %v", got)
			}
		})
	}
}

func timePtr(unix int64) *metav1.Time {
	timestamp := metav1.NewTime(time.Unix(unix, 0))
	return &timestamp
}

func TestRecordBuildSuccessTimestamp_Concurrent(t *testing.T) {
	resetLastBuildSuccessTimestamp(t)
	var workers sync.WaitGroup
	for unix := int64(1); unix <= 100; unix++ {
		workers.Go(func() { recordBuildSuccessTimestamp(time.Unix(unix, 0)) })
	}
	workers.Wait()
	if got := gaugeValue(BuildLastSuccessTimestamp); got != 100 {
		t.Fatalf("concurrent completions recorded %v, want latest timestamp 100", got)
	}
}

func TestActiveBuildsHandler(t *testing.T) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_active_builds"})
	handler := newActiveBuildsHandler(gauge)
	building := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Namespace: "first", Name: "build"},
		Status:     automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
	}
	completed := building.DeepCopy()
	completed.Status.Phase = phaseCompleted
	otherNamespace := building.DeepCopy()
	otherNamespace.Namespace = "second"

	steps := []struct {
		name  string
		event func()
		want  float64
	}{
		{"initial replay", func() { handler.OnAdd(building, true) }, 1},
		{"duplicate add", func() { handler.OnAdd(building, true) }, 1},
		{"resync", func() { handler.OnUpdate(building, building) }, 1},
		{"same name in another namespace", func() { handler.OnAdd(otherNamespace, false) }, 2},
		{"completed", func() { handler.OnUpdate(building, completed) }, 1},
		{"repeated completion", func() { handler.OnUpdate(building, completed) }, 1},
		{"active deletion", func() { handler.OnDelete(otherNamespace) }, 0},
		{"repeated deletion", func() { handler.OnDelete(otherNamespace) }, 0},
		{"completion without observed start", func() { handler.OnUpdate(building, completed) }, 0},
		{"start observed through update", func() { handler.OnUpdate(completed, building) }, 1},
		{"left Building again", func() { handler.OnUpdate(building, completed) }, 0},
		{"build started again", func() { handler.OnAdd(building, false) }, 1},
		{"tombstone deletion", func() {
			handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "first/build", Obj: building})
		}, 0},
		{"start before key-only deletion", func() { handler.OnAdd(building, false) }, 1},
		{"another namespace before key-only deletion", func() { handler.OnAdd(otherNamespace, false) }, 2},
		{"key-only tombstone deletion", func() {
			handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "first/build"})
		}, 1},
		{"repeated key-only deletion", func() {
			handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "first/build"})
		}, 1},
		{"remaining namespace deletion", func() { handler.OnDelete(otherNamespace) }, 0},
		{"unknown tombstone", func() {
			handler.OnDelete(cache.DeletedFinalStateUnknown{Key: "unknown", Obj: "unknown"})
		}, 0},
	}
	for _, step := range steps {
		step.event()
		if got := gaugeValue(gauge); got != step.want {
			t.Fatalf("%s: ActiveBuilds = %v, want %v", step.name, got, step.want)
		}
	}
}

// counterValue returns the current value of a counter with the given labels.
func counterValue(cv *prometheus.CounterVec, labels ...string) float64 {
	m := &io_prometheus_client.Metric{}
	if err := cv.WithLabelValues(labels...).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// histogramCount returns the sample count of a histogram with the given labels.
func histogramCount(hv *prometheus.HistogramVec, labels ...string) uint64 {
	m := &io_prometheus_client.Metric{}
	obs, err := hv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	if err := obs.(prometheus.Metric).Write(m); err != nil {
		return 0
	}
	return m.GetHistogram().GetSampleCount()
}

// histogramSum returns the sample sum of a histogram with the given labels.
func histogramSum(hv *prometheus.HistogramVec, labels ...string) float64 {
	m := &io_prometheus_client.Metric{}
	obs, err := hv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	if err := obs.(prometheus.Metric).Write(m); err != nil {
		return 0
	}
	return m.GetHistogram().GetSampleSum()
}

func newImageBuild(mode, target, format, arch string, start, end *metav1.Time) *automotivev1alpha1.ImageBuild {
	ib := &automotivev1alpha1.ImageBuild{
		Spec: automotivev1alpha1.ImageBuildSpec{
			Architecture: arch,
			AIB: &automotivev1alpha1.AIBSpec{
				Distro: "autosd",
				Target: target,
				Mode:   mode,
			},
			Export: &automotivev1alpha1.ExportSpec{
				Format: format,
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			StartTime:      start,
			CompletionTime: end,
		},
	}
	return ib
}

func pipelineRunWithTiming(json string) *tektonv1.PipelineRun {
	return &tektonv1.PipelineRun{
		Status: tektonv1.PipelineRunStatus{
			PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
				Results: []tektonv1.PipelineRunResult{
					{
						Name:  "build-timing",
						Value: tektonv1.ResultValue{Type: tektonv1.ParamTypeString, StringVal: json},
					},
				},
			},
		},
	}
}

func TestRecordBuildMetrics_Counter(t *testing.T) {
	labels := []string{"package", "autosd", "ebbr", "simg", "arm64", "success"}
	before := counterValue(BuildTotal, labels...)

	start := metav1.NewTime(time.Now().Add(-3 * time.Minute))
	end := metav1.Now()
	ib := newImageBuild("package", "ebbr", "simg", "arm64", &start, &end)
	pr := pipelineRunWithTiming(`{"setup_s":2,"build_s":170,"post_build_s":8,"total_s":180}`)

	recordBuildMetrics(ib, pr, buildStatusSuccess)

	after := counterValue(BuildTotal, labels...)
	if after-before != 1 {
		t.Errorf("BuildTotal counter increment = %v, want 1", after-before)
	}
}

func TestRecordBuildMetrics_FailureCounter(t *testing.T) {
	labels := []string{"package", "autosd", "ebbr", "simg", "amd64", "failure"}
	before := counterValue(BuildTotal, labels...)

	ib := newImageBuild("package", "ebbr", "simg", "amd64", nil, nil)
	recordBuildMetrics(ib, nil, buildStatusFailure)

	after := counterValue(BuildTotal, labels...)
	if after-before != 1 {
		t.Errorf("BuildTotal failure counter increment = %v, want 1", after-before)
	}
}

func TestRecordBuildMetrics_DurationWithoutTerminalStart(t *testing.T) {
	labels := []string{"package", "autosd", "terminal-start-fallback", "simg", "arm64", "success"}
	beforeCount := histogramCount(BuildDuration, labels...)
	beforeSum := histogramSum(BuildDuration, labels...)

	start := metav1.NewTime(time.Unix(100, 0))
	end := metav1.NewTime(time.Unix(280, 0))
	ib := newImageBuild("package", "terminal-start-fallback", "simg", "arm64", &start, nil)
	ib.Status.TerminalResult = &automotivev1alpha1.BuildTerminalResult{
		Phase:       phaseCompleted,
		CompletedAt: end,
	}

	recordBuildMetrics(ib, nil, buildStatusSuccess)

	if got := histogramCount(BuildDuration, labels...) - beforeCount; got != 1 {
		t.Errorf("BuildDuration sample count increment = %v, want 1", got)
	}
	if got := histogramSum(BuildDuration, labels...) - beforeSum; got != 180 {
		t.Errorf("BuildDuration sample sum increment = %v, want 180", got)
	}
}

func TestRecordBuildMetrics_Duration(t *testing.T) {
	labels := []string{"package", "autosd", "ebbr", "simg", "arm64", "success"}
	beforeCount := histogramCount(BuildDuration, labels...)
	beforeSum := histogramSum(BuildDuration, labels...)

	start := metav1.NewTime(time.Now().Add(-180 * time.Second))
	end := metav1.Now()
	ib := newImageBuild("package", "ebbr", "simg", "arm64", &start, &end)
	pr := pipelineRunWithTiming(`{"setup_s":2,"build_s":170,"post_build_s":8,"total_s":180}`)

	recordBuildMetrics(ib, pr, buildStatusSuccess)

	afterCount := histogramCount(BuildDuration, labels...)
	afterSum := histogramSum(BuildDuration, labels...)
	if afterCount-beforeCount != 1 {
		t.Errorf("BuildDuration sample count increment = %v, want 1", afterCount-beforeCount)
	}
	delta := afterSum - beforeSum
	if delta < 179 || delta > 181 {
		t.Errorf("BuildDuration observed value = %v, want ~180", delta)
	}
}

func TestRecordBuildMetrics_NoDurationWithoutTimestamps(t *testing.T) {
	labels := []string{"bootc", "autosd", "ebbr", "simg", "arm64", "success"}
	beforeCount := histogramCount(BuildDuration, labels...)

	ib := newImageBuild("bootc", "ebbr", "simg", "arm64", nil, nil)
	recordBuildMetrics(ib, &tektonv1.PipelineRun{}, buildStatusSuccess)

	afterCount := histogramCount(BuildDuration, labels...)
	if afterCount != beforeCount {
		t.Errorf("BuildDuration should not record without timestamps, got count delta %v", afterCount-beforeCount)
	}
}

func TestRecordBuildMetrics_PhaseDurations(t *testing.T) {
	setupLabels := []string{"package", "autosd", "ebbr", "setup"}
	buildLabels := []string{"package", "autosd", "ebbr", "build"}
	postLabels := []string{"package", "autosd", "ebbr", "post_build"}

	beforeSetup := histogramCount(BuildPhaseDuration, setupLabels...)
	beforeBuild := histogramCount(BuildPhaseDuration, buildLabels...)
	beforePost := histogramCount(BuildPhaseDuration, postLabels...)

	start := metav1.NewTime(time.Now().Add(-3 * time.Minute))
	end := metav1.Now()
	ib := newImageBuild("package", "ebbr", "simg", "arm64", &start, &end)
	pr := pipelineRunWithTiming(`{"setup_s":5,"build_s":160,"post_build_s":15,"total_s":180}`)

	recordBuildMetrics(ib, pr, buildStatusSuccess)

	if histogramCount(BuildPhaseDuration, setupLabels...)-beforeSetup != 1 {
		t.Error("setup phase not recorded")
	}
	if histogramCount(BuildPhaseDuration, buildLabels...)-beforeBuild != 1 {
		t.Error("build phase not recorded")
	}
	if histogramCount(BuildPhaseDuration, postLabels...)-beforePost != 1 {
		t.Error("post_build phase not recorded")
	}

	// Verify observed values
	setupSum := histogramSum(BuildPhaseDuration, setupLabels...)
	if setupSum < 5 {
		t.Errorf("setup phase sum = %v, want >= 5", setupSum)
	}
}

func TestRecordBuildMetrics_NoPhaseDurationsOnFailure(t *testing.T) {
	labels := []string{"package", "autosd", "x86", "setup"}
	beforeCount := histogramCount(BuildPhaseDuration, labels...)

	ib := newImageBuild("package", "x86", "simg", "amd64", nil, nil)
	pr := pipelineRunWithTiming(`{"setup_s":5,"build_s":160,"post_build_s":15,"total_s":180}`)

	recordBuildMetrics(ib, pr, buildStatusFailure)

	afterCount := histogramCount(BuildPhaseDuration, labels...)
	if afterCount != beforeCount {
		t.Error("phase durations should not be recorded on failure")
	}
}

func TestRecordBuildMetrics_MalformedTimingJSON(t *testing.T) {
	labels := []string{"package", "autosd", "qemu", "setup"}
	beforeCount := histogramCount(BuildPhaseDuration, labels...)

	start := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	end := metav1.Now()
	ib := newImageBuild("package", "qemu", "qcow2", "amd64", &start, &end)
	pr := pipelineRunWithTiming(`not valid json`)

	// Should not panic or record phase metrics
	recordBuildMetrics(ib, pr, buildStatusSuccess)

	afterCount := histogramCount(BuildPhaseDuration, labels...)
	if afterCount != beforeCount {
		t.Error("malformed JSON should not produce phase metrics")
	}
}

func TestRecordBuildMetrics_NilPipelineRun(t *testing.T) {
	labels := []string{"package", "autosd", "none", "simg", "amd64", "success"}
	before := counterValue(BuildTotal, labels...)

	ib := newImageBuild("package", "none", "simg", "amd64", nil, nil)

	// Should not panic with nil PipelineRun
	recordBuildMetrics(ib, nil, buildStatusSuccess)

	after := counterValue(BuildTotal, labels...)
	if after-before != 1 {
		t.Errorf("counter should still increment with nil PipelineRun, got delta %v", after-before)
	}
}

func TestRecordBuildMetrics_NoTimingResult(t *testing.T) {
	labels := []string{"package", "autosd", "generic", "setup"}
	beforeCount := histogramCount(BuildPhaseDuration, labels...)

	start := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	end := metav1.Now()
	ib := newImageBuild("package", "generic", "raw", "amd64", &start, &end)
	pr := &tektonv1.PipelineRun{
		Status: tektonv1.PipelineRunStatus{
			PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
				Results: []tektonv1.PipelineRunResult{
					{Name: "other-result", Value: tektonv1.ResultValue{StringVal: "foo"}},
				},
			},
		},
	}

	recordBuildMetrics(ib, pr, buildStatusSuccess)

	afterCount := histogramCount(BuildPhaseDuration, labels...)
	if afterCount != beforeCount {
		t.Error("should not record phase metrics when build-timing result is absent")
	}
}

func TestBuildMetricStatus(t *testing.T) {
	tests := []struct {
		name          string
		phase         string
		previousPhase string
		want          string
	}{
		{"completed", "Completed", "", buildStatusSuccess},
		{"failed", "Failed", "", buildStatusFailure},
		{"cancelled", "Cancelled", "", buildStatusFailure},
		{"expired with previous completed", "Expired", "Completed", buildStatusSuccess},
		{"expired with previous failed", "Expired", "Failed", buildStatusFailure},
		{"expired without previous phase (legacy)", "Expired", "", buildStatusSuccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &automotivev1alpha1.ImageBuild{
				Status: automotivev1alpha1.ImageBuildStatus{
					Phase:         tt.phase,
					PreviousPhase: tt.previousPhase,
				},
			}
			if got := buildMetricStatus(b); got != tt.want {
				t.Errorf("buildMetricStatus(%q, prev=%q) = %q, want %q", tt.phase, tt.previousPhase, got, tt.want)
			}
		})
	}
}

func TestInitialReplayDoesNotSeedCounters(t *testing.T) {
	// Use unique label values to avoid interference from other tests
	buildLabels := []string{"bootc", "fedora", "seed-target", "raw", "arm64", "success"}
	failLabels := []string{"image", "fedora", "seed-target", "qcow2", "amd64", "failure"}
	flashLabels := []string{"seed-target", "success"}

	beforeBuild := counterValue(BuildTotal, buildLabels...)
	beforeFail := counterValue(BuildTotal, failLabels...)
	beforeFlash := counterValue(FlashTotal, flashLabels...)

	start := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	end := metav1.Now()

	builds := []automotivev1alpha1.ImageBuild{
		{
			Spec: automotivev1alpha1.ImageBuildSpec{
				Architecture: "arm64",
				AIB:          &automotivev1alpha1.AIBSpec{Distro: "fedora", Target: "seed-target", Mode: "bootc"},
				Export:       &automotivev1alpha1.ExportSpec{Format: "raw"},
			},
			Status: automotivev1alpha1.ImageBuildStatus{
				Phase:            "Completed",
				StartTime:        &start,
				CompletionTime:   &end,
				FlashTaskRunName: "flash-run-1",
			},
		},
		{
			Spec: automotivev1alpha1.ImageBuildSpec{
				Architecture: "arm64",
				AIB:          &automotivev1alpha1.AIBSpec{Distro: "fedora", Target: "seed-target", Mode: "bootc"},
				Export:       &automotivev1alpha1.ExportSpec{Format: "raw"},
			},
			Status: automotivev1alpha1.ImageBuildStatus{
				Phase:          "Completed",
				StartTime:      &start,
				CompletionTime: &end,
			},
		},
		// Expired build with PreviousPhase=Completed → counts as success
		{
			Spec: automotivev1alpha1.ImageBuildSpec{
				Architecture: "arm64",
				AIB:          &automotivev1alpha1.AIBSpec{Distro: "fedora", Target: "seed-target", Mode: "bootc"},
				Export:       &automotivev1alpha1.ExportSpec{Format: "raw"},
			},
			Status: automotivev1alpha1.ImageBuildStatus{
				Phase:          "Expired",
				PreviousPhase:  "Completed",
				StartTime:      &start,
				CompletionTime: &end,
			},
		},
		{
			Spec: automotivev1alpha1.ImageBuildSpec{
				Architecture: "amd64",
				AIB:          &automotivev1alpha1.AIBSpec{Distro: "fedora", Target: "seed-target", Mode: "image"},
				Export:       &automotivev1alpha1.ExportSpec{Format: "qcow2"},
			},
			Status: automotivev1alpha1.ImageBuildStatus{
				Phase: "Failed",
			},
		},
		// Expired build with PreviousPhase=Failed → counts as failure
		{
			Spec: automotivev1alpha1.ImageBuildSpec{
				Architecture: "amd64",
				AIB:          &automotivev1alpha1.AIBSpec{Distro: "fedora", Target: "seed-target", Mode: "image"},
				Export:       &automotivev1alpha1.ExportSpec{Format: "qcow2"},
			},
			Status: automotivev1alpha1.ImageBuildStatus{
				Phase:         "Expired",
				PreviousPhase: "Failed",
			},
		},
		// In-progress builds must not seed terminal counters
		{
			Spec: automotivev1alpha1.ImageBuildSpec{
				Architecture: "amd64",
				AIB:          &automotivev1alpha1.AIBSpec{Distro: "fedora", Target: "seed-target", Mode: "image"},
			},
			Status: automotivev1alpha1.ImageBuildStatus{
				Phase: "Building",
			},
		},
	}

	replayBuildMetrics(t, builds)

	afterBuild := counterValue(BuildTotal, buildLabels...)
	if afterBuild != beforeBuild {
		t.Errorf("initial replay changed success counter by %v", afterBuild-beforeBuild)
	}

	afterFail := counterValue(BuildTotal, failLabels...)
	if afterFail != beforeFail {
		t.Errorf("initial replay changed failure counter by %v", afterFail-beforeFail)
	}

	afterFlash := counterValue(FlashTotal, flashLabels...)
	if afterFlash != beforeFlash {
		t.Errorf("initial replay changed flash counter by %v", afterFlash-beforeFlash)
	}
}

func replayBuildMetrics(t *testing.T, builds []automotivev1alpha1.ImageBuild) {
	t.Helper()
	active := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_active"})
	retained := testRetainedGauge()
	handler := newBuildMetricsHandler(active, retained, func(*automotivev1alpha1.ImageBuild) {
		t.Error("initial replay must not count a completion")
	})
	for i := range builds {
		build := builds[i].DeepCopy()
		build.Name = fmt.Sprintf("replayed-%d", i)
		build.UID = types.UID(build.Name)
		handler.OnAdd(build, true)
	}
}
