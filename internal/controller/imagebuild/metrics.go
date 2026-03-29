package imagebuild

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	metricsNamespace = "ado"
	metricsSubsystem = "build"

	buildStatusSuccess = "success"
	buildStatusFailure = "failure"
)

var (
	// BuildDuration tracks the total build duration in seconds.
	BuildDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "duration_seconds",
			Help:      "Total build duration in seconds",
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

	// BuildTotal counts total builds by status.
	BuildTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "total",
			Help:      "Total number of builds by status",
		},
		[]string{"mode", "distro", "target", "format", "arch", "status"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		BuildDuration,
		BuildPhaseDuration,
		BuildTotal,
	)
}
