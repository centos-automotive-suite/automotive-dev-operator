package buildapi

import (
	"fmt"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	sealedMetricsNamespace = "ado"
	sealedMetricsSubsystem = "sealed"
)

var (
	// SealedCreateRequestsTotal counts sealed create requests by operation and result.
	SealedCreateRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: sealedMetricsNamespace,
			Subsystem: sealedMetricsSubsystem,
			Name:      "create_requests_total",
			Help:      "Total number of sealed create requests by operation and result",
		},
		[]string{"operation", "result"},
	)

	// SealedRequestDuration tracks sealed API request duration by endpoint and status code.
	SealedRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: sealedMetricsNamespace,
			Subsystem: sealedMetricsSubsystem,
			Name:      "request_duration_seconds",
			Help:      "Sealed API request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"endpoint", "status_code"},
	)
)

func init() {
	prometheus.MustRegister(
		SealedCreateRequestsTotal,
		SealedRequestDuration,
	)
}

func sealedMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start).Seconds()
		endpoint := c.FullPath()
		statusCode := fmt.Sprintf("%d", c.Writer.Status())
		SealedRequestDuration.WithLabelValues(endpoint, statusCode).Observe(duration)
	}
}

func sealedOperationLabel(op buildcontract.SealedOperation, stages []string) string {
	if op != "" {
		return string(op)
	}
	// For multi-stage flows, use only the first stage to keep label
	// cardinality bounded and comparable across requests.
	if len(stages) > 0 {
		return stages[0]
	}
	return "unknown"
}
