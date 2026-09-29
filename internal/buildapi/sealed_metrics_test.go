package buildapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("Sealed Metrics", func() {
	var server *APIServer

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		server = NewAPIServer(":0", logr.Discard())
	})

	Context("metrics endpoint", func() {
		It("should expose prometheus metrics at /metrics", func() {
			// Ensure counter and histogram are present in exposition.
			SealedCreateRequestsTotal.WithLabelValues("reseal", "accepted").Inc()
			// Ensure at least one observation so the histogram appears
			SealedRequestDuration.WithLabelValues("/v1/reseals", "200").Observe(0.001)

			req, err := http.NewRequest("GET", "/metrics", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			body := w.Body.String()
			Expect(body).To(ContainSubstring("ado_sealed_create_requests_total"))
			Expect(body).To(ContainSubstring("ado_sealed_request_duration_seconds"))
		})

		It("records bad request metric for sealed route through router", func() {
			metricsTestRouter := gin.New()
			metricsTestRouter.POST("/v1/reseals", sealedMetricsMiddleware(), func(c *gin.Context) {
				server.createSealed(c, buildcontract.SealedReseal)
			})
			metricsTestRouter.GET("/metrics", metricsHandler())

			reqBody := []byte(`{"name":"metrics-test","operation":"bad-op","inputRef":"quay.io/example/input:latest"}`)
			req := httptest.NewRequest(http.MethodPost, "/v1/reseals", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			metricsTestRouter.ServeHTTP(w, req)
			Expect(w.Code).To(Equal(http.StatusBadRequest))

			metricsReq, err := http.NewRequest(http.MethodGet, "/metrics", nil)
			Expect(err).NotTo(HaveOccurred())
			metricsResp := httptest.NewRecorder()
			metricsTestRouter.ServeHTTP(metricsResp, metricsReq)

			Expect(metricsResp.Code).To(Equal(http.StatusOK))
			metricsBody := metricsResp.Body.String()
			Expect(metricsBody).To(ContainSubstring(`ado_sealed_create_requests_total{operation="reseal",result="bad_request"}`))
		})
	})

	Context("sealedOperationLabel", func() {
		It("prefers explicit operation", func() {
			label := sealedOperationLabel(buildcontract.SealedReseal, []string{"prepare-reseal"})
			Expect(label).To(Equal("reseal"))
		})

		It("falls back to first stage", func() {
			label := sealedOperationLabel("", []string{"extract-for-signing", "inject-signed"})
			Expect(label).To(Equal("extract-for-signing"))
		})
	})
})
