package buildapi

import (
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("Sealed", func() {
	Describe("Validation", func() {
		Describe("resolveSealedOperation", func() {
			It("resolves operation from URL path", func() {
				gin.SetMode(gin.TestMode)
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("POST", "/v1/extract-for-signings", nil)

				op := resolveSealedOperation(c)
				Expect(op).To(Equal(buildcontract.SealedExtractForSigning))
			})

			It("returns empty operation for unknown path", func() {
				gin.SetMode(gin.TestMode)
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("POST", "/v1/unknown", nil)

				op := resolveSealedOperation(c)
				Expect(op).To(BeEmpty())
			})
		})

		Describe("validateSealedRequest", func() {
			It("accepts operation and validates container refs", func() {
				req := &buildcontract.SealedRequest{
					Operation: buildcontract.SealedReseal,
					InputRef:  "quay.io/example/input:latest",
					OutputRef: "quay.io/example/output:latest",
				}

				stages, errMsg := validateSealedRequest(req)
				Expect(errMsg).To(BeEmpty())
				Expect(stages).To(Equal([]string{"reseal"}))
			})

			It("generates a default name when name is empty", func() {
				req := &buildcontract.SealedRequest{
					Operation: buildcontract.SealedPrepareReseal,
					InputRef:  "quay.io/example/input:latest",
				}

				_, errMsg := validateSealedRequest(req)
				Expect(errMsg).To(BeEmpty())
				Expect(req.Name).To(HavePrefix("prepare-reseal-"))
			})

			It("rejects inject-signed stage without signedRef", func() {
				req := &buildcontract.SealedRequest{
					Stages:   []string{"prepare-reseal", "inject-signed"},
					InputRef: "quay.io/example/input:latest",
				}

				_, errMsg := validateSealedRequest(req)
				Expect(errMsg).To(ContainSubstring("signedRef is required"))
			})

			It("rejects invalid operation", func() {
				req := &buildcontract.SealedRequest{
					Operation: buildcontract.SealedOperation("bad-op"),
					InputRef:  "quay.io/example/input:latest",
				}

				_, errMsg := validateSealedRequest(req)
				Expect(errMsg).To(ContainSubstring("operation must be one of"))
			})
		})
	})

	Describe("Routes", func() {
		var (
			server               *APIServer
			originalNamespace    string
			hadOriginalNamespace bool
		)

		BeforeEach(func() {
			gin.SetMode(gin.TestMode)
			server = NewAPIServer(":0", logr.Discard())
			originalNamespace, hadOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
			Expect(os.Setenv("BUILD_API_NAMESPACE", "test-ns")).To(Succeed())
		})

		AfterEach(func() {
			if hadOriginalNamespace {
				Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
			} else {
				Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
			}
		})

		It("requires authentication for sealed endpoints", func() {
			endpoints := []struct {
				method string
				path   string
			}{
				{http.MethodPost, "/v1/reseals"},
				{http.MethodGet, "/v1/reseals"},
				{http.MethodGet, "/v1/reseals/test-job"},
				{http.MethodGet, "/v1/reseals/test-job/logs"},
				{http.MethodPost, "/v1/prepare-reseals"},
				{http.MethodPost, "/v1/extract-for-signings"},
				{http.MethodPost, "/v1/inject-signeds"},
			}

			for _, endpoint := range endpoints {
				req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
				w := httptest.NewRecorder()
				server.router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized), endpoint.method+" "+endpoint.path)
			}
		})
	})
})
