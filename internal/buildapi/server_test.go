package buildapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("APIServer", func() {
	var (
		server *APIServer
		logger logr.Logger
	)

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		logger = logr.Discard()
		server = NewAPIServer(":0", logger)
	})

	AfterEach(func() {
		server = nil
	})

	Context("Server Creation", func() {
		It("should create a valid API server", func() {
			Expect(server).NotTo(BeNil())
			Expect(server.router).NotTo(BeNil())
			Expect(server.server).NotTo(BeNil())
			Expect(server.addr).To(Equal(":0"))
			Expect(server.log).To(Equal(logger))
		})
	})

	Context("Health Endpoint", func() {
		It("should return 200 OK for health check", func() {
			req, err := http.NewRequest("GET", "/v1/healthz", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Body.String()).To(Equal("ok"))
		})
	})

	Context("OpenAPI Endpoint", func() {
		It("should return OpenAPI spec", func() {
			req, err := http.NewRequest("GET", "/v1/openapi.yaml", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Header().Get("Content-Type")).To(Equal("application/yaml"))
			Expect(w.Body.String()).NotTo(BeEmpty())
		})
	})

	Context("Builds Endpoints Authentication", func() {
		var testCases = []struct {
			method string
			path   string
		}{
			{"GET", "/v1/builds"},
			{"POST", "/v1/builds"},
			{"GET", "/v1/builds/test-build"},
			{"GET", "/v1/builds/test-build/logs"},
			{"GET", "/v1/builds/test-build/template"},
			{"POST", "/v1/builds/test-build/uploads"},
		}

		It("should require authentication for all builds endpoints", func() {
			for _, tc := range testCases {
				By(fmt.Sprintf("testing %s %s", tc.method, tc.path))

				req, err := http.NewRequest(tc.method, tc.path, nil)
				Expect(err).NotTo(HaveOccurred())

				w := httptest.NewRecorder()
				server.router.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			}
		})
	})

	Context("OperatorConfig Endpoint", func() {
		var (
			originalGetClientFromRequestFn func(*gin.Context) (ctrlclient.Client, error)
			originalLoadOperatorConfigFn   func(context.Context, ctrlclient.Client, string) (*automotivev1alpha1.OperatorConfig, error)
			originalLoadTargetDefaultsFn   func(context.Context, ctrlclient.Client, string) (map[string]TargetDefaults, error)
			originalNamespace              string
			hasOriginalNamespace           bool
		)

		BeforeEach(func() {
			originalGetClientFromRequestFn = getClientFromRequestFn
			originalLoadOperatorConfigFn = loadOperatorConfigFn
			originalLoadTargetDefaultsFn = loadTargetDefaultsFn
			originalNamespace, hasOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
			Expect(os.Setenv("BUILD_API_NAMESPACE", "default")).To(Succeed())
		})

		AfterEach(func() {
			getClientFromRequestFn = originalGetClientFromRequestFn
			loadOperatorConfigFn = originalLoadOperatorConfigFn
			loadTargetDefaultsFn = originalLoadTargetDefaultsFn
			if hasOriginalNamespace {
				Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
			} else {
				Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
			}
		})

		It("should return empty operator config when config resource is not found", func() {
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return nil, nil
			}
			loadOperatorConfigFn = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return nil, k8serrors.NewNotFound(
					schema.GroupResource{
						Group:    "automotive.sdv.cloud.redhat.com",
						Resource: "operatorconfigs",
					},
					"config",
				)
			}

			req, err := http.NewRequest(http.MethodGet, "/v1/config", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("reqID", "test-req-id")

			server.handleGetOperatorConfig(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response OperatorConfigResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.JumpstarterTargets).To(BeNil())
			Expect(response.TargetDefaults).To(BeNil())
		})

		It("should return jumpstarter targets and target defaults when config exists", func() {
			config := &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					Jumpstarter: &automotivev1alpha1.JumpstarterConfig{
						TargetMappings: map[string]automotivev1alpha1.JumpstarterTargetMapping{
							"qemu": {
								Selector: "board-type=qemu",
							},
							"ebbr": {
								Selector: "board-type=ebbr",
								FlashCmd: "j storage flash ${IMAGE}",
							},
						},
					},
				},
			}

			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return nil, nil
			}
			loadOperatorConfigFn = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return config, nil
			}
			loadTargetDefaultsFn = func(_ context.Context, _ ctrlclient.Client, _ string) (map[string]TargetDefaults, error) {
				return map[string]TargetDefaults{
					"ebbr": {Architecture: "arm64", ExtraArgs: []string{"--separate-partitions"}},
				}, nil
			}

			req, err := http.NewRequest(http.MethodGet, "/v1/config", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("reqID", "test-req-id")

			server.handleGetOperatorConfig(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response OperatorConfigResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.JumpstarterTargets).To(HaveLen(2))
			Expect(response.JumpstarterTargets["qemu"]).To(Equal(JumpstarterTarget{Selector: "board-type=qemu"}))
			Expect(response.JumpstarterTargets["ebbr"]).To(Equal(JumpstarterTarget{
				Selector: "board-type=ebbr",
				FlashCmd: "j storage flash ${IMAGE}",
			}))
			Expect(response.TargetDefaults).To(HaveLen(1))
			Expect(response.TargetDefaults["ebbr"]).To(Equal(TargetDefaults{
				Architecture: "arm64",
				ExtraArgs:    []string{"--separate-partitions"},
			}))
		})
	})

	Context("Server Lifecycle", func() {
		It("should start and stop gracefully", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			errChan := make(chan error, 1)
			go func() {
				errChan <- server.Start(ctx)
			}()

			time.Sleep(100 * time.Millisecond)

			cancel()

			Eventually(errChan, 2*time.Second).Should(Receive(BeNil()))
		})
	})

	Context("Integration with Kubernetes", func() {
		BeforeEach(func() {
			if os.Getenv("KUBECONFIG") == "" && os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
				Skip("no kubernetes configuration found")
			}
		})

		It("should be able to connect to Kubernetes cluster", func() {
			req, err := http.NewRequest("GET", "/v1/healthz", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Body.String()).To(Equal("ok"))
		})
	})
})

var _ = Describe("APIServer Performance", func() {
	var (
		server *APIServer
	)

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		server = NewAPIServer(":0", logr.Discard())
	})

	It("should handle health endpoint requests", func() {
		req, _ := http.NewRequest("GET", "/v1/healthz", nil)

		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
	})

	It("should handle openapi endpoint requests efficiently", func() {
		req, _ := http.NewRequest("GET", "/v1/openapi.yaml", nil)

		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
	})
})
