package buildapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("APIServer Integration", func() {
	var (
		server *APIServer
		logger logr.Logger
		ctx    context.Context
		cancel context.CancelFunc
	)

	BeforeEach(func() {
		if os.Getenv("KUBECONFIG") == "" && os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
			Skip("no kubernetes configuration found - set KUBECONFIG or run in cluster")
		}

		gin.SetMode(gin.DebugMode)
		logger = logr.Discard()
		server = NewAPIServer(":8080", logger)
		ctx, cancel = context.WithCancel(context.Background())
	})

	AfterEach(func() {
		if cancel != nil {
			cancel()
		}
		time.Sleep(100 * time.Millisecond)
	})

	Context("Standalone Server", func() {
		It("should start and serve requests against real Kubernetes cluster", func() {
			go func() {
				err := server.Start(ctx)
				if err != nil && err != context.Canceled {
					Fail(fmt.Sprintf("server failed to start: %v", err))
				}
			}()

			time.Sleep(500 * time.Millisecond)

			resp, err := http.Get("http://localhost:8080/v1/healthz")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			_ = resp.Body.Close()

			resp, err = http.Get("http://localhost:8080/v1/openapi.yaml")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(resp.Header.Get("Content-Type")).To(Equal("application/yaml"))
			_ = resp.Body.Close()

			resp, err = http.Get("http://localhost:8080/v1/builds")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
			_ = resp.Body.Close()
		})

		It("should handle authentication with real Kubernetes tokens", func() {
			go func() {
				err := server.Start(ctx)
				if err != nil && err != context.Canceled {
					Fail(fmt.Sprintf("server failed to start: %v", err))
				}
			}()

			time.Sleep(500 * time.Millisecond)

			token := os.Getenv("KUBERNETES_TOKEN")
			if token == "" {
				Skip("no KUBERNETES_TOKEN environment variable set")
			}

			req, err := http.NewRequest("GET", "http://localhost:8080/v1/builds", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer "+token)

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()

			Expect(resp.StatusCode).NotTo(Equal(http.StatusUnauthorized))
		})
	})
})

var _ = Describe("APIServer Manual Testing", func() {
	It("should provide instructions for manual testing", func() {
		By("Starting the server manually")
		fmt.Println()
		fmt.Println("1. Start the server:")
		fmt.Println("   go run ./cmd/build-api/")
		fmt.Println()
		fmt.Println("2. Test endpoints:")
		fmt.Println("   GET http://localhost:8080/v1/healthz")
		fmt.Println("   GET http://localhost:8080/v1/openapi.yaml")
		fmt.Println()
		fmt.Println("3. Test with authentication:")
		fmt.Println("   # Get your token:")
		fmt.Println("   oc whoami -t")
		fmt.Println("   # or")
		cmd := "kubectl get secret -o jsonpath='{.data.token}' " +
			"$(kubectl get secret | grep default-token | awk '{print $1}') | base64 -d"
		fmt.Println("   " + cmd)
		fmt.Println()
		fmt.Println("   # Test authenticated endpoint:")
		fmt.Println("   GET http://localhost:8080/v1/builds")
		fmt.Println("   Header: Authorization: Bearer YOUR_TOKEN")
		fmt.Println()
		fmt.Println("4. Environment variables:")
		fmt.Println("   export GIN_MODE=debug          # Enable debug mode")
		fmt.Println("   export PORT=8080               # Set port (default: 8080)")
		fmt.Println("   export BUILD_API_NAMESPACE=ns  # Set target namespace")
		fmt.Println("   export KUBECONFIG=~/.kube/config # Set kubeconfig")
		fmt.Println()
	})
})
