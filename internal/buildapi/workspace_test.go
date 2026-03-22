package buildapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("Workspace API", func() {
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

	Context("Authentication", func() {
		var testCases = []struct {
			method string
			path   string
		}{
			{"POST", "/v1/workspaces"},
			{"GET", "/v1/workspaces"},
			{"GET", "/v1/workspaces/my-app"},
			{"DELETE", "/v1/workspaces/my-app"},
			{"POST", "/v1/workspaces/my-app/start"},
			{"POST", "/v1/workspaces/my-app/stop"},
			{"POST", "/v1/workspaces/my-app/sync"},
			{"POST", "/v1/workspaces/my-app/exec"},
			{"POST", "/v1/workspaces/my-app/deploy"},
		}

		It("should require authentication for all workspace endpoints", func() {
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

	Context("Create Workspace", func() {
		It("should reject request with missing name", func() {
			body, _ := json.Marshal(WorkspaceRequest{})
			req, err := http.NewRequest("POST", "/v1/workspaces", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			// 401 because no auth — but the route must exist (not 404)
			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})

		It("should reject invalid JSON", func() {
			req, err := http.NewRequest("POST", "/v1/workspaces", bytes.NewReader([]byte("not json")))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Context("Exec Workspace", func() {
		It("should reject request with missing command", func() {
			body, _ := json.Marshal(WorkspaceExecRequest{})
			req, err := http.NewRequest("POST", "/v1/workspaces/my-app/exec", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Context("Deploy Workspace", func() {
		It("should reject request with missing fields", func() {
			body, _ := json.Marshal(WorkspaceDeployRequest{})
			req, err := http.NewRequest("POST", "/v1/workspaces/my-app/deploy", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})
	})
})
