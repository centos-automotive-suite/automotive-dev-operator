package buildapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("Workspace API", func() {
	var (
		server    *APIServer
		authToken string
	)

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		server = newTestServer(GinkgoT(), nil)
		server.internalJWT = &internalJWTConfig{
			issuer: "workspace-test", audience: "workspace-api", key: []byte("workspace-test-signing-key-32-bytes"),
		}
		server.lastAuthConfigCheck = time.Now()
		server.router = server.createRouter()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Issuer: server.internalJWT.issuer, Audience: jwt.ClaimStrings{server.internalJWT.audience},
			Subject: "workspace-user", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		var err error
		authToken, err = token.SignedString(server.internalJWT.key)
		Expect(err).NotTo(HaveOccurred())
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
			{"POST", "/v1/workspaces/my-app/sync/plan"},
			{"POST", "/v1/workspaces/my-app/sync/delete"},
			{"POST", "/v1/workspaces/my-app/exec"},
			{"POST", "/v1/workspaces/my-app/runs"},
			{"GET", "/v1/workspaces/my-app/runs"},
			{"DELETE", "/v1/workspaces/my-app/runs/run"},
			{"GET", "/v1/workspaces/my-app/runs/run"},
			{"GET", "/v1/workspaces/my-app/runs/run/logs"},
			{"POST", "/v1/workspaces/my-app/runs/run/cancel"},
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
		It("should reject memory below the container runtime minimum", func() {
			_, err := buildWorkspaceResources("", "4", nil)
			Expect(err).To(MatchError(`invalid --memory value "4": must be at least 6Mi`))
		})

		It("should reject request with missing name", func() {
			body, _ := json.Marshal(buildcontract.WorkspaceRequest{})
			req, err := http.NewRequest("POST", "/v1/workspaces", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+authToken)

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
			Expect(w.Body.String()).To(MatchJSON(`{"error":"name is required"}`))
		})

		It("should reject invalid JSON", func() {
			req, err := http.NewRequest("POST", "/v1/workspaces", bytes.NewReader([]byte("not json")))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+authToken)

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
			Expect(w.Body.String()).To(MatchJSON(`{"error":"invalid JSON request"}`))
		})
	})

	Context("Workspace response", func() {
		DescribeTable("status mapping",
			func(stopped bool, status automotivev1alpha1.WorkspaceStatus, wantPhase, wantReason, wantMessage string) {
				response := workspaceResponseFromCR(&automotivev1alpha1.Workspace{
					Spec:   automotivev1alpha1.WorkspaceSpec{Stopped: stopped},
					Status: status,
				})

				Expect(response.Phase).To(Equal(wantPhase))
				Expect(response.Reason).To(Equal(wantReason))
				Expect(response.Message).To(Equal(wantMessage))
			},
			Entry("propagates reason and message", false,
				automotivev1alpha1.WorkspaceStatus{
					Phase:   "Failed",
					Reason:  automotivev1alpha1.WorkspaceReasonContainerRuntimeError,
					Message: "container toolchain: CreateContainerError",
				},
				"Failed", string(automotivev1alpha1.WorkspaceReasonContainerRuntimeError), "container toolchain: CreateContainerError"),
			Entry("clears stale status while stopping", true,
				automotivev1alpha1.WorkspaceStatus{
					Phase:   "Failed",
					Reason:  automotivev1alpha1.WorkspaceReasonContainerRuntimeError,
					Message: "container toolchain: CreateContainerError",
				},
				"Stopping", "", ""),
			Entry("clears stale status while starting", false,
				automotivev1alpha1.WorkspaceStatus{
					Phase:   "Stopped",
					Reason:  automotivev1alpha1.WorkspaceReasonAutoPaused,
					Message: "Auto-paused after 30m of inactivity",
				},
				"Starting", "", ""),
		)
	})

	Context("Exec Workspace", func() {
		It("should reject request with missing command", func() {
			body, _ := json.Marshal(buildcontract.WorkspaceExecRequest{})
			req, err := http.NewRequest("POST", "/v1/workspaces/my-app/exec", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+authToken)

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
			Expect(w.Body.String()).To(MatchJSON(`{"error":"command is required"}`))
		})
	})

	Context("Deploy Workspace", func() {
		It("should reject request with missing fields", func() {
			body, _ := json.Marshal(buildcontract.WorkspaceDeployRequest{})
			req, err := http.NewRequest("POST", "/v1/workspaces/my-app/deploy", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+authToken)

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
			Expect(w.Body.String()).To(MatchJSON(`{"error":"at least one artifact mapping is required"}`))
		})
	})
})
