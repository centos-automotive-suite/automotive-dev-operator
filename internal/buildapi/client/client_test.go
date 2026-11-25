package client

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	buildapi "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/version"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

func TestClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Suite")
}

var _ = Describe("WithInsecureTLS", func() {
	It("should preserve default transport settings when cloning", func() {
		client, err := New("https://api.example.com", WithInsecureTLS())
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())

		transport, ok := client.httpClient.Transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(transport).NotTo(BeNil())
		Expect(transport.TLSClientConfig).NotTo(BeNil())
		Expect(transport.TLSClientConfig.InsecureSkipVerify).To(BeTrue())

		// Verify that default transport settings are preserved
		// (proxy, HTTP/2, connection pooling should be inherited)
		// Note: We can't compare function pointers directly, but we verify
		// that the transport was cloned (not nil) and TLS config is set
		Expect(transport.Proxy).NotTo(BeNil())
		Expect(transport.DialContext).NotTo(BeNil())
	})

	It("should update existing transport TLS config", func() {
		existingTransport := &http.Transport{}
		existingClient := &http.Client{
			Transport: existingTransport,
		}

		client, err := New("https://api.example.com", WithHTTPClient(existingClient), WithInsecureTLS())
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())

		transport, ok := client.httpClient.Transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(transport.TLSClientConfig).NotTo(BeNil())
		Expect(transport.TLSClientConfig.InsecureSkipVerify).To(BeTrue())
	})
})

var _ = Describe("WithCACertificate", func() {
	var tempCertFile string
	var tlsServer *httptest.Server

	BeforeEach(func() {
		tlsServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/workspaces/my-app/start" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(buildapi.WorkspaceResponse{Name: "my-app", Phase: "Running"})
		}))
		tempCertFile = filepath.Join(GinkgoT().TempDir(), "ca.pem")
		certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
		Expect(os.WriteFile(tempCertFile, certData, 0o600)).To(Succeed())
	})

	AfterEach(func() {
		tlsServer.Close()
	})

	It("trusts the supplied CA for HTTPS and preserves default transport settings", func() {
		untrustedClient, err := New(tlsServer.URL)
		Expect(err).NotTo(HaveOccurred())
		_, err = untrustedClient.StartWorkspace(context.Background(), "my-app")
		Expect(err).To(HaveOccurred())
		var unknownAuthority x509.UnknownAuthorityError
		Expect(errors.As(err, &unknownAuthority)).To(BeTrue(), "the negative control must fail certificate verification")

		client, err := New(tlsServer.URL, WithCACertificate(tempCertFile))
		Expect(err).NotTo(HaveOccurred())
		transport, ok := client.httpClient.Transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(transport.TLSClientConfig).NotTo(BeNil())
		Expect(transport.TLSClientConfig.RootCAs).NotTo(BeNil())
		Expect(transport.TLSClientConfig.InsecureSkipVerify).To(BeFalse())
		defaultTransport := http.DefaultTransport.(*http.Transport)
		Expect(transport).NotTo(BeIdenticalTo(defaultTransport))
		Expect(transport.Proxy).NotTo(BeNil())
		Expect(transport.DialContext).NotTo(BeNil())
		Expect(transport.ForceAttemptHTTP2).To(Equal(defaultTransport.ForceAttemptHTTP2))
		Expect(transport.MaxIdleConns).To(Equal(defaultTransport.MaxIdleConns))
		Expect(transport.IdleConnTimeout).To(Equal(defaultTransport.IdleConnTimeout))
		Expect(transport.TLSHandshakeTimeout).To(Equal(defaultTransport.TLSHandshakeTimeout))
		DeferCleanup(transport.CloseIdleConnections)

		response, err := client.StartWorkspace(context.Background(), "my-app")
		Expect(err).NotTo(HaveOccurred())
		Expect(response.Name).To(Equal("my-app"))
		Expect(response.Phase).To(Equal("Running"))
	})

	It("should handle non-existent certificate file gracefully", func() {
		client, err := New("https://api.example.com", WithCACertificate("/non/existent/file.pem"))
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
		// Should not fail, just skip CA cert configuration
	})

	It("should handle invalid certificate file gracefully", func() {
		invalidFile, err := os.CreateTemp("", "invalid-*.pem")
		Expect(err).NotTo(HaveOccurred())
		_, err = invalidFile.WriteString("invalid certificate data")
		Expect(err).NotTo(HaveOccurred())
		Expect(invalidFile.Close()).To(Succeed())

		client, err := New("https://api.example.com", WithCACertificate(invalidFile.Name()))
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
		// Should not fail, just skip CA cert configuration

		_ = os.Remove(invalidFile.Name())
	})
})

var _ = Describe("Workspace Start/Stop", func() {
	var (
		mockServer *httptest.Server
		apiClient  *Client
	)

	AfterEach(func() {
		if mockServer != nil {
			mockServer.Close()
		}
	})

	Context("StartWorkspace", func() {
		It("should POST to the correct endpoint and decode response", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				Expect(r.URL.Path).To(Equal("/v1/workspaces/my-app/start"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-token"))

				w.Header().Set("Content-Type", "application/json")
				resp := buildapi.WorkspaceResponse{
					Name:  "my-app",
					Phase: "Pending",
					Arch:  "amd64",
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			resp, err := apiClient.StartWorkspace(context.Background(), "my-app")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Name).To(Equal("my-app"))
			Expect(resp.Phase).To(Equal("Pending"))
			Expect(resp.Arch).To(Equal("amd64"))
		})

		It("should return error on non-200 response", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error": "workspace not found"}`))
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			resp, err := apiClient.StartWorkspace(context.Background(), "nonexistent")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("workspace not found"))
			Expect(resp).To(BeNil())
		})
	})

	Context("StopWorkspace", func() {
		It("should POST to the correct endpoint and decode response", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				Expect(r.URL.Path).To(Equal("/v1/workspaces/my-app/stop"))

				w.Header().Set("Content-Type", "application/json")
				resp := buildapi.WorkspaceResponse{
					Name:  "my-app",
					Phase: "Running",
					Arch:  "arm64",
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			resp, err := apiClient.StopWorkspace(context.Background(), "my-app")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Name).To(Equal("my-app"))
			Expect(resp.Phase).To(Equal("Running"))
		})

		It("should return error on server error", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "internal error"}`))
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			resp, err := apiClient.StopWorkspace(context.Background(), "my-app")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("internal error"))
			Expect(resp).To(BeNil())
		})
	})

	Context("DeleteBuild", func() {
		It("should DELETE to the correct endpoint", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodDelete))
				Expect(r.URL.Path).To(Equal("/v1/builds/my-build"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-token"))

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"message": "build \"my-build\" deleted"}`))
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			err = apiClient.DeleteBuild(context.Background(), "my-build")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error on 403 Forbidden", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error": "you can only delete your own builds"}`))
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			err = apiClient.DeleteBuild(context.Background(), "other-build")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("you can only delete your own builds"))
		})

		It("should return error on 404 Not Found", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error": "build not found"}`))
			}))

			var err error
			apiClient, err = New(mockServer.URL, WithAuthToken("test-token"))
			Expect(err).NotTo(HaveOccurred())

			err = apiClient.DeleteBuild(context.Background(), "nonexistent")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("build not found"))
		})

		It("should properly escape build names in the URL path", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.URL.Path).To(Equal("/v1/builds/my%20build"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"message": "deleted"}`))
			}))

			var err error
			apiClient, err = New(mockServer.URL)
			Expect(err).NotTo(HaveOccurred())

			err = apiClient.DeleteBuild(context.Background(), "my build")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("workspaceAction with URL-unsafe names", func() {
		It("should properly escape workspace names in the URL path", func() {
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The name "my app" should be escaped to "my%20app"
				Expect(r.URL.Path).To(Equal("/v1/workspaces/my%20app/start"))

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(buildapi.WorkspaceResponse{Name: "my app"})
			}))

			var err error
			apiClient, err = New(mockServer.URL)
			Expect(err).NotTo(HaveOccurred())

			resp, err := apiClient.StartWorkspace(context.Background(), "my app")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Name).To(Equal("my app"))
		})
	})
})

var _ = Describe("WithServerVersionObserver", func() {
	serve := func(status int, serverVersion string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if serverVersion != "" {
				w.Header().Set(version.Header, serverVersion)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`[]`))
		}))
		DeferCleanup(srv.Close)
		return srv
	}

	observedVersions := func(srv *httptest.Server) []string {
		var seen []string
		c, err := New(srv.URL, WithServerVersionObserver(func(v string) { seen = append(seen, v) }))
		Expect(err).NotTo(HaveOccurred())
		_, _ = c.ListBuilds(context.Background())
		return seen
	}

	It("passes the version the server reports", func() {
		Expect(observedVersions(serve(http.StatusOK, "0.2.1"))).To(Equal([]string{"0.2.1"}))
	})

	It("passes an empty version when the server reports none", func() {
		Expect(observedVersions(serve(http.StatusOK, ""))).To(Equal([]string{""}))
	})

	It("skips failed responses, which can come from a proxy in front of the Build API", func() {
		Expect(observedVersions(serve(http.StatusServiceUnavailable, ""))).To(BeEmpty())
	})
})

var _ = Describe("Errors from a Build API of another version", func() {
	BeforeEach(func() {
		DeferCleanup(func(v string) { version.Version = v }, version.Version)
		version.Version = "v0.4.0"
	})

	listBuildsError := func(serverVersion string) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if serverVersion != "" {
				w.Header().Set(version.Header, serverVersion)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid JSON request"}`))
		}))
		DeferCleanup(srv.Close)
		c, err := New(srv.URL)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.ListBuilds(context.Background())
		Expect(err).To(HaveOccurred())
		return err
	}

	It("name both versions", func() {
		Expect(listBuildsError("0.3.0")).To(MatchError(ContainSubstring("(caib v0.4.0, Build API 0.3.0)")))
	})

	It("don't name versions that match", func() {
		Expect(listBuildsError("0.4.0").Error()).NotTo(ContainSubstring("Build API 0.4.0"))
	})

	It("don't name versions when the server reports none", func() {
		Expect(listBuildsError("").Error()).NotTo(ContainSubstring("caib v0.4.0"))
	})
})
