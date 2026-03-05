package config

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

// roundTripFunc adapts a function to http.RoundTripper for concise inline transports.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// writeJumpstarterConfig creates jumpstarter config.yaml and clients/<alias>.yaml under baseDir.
func writeJumpstarterConfig(baseDir, alias, endpoint string) {
	jmpDir := filepath.Join(baseDir, "jumpstarter")
	ExpectWithOffset(1, os.MkdirAll(filepath.Join(jmpDir, "clients"), 0700)).To(Succeed())

	configYAML := "config:\n  current-client: " + alias + "\n"
	ExpectWithOffset(1, os.WriteFile(filepath.Join(jmpDir, "config.yaml"), []byte(configYAML), 0600)).To(Succeed())

	if alias != "" {
		clientYAML := "endpoint: " + endpoint + "\n"
		ExpectWithOffset(1, os.WriteFile(filepath.Join(jmpDir, "clients", alias+".yaml"), []byte(clientYAML), 0600)).To(Succeed())
	}
}

var _ = Describe("DeriveServerFromJumpstarter", func() {
	var tempDir string
	var origXDG, origHome string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-derive-test-*")
		Expect(err).NotTo(HaveOccurred())

		origXDG = os.Getenv("XDG_CONFIG_HOME")
		origHome = os.Getenv("HOME")
		Expect(os.Setenv("XDG_CONFIG_HOME", tempDir)).To(Succeed())
		// HOME controls where SaveServerURL writes ~/.caib/cli.json
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
	})

	AfterEach(func() {
		healthHTTPClient = nil
		_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		_ = os.Setenv("HOME", origHome)
		_ = os.RemoveAll(tempDir)
	})

	It("derives correct URL from .apps. domain and saves config on health 200", func() {
		writeJumpstarterConfig(tempDir, "mycluster", "grpc.lab.apps.example.com:443")

		var requestedURL string
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requestedURL = req.URL.String()
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		result := DeriveServerFromJumpstarter()
		expected := "https://ado-build-api-automotive-dev-operator-system.apps.example.com"

		Expect(result).To(Equal(expected))
		Expect(requestedURL).To(Equal(expected + "/v1/healthz"))

		// Verify it was persisted
		cfg, err := Read()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.ServerURL).To(Equal(expected))
	})

	It("derives correct URL using fallback (non-.apps. domain)", func() {
		writeJumpstarterConfig(tempDir, "mycluster", "svc.namespace.cluster.local:443")

		var requestedURL string
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requestedURL = req.URL.String()
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		result := DeriveServerFromJumpstarter()
		expected := "https://ado-build-api-automotive-dev-operator-system.cluster.local"

		Expect(result).To(Equal(expected))
		Expect(requestedURL).To(Equal(expected + "/v1/healthz"))
	})

	It("returns empty when health check returns non-200", func() {
		writeJumpstarterConfig(tempDir, "mycluster", "grpc.lab.apps.example.com:443")

		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		Expect(DeriveServerFromJumpstarter()).To(BeEmpty())
	})

	It("returns empty when no jumpstarter config exists", func() {
		called := false
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				called = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		Expect(DeriveServerFromJumpstarter()).To(BeEmpty())
		Expect(called).To(BeFalse(), "health check should not be called when there is no jumpstarter config")
	})

	It("returns empty when health check returns a network error", func() {
		writeJumpstarterConfig(tempDir, "mycluster", "grpc.lab.apps.example.com:443")

		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("connection refused")
			}),
		}

		Expect(DeriveServerFromJumpstarter()).To(BeEmpty())
	})

	It("returns empty when endpoint has fewer than 3 domain labels", func() {
		writeJumpstarterConfig(tempDir, "mycluster", "localhost:443")

		called := false
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				called = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		Expect(DeriveServerFromJumpstarter()).To(BeEmpty())
		Expect(called).To(BeFalse(), "health check should not be called when domain cannot be derived")
	})
})

var _ = Describe("DefaultServerWithDerive", func() {
	var tempDir string
	var origXDG, origHome, origCAIBServer string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-default-test-*")
		Expect(err).NotTo(HaveOccurred())

		origXDG = os.Getenv("XDG_CONFIG_HOME")
		origHome = os.Getenv("HOME")
		origCAIBServer = os.Getenv("CAIB_SERVER")
		Expect(os.Setenv("XDG_CONFIG_HOME", tempDir)).To(Succeed())
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("CAIB_SERVER")).To(Succeed())
	})

	AfterEach(func() {
		healthHTTPClient = nil
		_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		_ = os.Setenv("HOME", origHome)
		if origCAIBServer != "" {
			_ = os.Setenv("CAIB_SERVER", origCAIBServer)
		} else {
			_ = os.Unsetenv("CAIB_SERVER")
		}
		_ = os.RemoveAll(tempDir)
	})

	It("returns CAIB_SERVER env when set, without calling derive", func() {
		Expect(os.Setenv("CAIB_SERVER", "https://from-env.example.com")).To(Succeed())
		Expect(SaveServerURL("https://from-config.example.com")).To(Succeed())
		writeJumpstarterConfig(tempDir, "mycluster", "grpc.lab.apps.example.com:443")

		called := false
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				called = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		Expect(DefaultServerWithDerive()).To(Equal("https://from-env.example.com"))
		Expect(called).To(BeFalse(), "derivation should not be attempted when CAIB_SERVER is set")
	})

	It("returns saved config when CAIB_SERVER is empty, without calling derive", func() {
		Expect(SaveServerURL("https://from-config.example.com")).To(Succeed())
		writeJumpstarterConfig(tempDir, "mycluster", "grpc.lab.apps.example.com:443")

		called := false
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				called = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		Expect(DefaultServerWithDerive()).To(Equal("https://from-config.example.com"))
		Expect(called).To(BeFalse(), "derivation should not be attempted when saved config exists")
	})

	It("falls through to Jumpstarter derivation when env and config are empty", func() {
		writeJumpstarterConfig(tempDir, "mycluster", "grpc.lab.apps.example.com:443")

		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		expected := "https://ado-build-api-automotive-dev-operator-system.apps.example.com"
		Expect(DefaultServerWithDerive()).To(Equal(expected))
	})

	It("returns empty when nothing is configured and no jumpstarter config exists", func() {
		called := false
		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				called = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		Expect(DefaultServerWithDerive()).To(BeEmpty())
		Expect(called).To(BeFalse(), "health check should not be called when there is no jumpstarter config")
	})
})
