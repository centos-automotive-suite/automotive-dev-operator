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

// writeJumpstarterConfig creates ~/.config/jumpstarter/{config.yaml,clients/mycluster.yaml} under homeDir.
func writeJumpstarterConfig(baseDir, endpoint string) {
	const alias = "mycluster"
	jmpDir := filepath.Join(baseDir, ".config", "jumpstarter")
	ExpectWithOffset(1, os.MkdirAll(filepath.Join(jmpDir, "clients"), 0700)).To(Succeed())

	configYAML := "config:\n  current-client: " + alias + "\n"
	ExpectWithOffset(1, os.WriteFile(filepath.Join(jmpDir, "config.yaml"), []byte(configYAML), 0600)).To(Succeed())

	clientYAML := "endpoint: " + endpoint + "\n"
	ExpectWithOffset(1, os.WriteFile(filepath.Join(jmpDir, "clients", alias+".yaml"), []byte(clientYAML), 0600)).To(Succeed())
}

var _ = Describe("DeriveServerFromJumpstarter", func() {
	var tempDir string
	var origHome, origXDG string

	var origBuildNS string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-derive-test-*")
		Expect(err).NotTo(HaveOccurred())

		origHome = os.Getenv("HOME")
		origXDG = os.Getenv("XDG_CONFIG_HOME")
		origBuildNS = os.Getenv("CAIB_BUILD_API_NAMESPACE")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CONFIG_HOME")).To(Succeed())
		Expect(os.Unsetenv("CAIB_BUILD_API_NAMESPACE")).To(Succeed())
	})

	AfterEach(func() {
		healthHTTPClient = nil
		_ = os.Setenv("HOME", origHome)
		if origXDG != "" {
			_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		if origBuildNS != "" {
			_ = os.Setenv("CAIB_BUILD_API_NAMESPACE", origBuildNS)
		} else {
			_ = os.Unsetenv("CAIB_BUILD_API_NAMESPACE")
		}
		_ = os.RemoveAll(tempDir)
	})

	It("derives correct URL from .apps. domain and saves config on health 200", func() {
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

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

		// Verify it was persisted with source endpoint
		cfg, err := Read()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.ServerURL).To(Equal(expected))
		Expect(cfg.DerivedFromEndpoint).To(Equal("grpc.lab.apps.example.com:443"))
	})

	It("uses CAIB_BUILD_API_NAMESPACE when set", func() {
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")
		Expect(os.Setenv("CAIB_BUILD_API_NAMESPACE", "custom-ns")).To(Succeed())

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
		expected := "https://ado-build-api-custom-ns.apps.example.com"

		Expect(result).To(Equal(expected))
		Expect(requestedURL).To(Equal(expected + "/v1/healthz"))
	})

	It("derives correct URL using fallback (non-.apps. domain)", func() {
		writeJumpstarterConfig(tempDir, "svc.namespace.cluster.local:443")

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
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

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
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("connection refused")
			}),
		}

		Expect(DeriveServerFromJumpstarter()).To(BeEmpty())
	})

	It("returns empty when endpoint has fewer than 3 domain labels", func() {
		writeJumpstarterConfig(tempDir, "localhost:443")

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
	var origHome, origXDG, origCAIBServer, origBuildNS string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-default-test-*")
		Expect(err).NotTo(HaveOccurred())

		origHome = os.Getenv("HOME")
		origXDG = os.Getenv("XDG_CONFIG_HOME")
		origCAIBServer = os.Getenv("CAIB_SERVER")
		origBuildNS = os.Getenv("CAIB_BUILD_API_NAMESPACE")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CONFIG_HOME")).To(Succeed())
		Expect(os.Unsetenv("CAIB_SERVER")).To(Succeed())
		Expect(os.Unsetenv("CAIB_BUILD_API_NAMESPACE")).To(Succeed())
	})

	AfterEach(func() {
		healthHTTPClient = nil
		_ = os.Setenv("HOME", origHome)
		if origXDG != "" {
			_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		if origBuildNS != "" {
			_ = os.Setenv("CAIB_BUILD_API_NAMESPACE", origBuildNS)
		} else {
			_ = os.Unsetenv("CAIB_BUILD_API_NAMESPACE")
		}
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
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

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

	It("returns manually-saved config when CAIB_SERVER is empty, without calling derive", func() {
		Expect(SaveServerURL("https://from-config.example.com")).To(Succeed())
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

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

	It("returns derived config when Jumpstarter endpoint still matches (cache hit)", func() {
		// Simulate a previously-derived config that matches current Jumpstarter endpoint
		Expect(saveConfig(&CLIConfig{
			ServerURL:           "https://ado-build-api-automotive-dev-operator-system.apps.example.com",
			DerivedFromEndpoint: "grpc.lab.apps.example.com:443",
		})).To(Succeed())
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

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

		Expect(DefaultServerWithDerive()).To(Equal("https://ado-build-api-automotive-dev-operator-system.apps.example.com"))
		Expect(called).To(BeFalse(), "should use cached URL when Jumpstarter endpoint matches")
	})

	It("invalidates derived config when Jumpstarter endpoint changes", func() {
		// Simulate a derived config from old cluster
		Expect(saveConfig(&CLIConfig{
			ServerURL:           "https://ado-build-api-automotive-dev-operator-system.apps.old-cluster.com",
			DerivedFromEndpoint: "grpc.lab.apps.old-cluster.com:443",
		})).To(Succeed())
		// Current Jumpstarter config points to new cluster
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.new-cluster.com:443")

		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		result := DefaultServerWithDerive()
		Expect(result).To(Equal("https://ado-build-api-automotive-dev-operator-system.apps.new-cluster.com"))

		// Verify new derivation was persisted with new source
		cfg, err := Read()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.DerivedFromEndpoint).To(Equal("grpc.lab.apps.new-cluster.com:443"))
	})

	It("does not invalidate manually-set config even when Jumpstarter endpoint changes", func() {
		// Manually set (no DerivedFromEndpoint)
		Expect(SaveServerURL("https://manual-server.example.com")).To(Succeed())
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.different-cluster.com:443")

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

		Expect(DefaultServerWithDerive()).To(Equal("https://manual-server.example.com"))
		Expect(called).To(BeFalse(), "manually-set URL should never be invalidated")
	})

	It("invalidates derived config when Jumpstarter config is removed", func() {
		// Derived URL from a cluster that no longer has Jumpstarter config
		Expect(saveConfig(&CLIConfig{
			ServerURL:           "https://ado-build-api-automotive-dev-operator-system.apps.old-cluster.com",
			DerivedFromEndpoint: "grpc.lab.apps.old-cluster.com:443",
		})).To(Succeed())
		// No Jumpstarter config written - simulates deletion/corruption

		healthHTTPClient = &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("connection refused")
			}),
		}

		// Should not return stale URL; derivation runs but fails → empty
		Expect(DefaultServerWithDerive()).To(BeEmpty())
	})

	It("falls through to Jumpstarter derivation when env and config are empty", func() {
		writeJumpstarterConfig(tempDir, "grpc.lab.apps.example.com:443")

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

var _ = Describe("S3Defaults", func() {
	var tempDir string
	var origHome, origXDG string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-s3-config-test-*")
		Expect(err).NotTo(HaveOccurred())

		origHome = os.Getenv("HOME")
		origXDG = os.Getenv("XDG_CONFIG_HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CONFIG_HOME")).To(Succeed())
	})

	AfterEach(func() {
		_ = os.Setenv("HOME", origHome)
		if origXDG != "" {
			_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		_ = os.RemoveAll(tempDir)
	})

	It("returns nil when no config file exists", func() {
		result, err := S3Defaults()
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(BeNil())
	})

	It("returns nil when config file has no S3 section", func() {
		Expect(SaveServerURL("https://example.com")).To(Succeed())
		result, err := S3Defaults()
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(BeNil())
	})

	It("returns S3 config when present", func() {
		cfg := &CLIConfig{
			ServerURL: "https://example.com",
			S3: &S3Config{
				Bucket:            "my-bucket",
				Prefix:            "builds/",
				Endpoint:          "https://minio.local",
				Region:            "eu-west-1",
				CredentialsSecret: "my-s3-creds",
			},
		}
		Expect(saveConfig(cfg)).To(Succeed())

		result, err := S3Defaults()
		Expect(err).NotTo(HaveOccurred())
		Expect(result).NotTo(BeNil())
		Expect(result.Bucket).To(Equal("my-bucket"))
		Expect(result.Prefix).To(Equal("builds/"))
		Expect(result.Endpoint).To(Equal("https://minio.local"))
		Expect(result.Region).To(Equal("eu-west-1"))
		Expect(result.CredentialsSecret).To(Equal("my-s3-creds"))
	})

	It("returns error when config file contains invalid JSON", func() {
		configDir := filepath.Join(tempDir, ".config", "caib")
		Expect(os.MkdirAll(configDir, 0700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(configDir, "cli.json"), []byte("{invalid"), 0600)).To(Succeed())

		result, err := S3Defaults()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading config for S3 defaults"))
		Expect(result).To(BeNil())
	})
})

var _ = Describe("SaveServerURL preserves S3 config", func() {
	var tempDir string
	var origHome, origXDG string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-preserve-s3-test-*")
		Expect(err).NotTo(HaveOccurred())

		origHome = os.Getenv("HOME")
		origXDG = os.Getenv("XDG_CONFIG_HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CONFIG_HOME")).To(Succeed())
	})

	AfterEach(func() {
		_ = os.Setenv("HOME", origHome)
		if origXDG != "" {
			_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		_ = os.RemoveAll(tempDir)
	})

	It("preserves S3 config when saving a new server URL", func() {
		cfg := &CLIConfig{
			ServerURL: "https://old-server.com",
			S3: &S3Config{
				Bucket:   "my-bucket",
				Endpoint: "https://minio.local",
			},
		}
		Expect(saveConfig(cfg)).To(Succeed())

		Expect(SaveServerURL("https://new-server.com")).To(Succeed())

		result, err := Read()
		Expect(err).NotTo(HaveOccurred())
		Expect(result.ServerURL).To(Equal("https://new-server.com"))
		Expect(result.DerivedFromEndpoint).To(BeEmpty())
		Expect(result.S3).NotTo(BeNil())
		Expect(result.S3.Bucket).To(Equal("my-bucket"))
		Expect(result.S3.Endpoint).To(Equal("https://minio.local"))
	})

	It("preserves S3 config when saving a derived server URL", func() {
		cfg := &CLIConfig{
			S3: &S3Config{
				Bucket:            "my-bucket",
				CredentialsSecret: "my-creds",
			},
		}
		Expect(saveConfig(cfg)).To(Succeed())

		Expect(saveDerivedServerURL("https://derived.com", "grpc.endpoint:443")).To(Succeed())

		result, err := Read()
		Expect(err).NotTo(HaveOccurred())
		Expect(result.ServerURL).To(Equal("https://derived.com"))
		Expect(result.DerivedFromEndpoint).To(Equal("grpc.endpoint:443"))
		Expect(result.S3).NotTo(BeNil())
		Expect(result.S3.Bucket).To(Equal("my-bucket"))
		Expect(result.S3.CredentialsSecret).To(Equal("my-creds"))
	})
})

var _ = Describe("SaveServerURL with invalid config file", func() {
	var tempDir string
	var origHome, origXDG string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-invalid-config-test-*")
		Expect(err).NotTo(HaveOccurred())

		origHome = os.Getenv("HOME")
		origXDG = os.Getenv("XDG_CONFIG_HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CONFIG_HOME")).To(Succeed())
	})

	AfterEach(func() {
		_ = os.Setenv("HOME", origHome)
		if origXDG != "" {
			_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		_ = os.RemoveAll(tempDir)
	})

	writeInvalidConfig := func() string {
		configDir := filepath.Join(tempDir, ".config", "caib")
		ExpectWithOffset(1, os.MkdirAll(configDir, 0700)).To(Succeed())
		path := filepath.Join(configDir, "cli.json")
		ExpectWithOffset(1, os.WriteFile(path, []byte("{invalid json"), 0600)).To(Succeed())
		return path
	}

	It("returns error from SaveServerURL and leaves file unchanged", func() {
		path := writeInvalidConfig()
		original, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())

		err = SaveServerURL("https://new.example.com")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading existing config"))

		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(original))
	})

	It("returns error from saveDerivedServerURL and leaves file unchanged", func() {
		path := writeInvalidConfig()
		original, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())

		err = saveDerivedServerURL("https://derived.example.com", "grpc.endpoint:443")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading existing config"))

		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(original))
	})
})

var _ = Describe("Read with XDG config override", func() {
	var tempDir string
	var origHome, origXDG string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-xdg-config-test-*")
		Expect(err).NotTo(HaveOccurred())

		origHome = os.Getenv("HOME")
		origXDG = os.Getenv("XDG_CONFIG_HOME")
		Expect(os.Setenv("HOME", filepath.Join(tempDir, "home"))).To(Succeed())
		Expect(os.Setenv("XDG_CONFIG_HOME", filepath.Join(tempDir, "custom-config"))).To(Succeed())
	})

	AfterEach(func() {
		_ = os.Setenv("HOME", origHome)
		if origXDG != "" {
			_ = os.Setenv("XDG_CONFIG_HOME", origXDG)
		} else {
			_ = os.Unsetenv("XDG_CONFIG_HOME")
		}
		_ = os.RemoveAll(tempDir)
	})

	It("reads cli.json from XDG_CONFIG_HOME when set", func() {
		configDir := filepath.Join(tempDir, "custom-config", "caib")
		Expect(os.MkdirAll(configDir, 0700)).To(Succeed())
		Expect(os.WriteFile(
			filepath.Join(configDir, "cli.json"),
			[]byte("{\"server_url\":\"https://from-xdg.example.com\"}"),
			0600,
		)).To(Succeed())

		cfg, err := Read()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.ServerURL).To(Equal("https://from-xdg.example.com"))
	})
})
