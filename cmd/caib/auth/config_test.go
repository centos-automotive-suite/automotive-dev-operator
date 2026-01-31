package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

var _ = Describe("GetOIDCConfigFromAPI", func() {
	var server *httptest.Server

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	It("should return config when API returns valid OIDC configuration", func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.URL.Path).To(Equal("/v1/auth/config"))
			response := map[string]interface{}{
				"clientId": "test-client",
				"jwt": []map[string]interface{}{
					{
						"issuer": map[string]interface{}{
							"url":       "https://issuer.example.com",
							"audiences": []string{"audience1"},
						},
						"claimMappings": map[string]interface{}{
							"username": map[string]interface{}{
								"claim": "preferred_username",
							},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}))

		config, err := GetOIDCConfigFromAPI(server.URL)
		Expect(err).NotTo(HaveOccurred())
		Expect(config).NotTo(BeNil())
		Expect(config.IssuerURL).To(Equal("https://issuer.example.com"))
		Expect(config.ClientID).To(Equal("test-client"))
		Expect(config.Scopes).To(Equal([]string{"openid", "profile", "email"}))
	})

	It("should return nil config without error when API returns 404", func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		config, err := GetOIDCConfigFromAPI(server.URL)
		Expect(err).NotTo(HaveOccurred())
		Expect(config).To(BeNil())
	})

	It("should return error when API returns non-200 status", func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		config, err := GetOIDCConfigFromAPI(server.URL)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("HTTP 500"))
		Expect(config).To(BeNil())
	})

	It("should return error when API returns empty JWT array", func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			response := map[string]interface{}{
				"clientId": "test-client",
				"jwt":      []interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}))

		config, err := GetOIDCConfigFromAPI(server.URL)
		Expect(err).NotTo(HaveOccurred())
		Expect(config).To(BeNil())
	})

	It("should return error when client ID is missing", func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			response := map[string]interface{}{
				"clientId": "",
				"jwt": []map[string]interface{}{
					{
						"issuer": map[string]interface{}{
							"url": "https://issuer.example.com",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}))

		config, err := GetOIDCConfigFromAPI(server.URL)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("client ID is required"))
		Expect(config).To(BeNil())
	})

	It("should return error when network request fails", func() {
		config, err := GetOIDCConfigFromAPI("http://invalid-host-that-does-not-exist:9999")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to fetch OIDC config from API"))
		Expect(config).To(BeNil())
	})

	It("should return error when response is invalid JSON", func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("invalid json"))
		}))

		config, err := GetOIDCConfigFromAPI(server.URL)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to decode"))
		Expect(config).To(BeNil())
	})
})

var _ = Describe("GetOIDCConfigFromLocalConfig", func() {
	var tempDir string
	var originalHome string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		_ = os.Setenv("HOME", tempDir)
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
	})

	It("should read config from local file", func() {
		configDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(configDir, 0700)).To(Succeed())

		configData := map[string]interface{}{
			"issuer_url": "https://issuer.example.com",
			"client_id":  "test-client",
			"scopes":     []string{"openid", "profile"},
		}
		data, err := json.Marshal(configData)
		Expect(err).NotTo(HaveOccurred())

		configPath := filepath.Join(configDir, "config.json")
		Expect(os.WriteFile(configPath, data, 0600)).To(Succeed())

		config, err := GetOIDCConfigFromLocalConfig()
		Expect(err).NotTo(HaveOccurred())
		Expect(config).NotTo(BeNil())
		Expect(config.IssuerURL).To(Equal("https://issuer.example.com"))
		Expect(config.ClientID).To(Equal("test-client"))
		Expect(config.Scopes).To(Equal([]string{"openid", "profile"}))
	})

	It("should return error when file does not exist", func() {
		config, err := GetOIDCConfigFromLocalConfig()
		Expect(err).To(HaveOccurred())
		Expect(config).To(BeNil())
	})

	It("should return error when config is invalid", func() {
		configDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(configDir, 0700)).To(Succeed())

		configPath := filepath.Join(configDir, "config.json")
		Expect(os.WriteFile(configPath, []byte("invalid json"), 0600)).To(Succeed())

		config, err := GetOIDCConfigFromLocalConfig()
		Expect(err).To(HaveOccurred())
		Expect(config).To(BeNil())
	})

	It("should return error when issuer_url is missing", func() {
		configDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(configDir, 0700)).To(Succeed())

		configData := map[string]interface{}{
			"client_id": "test-client",
		}
		data, err := json.Marshal(configData)
		Expect(err).NotTo(HaveOccurred())

		configPath := filepath.Join(configDir, "config.json")
		Expect(os.WriteFile(configPath, data, 0600)).To(Succeed())

		config, err := GetOIDCConfigFromLocalConfig()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("issuer_url and client_id required"))
		Expect(config).To(BeNil())
	})
})

var _ = Describe("SaveOIDCConfig", func() {
	var tempDir string
	var originalHome string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		_ = os.Setenv("HOME", tempDir)
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
	})

	It("should save config to local file", func() {
		config := &OIDCConfig{
			IssuerURL: "https://issuer.example.com",
			ClientID:  "test-client",
			Scopes:    []string{"openid", "profile"},
		}

		err := SaveOIDCConfig(config)
		Expect(err).NotTo(HaveOccurred())

		configPath := filepath.Join(tempDir, tokenCacheDir, "config.json")
		data, err := os.ReadFile(configPath)
		Expect(err).NotTo(HaveOccurred())

		var savedConfig map[string]interface{}
		Expect(json.Unmarshal(data, &savedConfig)).To(Succeed())
		Expect(savedConfig["issuer_url"]).To(Equal("https://issuer.example.com"))
		Expect(savedConfig["client_id"]).To(Equal("test-client"))
	})
})
