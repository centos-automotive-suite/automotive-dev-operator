package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

var _ = Describe("CreateClientWithReauth", func() {
	It("should handle nil authToken pointer safely", func() {
		ctx := context.Background()
		client, err := CreateClientWithReauth(ctx, "https://api.example.com", nil, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})

	It("should create client with empty token when authToken is empty string", func() {
		ctx := context.Background()
		emptyToken := ""
		client, err := CreateClientWithReauth(ctx, "https://api.example.com", &emptyToken, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})

	It("should create client with provided token", func() {
		ctx := context.Background()
		token := "test-token"
		client, err := CreateClientWithReauth(ctx, "https://api.example.com", &token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})

	It("should handle OIDC errors gracefully and still create client", func() {
		ctx := context.Background()
		emptyToken := ""
		// Use invalid server URL to trigger OIDC error
		client, err := CreateClientWithReauth(ctx, "http://invalid-server:9999", &emptyToken, false)
		// Should still create client even if OIDC fails (auth is optional)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})
})

var _ = Describe("RefreshCachedToken", func() {
	var (
		tempDir      string
		originalHome string
		apiServer    *httptest.Server
		tokenServer  *httptest.Server
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-refresh-cached-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
		if apiServer != nil {
			apiServer.Close()
		}
		if tokenServer != nil {
			tokenServer.Close()
		}
	})

	It("should return error when no cache exists", func() {
		apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"clientId": "test-client",
				"jwt": []map[string]interface{}{
					{
						"issuer": map[string]interface{}{
							"url": "https://issuer.example.com",
						},
						"claimMappings": map[string]interface{}{
							"username": map[string]interface{}{"claim": "preferred_username"},
						},
					},
				},
			})
		}))

		ctx := context.Background()
		_, err := RefreshCachedToken(ctx, apiServer.URL, false)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no cached token found"))
	})

	It("should return error when cache has no refresh token", func() {
		newToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)

		// Set up token cache without refresh token
		cacheDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())
		cache := TokenCache{
			Token:     newToken,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Issuer:    "https://issuer.example.com",
		}
		data, _ := json.Marshal(cache)
		Expect(os.WriteFile(filepath.Join(cacheDir, tokenCacheFile), data, 0600)).To(Succeed())

		apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"clientId": "test-client",
				"jwt": []map[string]interface{}{
					{
						"issuer": map[string]interface{}{
							"url": "https://issuer.example.com",
						},
						"claimMappings": map[string]interface{}{
							"username": map[string]interface{}{"claim": "preferred_username"},
						},
					},
				},
			})
		}))

		ctx := context.Background()
		_, err := RefreshCachedToken(ctx, apiServer.URL, false)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no refresh token stored"))
	})

	It("should return error when OIDC is not configured on server", func() {
		apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		ctx := context.Background()
		_, err := RefreshCachedToken(ctx, apiServer.URL, false)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not configured"))
	})

	It("should successfully refresh when cache has refresh token", func() {
		newAccessToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)

		// Token endpoint server (OIDC provider)
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/.well-known/openid-configuration" {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"authorization_endpoint": "https://issuer.example.com/auth",
					"token_endpoint":         tokenServer.URL + "/token",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  newAccessToken,
				"refresh_token": "new-refresh",
				"expires_in":    3600,
			})
		}))

		// Set up token cache with refresh token
		cacheDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())
		cache := TokenCache{
			Token:        makeExpiredTestJWT(tokenServer.URL),
			RefreshToken: "old-refresh",
			ExpiresAt:    time.Now().Add(-1 * time.Hour),
			Issuer:       tokenServer.URL,
		}
		data, _ := json.Marshal(cache)
		Expect(os.WriteFile(filepath.Join(cacheDir, tokenCacheFile), data, 0600)).To(Succeed())

		// API server returns OIDC config pointing to the token server
		apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"clientId": "test-client",
				"jwt": []map[string]interface{}{
					{
						"issuer": map[string]interface{}{
							"url": tokenServer.URL,
						},
						"claimMappings": map[string]interface{}{
							"username": map[string]interface{}{"claim": "preferred_username"},
						},
					},
				},
			})
		}))

		ctx := context.Background()
		token, err := RefreshCachedToken(ctx, apiServer.URL, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(newAccessToken))
	})
})
