package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

type testHTTPStatusError struct {
	code int
}

func (e *testHTTPStatusError) Error() string {
	return http.StatusText(e.code)
}

func (e *testHTTPStatusError) HTTPStatusCode() int {
	return e.code
}

var _ = Describe("IsAuthError", func() {
	DescribeTable("classifies only authentication failures for reauthentication",
		func(err error, expected bool) {
			Expect(IsAuthError(err)).To(Equal(expected))
		},
		Entry("nil error", nil, false),
		Entry("401 response", &testHTTPStatusError{code: http.StatusUnauthorized}, true),
		Entry("wrapped 401 response", fmt.Errorf("request failed: %w", &testHTTPStatusError{code: http.StatusUnauthorized}), true),
		Entry("unstructured unauthorized response", errors.New("request failed: unauthorized"), false),
		Entry("403 workspace image policy response", &testHTTPStatusError{code: http.StatusForbidden}, false),
		Entry("forbidden response", errors.New("request failed: forbidden"), false),
		Entry("unrelated response", errors.New("request failed: 500 Internal Server Error"), false),
	)
})

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
		tempDir          string
		originalHome     string
		originalXDGCache string
		apiServer        *httptest.Server
		tokenServer      *httptest.Server
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-refresh-cached-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		originalXDGCache = os.Getenv("XDG_CACHE_HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CACHE_HOME")).To(Succeed())
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		if originalXDGCache != "" {
			_ = os.Setenv("XDG_CACHE_HOME", originalXDGCache)
		} else {
			_ = os.Unsetenv("XDG_CACHE_HOME")
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId": "test-client",
				"jwt": []map[string]any{
					{
						"issuer": map[string]any{
							"url": "https://issuer.example.com",
						},
						"claimMappings": map[string]any{
							"username": map[string]any{"claim": "preferred_username"},
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
		cacheDir := filepath.Join(tempDir, ".cache", "caib")
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId": "test-client",
				"jwt": []map[string]any{
					{
						"issuer": map[string]any{
							"url": "https://issuer.example.com",
						},
						"claimMappings": map[string]any{
							"username": map[string]any{"claim": "preferred_username"},
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  newAccessToken,
				"refresh_token": "new-refresh",
				"expires_in":    3600,
			})
		}))

		// Set up token cache with refresh token
		cacheDir := filepath.Join(tempDir, ".cache", "caib")
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId": "test-client",
				"jwt": []map[string]any{
					{
						"issuer": map[string]any{
							"url": tokenServer.URL,
						},
						"claimMappings": map[string]any{
							"username": map[string]any{"claim": "preferred_username"},
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

var _ = Describe("GetTokenWithReauth with an externally issued token", func() {
	var (
		tempDir          string
		originalHome     string
		originalXDGCache string
		apiServer        *httptest.Server
		issuerServer     *httptest.Server
	)

	// startAPIServer serves the Build API OIDC config pointing at issuerURL,
	// optionally restricting the audiences the server accepts.
	startAPIServer := func(issuerURL string, audiences ...string) *httptest.Server {
		issuer := map[string]any{"url": issuerURL}
		if len(audiences) > 0 {
			issuer["audiences"] = audiences
		}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId": "test-client",
				"jwt": []map[string]any{
					{
						"issuer": issuer,
						"claimMappings": map[string]any{
							"username": map[string]any{"claim": "preferred_username"},
						},
					},
				},
			})
		}))
	}

	writeTokenCache := func(cache TokenCache) {
		cacheDir := filepath.Join(tempDir, ".cache", "caib")
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())
		data, err := json.Marshal(cache)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(cacheDir, tokenCacheFile), data, 0600)).To(Succeed())
	}

	readTokenCache := func() *TokenCache {
		data, err := os.ReadFile(filepath.Join(tempDir, ".cache", "caib", tokenCacheFile))
		if err != nil {
			return nil
		}
		var cache TokenCache
		Expect(json.Unmarshal(data, &cache)).To(Succeed())
		return &cache
	}

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-external-token-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		originalXDGCache = os.Getenv("XDG_CACHE_HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
		Expect(os.Unsetenv("XDG_CACHE_HOME")).To(Succeed())

		// Issuer that cannot complete a login flow: discovery always fails, so any
		// fall-through to the browser flow surfaces as an error instead of hanging.
		issuerServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		if originalXDGCache != "" {
			_ = os.Setenv("XDG_CACHE_HOME", originalXDGCache)
		} else {
			_ = os.Unsetenv("XDG_CACHE_HOME")
		}
		_ = os.RemoveAll(tempDir)
		if apiServer != nil {
			apiServer.Close()
		}
		if issuerServer != nil {
			issuerServer.Close()
		}
	})

	It("reuses a valid token issued by the configured issuer", func() {
		apiServer = startAPIServer(issuerServer.URL)
		external := makeValidTestJWT(issuerServer.URL, 1*time.Hour)

		token, didAuth, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(external))
		Expect(didAuth).To(BeFalse())
	})

	It("caches the reused token so later commands do not log in again", func() {
		apiServer = startAPIServer(issuerServer.URL)
		external := makeValidTestJWT(issuerServer.URL, 1*time.Hour)

		_, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).NotTo(HaveOccurred())

		cache := readTokenCache()
		Expect(cache).NotTo(BeNil())
		Expect(cache.Token).To(Equal(external))
		Expect(cache.Issuer).To(Equal(issuerServer.URL))
		Expect(cache.RefreshToken).To(BeEmpty())
		Expect(cache.ExpiresAt).To(BeTemporally(">", time.Now()))
	})

	It("ignores a token issued by a different issuer", func() {
		apiServer = startAPIServer(issuerServer.URL)
		external := makeValidTestJWT("https://other-issuer.example.com", 1*time.Hour)

		token, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).To(HaveOccurred())
		Expect(token).NotTo(Equal(external))
		Expect(readTokenCache()).To(BeNil())
	})

	It("ignores an expired token from the configured issuer", func() {
		apiServer = startAPIServer(issuerServer.URL)
		external := makeExpiredTestJWT(issuerServer.URL)

		token, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).To(HaveOccurred())
		Expect(token).NotTo(Equal(external))
		Expect(readTokenCache()).To(BeNil())
	})

	It("ignores a token with no issuer claim", func() {
		apiServer = startAPIServer(issuerServer.URL)
		external := makeTestJWT(map[string]any{
			"sub": "test-user",
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
		})

		token, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).To(HaveOccurred())
		Expect(token).NotTo(Equal(external))
		Expect(readTokenCache()).To(BeNil())
	})

	It("reuses a token whose audience the server accepts", func() {
		apiServer = startAPIServer(issuerServer.URL, "caib-cli")
		external := makeAudienceTestJWT(issuerServer.URL, "caib-cli")

		token, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(external))
	})

	// A `jmp login` token is minted for the Jumpstarter client, so on a Build API
	// that restricts audiences it would be rejected with a 401. Reusing it would
	// cost a round trip and leave a rejected token in the cache.
	It("ignores a token whose audience the server does not accept", func() {
		apiServer = startAPIServer(issuerServer.URL, "caib-cli")
		external := makeAudienceTestJWT(issuerServer.URL, "jumpstarter-cli")

		token, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).To(HaveOccurred())
		Expect(token).NotTo(Equal(external))
		Expect(readTokenCache()).To(BeNil())
	})

	It("does not overwrite a cached login that still holds a refresh token", func() {
		apiServer = startAPIServer(issuerServer.URL)
		cached := makeValidTestJWT(issuerServer.URL, 1*time.Hour)
		writeTokenCache(TokenCache{
			Token:        cached,
			RefreshToken: "my-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			Issuer:       issuerServer.URL,
		})

		external := makeValidTestJWT(issuerServer.URL, 2*time.Hour)
		token, didAuth, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).NotTo(HaveOccurred())
		// The cached session wins, so the caller must be handed the token later
		// commands will actually send — not the external one we declined to adopt.
		Expect(token).To(Equal(cached))
		Expect(didAuth).To(BeFalse())

		cache := readTokenCache()
		Expect(cache.Token).To(Equal(cached))
		Expect(cache.RefreshToken).To(Equal("my-refresh-token"))
	})

	// A cache we cannot write is no reason to send the user through a browser
	// login: the token was already checked against what this server accepts.
	It("still reuses the token when the cache cannot be written", func() {
		apiServer = startAPIServer(issuerServer.URL)
		// A regular file where the cache directory belongs makes the save fail.
		Expect(os.MkdirAll(filepath.Join(tempDir, ".cache"), 0700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(tempDir, ".cache", "caib"), []byte("not a directory"), 0600)).To(Succeed())

		external := makeValidTestJWT(issuerServer.URL, 1*time.Hour)
		token, didAuth, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(external))
		Expect(didAuth).To(BeFalse())
	})

	It("ignores a non-JWT token", func() {
		apiServer = startAPIServer(issuerServer.URL)

		token, _, err := GetTokenWithReauth(context.Background(), apiServer.URL, "not-a-jwt", false)
		Expect(err).To(HaveOccurred())
		Expect(token).To(BeEmpty())
		Expect(readTokenCache()).To(BeNil())
	})

	It("returns no token when the server has OIDC disabled", func() {
		apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		external := makeValidTestJWT(issuerServer.URL, 1*time.Hour)

		token, didAuth, err := GetTokenWithReauth(context.Background(), apiServer.URL, external, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(BeEmpty())
		Expect(didAuth).To(BeFalse())
	})
})
