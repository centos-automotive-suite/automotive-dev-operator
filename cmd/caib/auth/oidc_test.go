package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

// makeTestJWT creates an unsigned JWT with the given claims for testing.
func makeTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + "."
}

func makeValidTestJWT(iss string, expiresIn time.Duration) string {
	return makeTestJWT(map[string]interface{}{
		"sub": "test-user",
		"iss": iss,
		"exp": float64(time.Now().Add(expiresIn).Unix()),
		"iat": float64(time.Now().Unix()),
	})
}

func makeExpiredTestJWT(iss string) string {
	return makeTestJWT(map[string]interface{}{
		"sub": "test-user",
		"iss": iss,
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
		"iat": float64(time.Now().Add(-2 * time.Hour).Unix()),
	})
}

var _ = Describe("IsTokenValid", func() {
	var oidcAuth *OIDCAuth

	BeforeEach(func() {
		oidcAuth = &OIDCAuth{}
	})

	It("should return true for a valid non-expired token", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		Expect(oidcAuth.IsTokenValid(token)).To(BeTrue())
	})

	It("should return false for an expired token", func() {
		token := makeExpiredTestJWT("https://issuer.example.com")
		Expect(oidcAuth.IsTokenValid(token)).To(BeFalse())
	})

	It("should return false for a malformed token", func() {
		Expect(oidcAuth.IsTokenValid("not-a-jwt")).To(BeFalse())
	})

	It("should return false for an empty token", func() {
		Expect(oidcAuth.IsTokenValid("")).To(BeFalse())
	})

	It("should return true for a token without exp claim", func() {
		token := makeTestJWT(map[string]interface{}{
			"sub": "user1",
			"iss": "https://issuer.example.com",
		})
		Expect(oidcAuth.IsTokenValid(token)).To(BeTrue())
	})
})

var _ = Describe("NewOIDCAuth", func() {
	It("should return nil when issuerURL is empty", func() {
		Expect(NewOIDCAuth("", "client-id", nil, false)).To(BeNil())
	})

	It("should return nil when clientID is empty", func() {
		Expect(NewOIDCAuth("https://issuer.example.com", "", nil, false)).To(BeNil())
	})

	It("should use default scopes with offline_access when none provided", func() {
		auth := NewOIDCAuth("https://issuer.example.com", "client-id", nil, false)
		Expect(auth).NotTo(BeNil())
		Expect(auth.config.Scopes).To(Equal([]string{"openid", "profile", "email", "offline_access"}))
	})

	It("should use provided scopes when specified", func() {
		scopes := []string{"openid", "custom"}
		auth := NewOIDCAuth("https://issuer.example.com", "client-id", scopes, false)
		Expect(auth).NotTo(BeNil())
		Expect(auth.config.Scopes).To(Equal([]string{"openid", "custom"}))
	})
})

var _ = Describe("Token cache save/load", func() {
	var tempDir string
	var originalHome string
	var oidcAuth *OIDCAuth

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-oidc-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())

		cachePath := filepath.Join(tempDir, tokenCacheDir, tokenCacheFile)
		oidcAuth = &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: "https://issuer.example.com",
				ClientID:  "test-client",
			},
			cachePath: cachePath,
		}
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
	})

	It("should save and load a token with refresh token", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		err := oidcAuth.saveTokenCache(token, "my-refresh-token")
		Expect(err).NotTo(HaveOccurred())

		err = oidcAuth.loadTokenCache()
		Expect(err).NotTo(HaveOccurred())
		Expect(oidcAuth.tokenCache).NotTo(BeNil())
		Expect(oidcAuth.tokenCache.Token).To(Equal(token))
		Expect(oidcAuth.tokenCache.RefreshToken).To(Equal("my-refresh-token"))
		Expect(oidcAuth.tokenCache.Issuer).To(Equal("https://issuer.example.com"))
	})

	It("should save and load a token without refresh token", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		err := oidcAuth.saveTokenCache(token, "")
		Expect(err).NotTo(HaveOccurred())

		err = oidcAuth.loadTokenCache()
		Expect(err).NotTo(HaveOccurred())
		Expect(oidcAuth.tokenCache.RefreshToken).To(BeEmpty())
	})

	It("should reject cache when issuer doesn't match", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		Expect(oidcAuth.saveTokenCache(token, "rt")).To(Succeed())

		oidcAuth.config.IssuerURL = "https://other-issuer.example.com"
		err := oidcAuth.loadTokenCache()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})

	It("should return error when cache file doesn't exist", func() {
		err := oidcAuth.loadTokenCache()
		Expect(err).To(HaveOccurred())
	})

	It("should set correct file permissions on cache file", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		Expect(oidcAuth.saveTokenCache(token, "rt")).To(Succeed())

		info, err := os.Stat(oidcAuth.cachePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0600)))
	})

	It("should preserve refresh_token in JSON serialization", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		Expect(oidcAuth.saveTokenCache(token, "my-refresh")).To(Succeed())

		data, err := os.ReadFile(oidcAuth.cachePath)
		Expect(err).NotTo(HaveOccurred())

		var raw map[string]interface{}
		Expect(json.Unmarshal(data, &raw)).To(Succeed())
		Expect(raw["refresh_token"]).To(Equal("my-refresh"))
	})

	It("should omit refresh_token from JSON when empty", func() {
		token := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		Expect(oidcAuth.saveTokenCache(token, "")).To(Succeed())

		data, err := os.ReadFile(oidcAuth.cachePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).NotTo(ContainSubstring("refresh_token"))
	})
})

var _ = Describe("LoadTokenCache (exported)", func() {
	var tempDir string
	var originalHome string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-load-cache-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
	})

	It("should return error when no cache file exists", func() {
		cache, err := LoadTokenCache()
		Expect(err).To(HaveOccurred())
		Expect(cache).To(BeNil())
	})

	It("should load cache with refresh token", func() {
		cacheDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())

		cache := TokenCache{
			Token:        "access-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			Issuer:       "https://issuer.example.com",
		}
		data, err := json.Marshal(cache)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(cacheDir, tokenCacheFile), data, 0600)).To(Succeed())

		loaded, err := LoadTokenCache()
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded).NotTo(BeNil())
		Expect(loaded.Token).To(Equal("access-token"))
		Expect(loaded.RefreshToken).To(Equal("refresh-token"))
		Expect(loaded.Issuer).To(Equal("https://issuer.example.com"))
	})

	It("should load cache without refresh token", func() {
		cacheDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())

		cache := TokenCache{
			Token:     "access-token",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Issuer:    "https://issuer.example.com",
		}
		data, err := json.Marshal(cache)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(cacheDir, tokenCacheFile), data, 0600)).To(Succeed())

		loaded, err := LoadTokenCache()
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded.RefreshToken).To(BeEmpty())
	})

	It("should return error for invalid JSON", func() {
		cacheDir := filepath.Join(tempDir, tokenCacheDir)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(cacheDir, tokenCacheFile), []byte("bad json"), 0600)).To(Succeed())

		cache, err := LoadTokenCache()
		Expect(err).To(HaveOccurred())
		Expect(cache).To(BeNil())
	})
})

var _ = Describe("refreshAccessToken", func() {
	var (
		tokenServer *httptest.Server
		oidcAuth    *OIDCAuth
	)

	AfterEach(func() {
		if tokenServer != nil {
			tokenServer.Close()
		}
	})

	It("should return new tokens on successful refresh", func() {
		newAccessToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).To(Equal("POST"))
			Expect(r.FormValue("grant_type")).To(Equal("refresh_token"))
			Expect(r.FormValue("refresh_token")).To(Equal("old-refresh-token"))
			Expect(r.FormValue("client_id")).To(Equal("test-client"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  newAccessToken,
				"refresh_token": "new-refresh-token",
				"expires_in":    3600,
			})
		}))

		oidcAuth = &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: "https://issuer.example.com",
				ClientID:  "test-client",
			},
		}

		ctx := context.Background()
		resp, err := oidcAuth.refreshAccessToken(ctx, tokenServer.URL, "old-refresh-token")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AccessToken).To(Equal(newAccessToken))
		Expect(resp.RefreshToken).To(Equal("new-refresh-token"))
	})

	It("should accept id_token when access_token is absent", func() {
		idToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id_token":   idToken,
				"expires_in": 3600,
			})
		}))

		oidcAuth = &OIDCAuth{
			config: OIDCConfig{ClientID: "test-client"},
		}

		ctx := context.Background()
		resp, err := oidcAuth.refreshAccessToken(ctx, tokenServer.URL, "rt")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.IDToken).To(Equal(idToken))
	})

	It("should return error when server returns neither access_token nor id_token", func() {
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"expires_in": 3600,
			})
		}))

		oidcAuth = &OIDCAuth{
			config: OIDCConfig{ClientID: "test-client"},
		}

		ctx := context.Background()
		_, err := oidcAuth.refreshAccessToken(ctx, tokenServer.URL, "rt")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("neither id_token nor access_token"))
	})

	It("should return error when server returns non-200", func() {
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}))

		oidcAuth = &OIDCAuth{
			config: OIDCConfig{ClientID: "test-client"},
		}

		ctx := context.Background()
		_, err := oidcAuth.refreshAccessToken(ctx, tokenServer.URL, "expired-rt")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("token refresh failed"))
	})
})

var _ = Describe("tryRefreshToken", func() {
	var (
		tempDir      string
		originalHome string
		oidcServer   *httptest.Server
		oidcAuth     *OIDCAuth
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-try-refresh-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
		if oidcServer != nil {
			oidcServer.Close()
		}
	})

	It("should refresh token and save to cache", func() {
		var newAccessToken string

		oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, ".well-known") {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"authorization_endpoint": oidcServer.URL + "/auth",
					"token_endpoint":         oidcServer.URL + "/token",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  newAccessToken,
				"refresh_token": "rotated-refresh",
				"expires_in":    3600,
			})
		}))

		newAccessToken = makeValidTestJWT(oidcServer.URL, 1*time.Hour)

		cachePath := filepath.Join(tempDir, tokenCacheDir, tokenCacheFile)
		oidcAuth = &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: oidcServer.URL,
				ClientID:  "test-client",
			},
			cachePath: cachePath,
			tokenCache: &TokenCache{
				Token:        "old-expired-token",
				RefreshToken: "old-refresh-token",
				Issuer:       oidcServer.URL,
			},
		}

		ctx := context.Background()
		token, err := oidcAuth.tryRefreshToken(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(newAccessToken))

		err = oidcAuth.loadTokenCache()
		Expect(err).NotTo(HaveOccurred())
		Expect(oidcAuth.tokenCache.Token).To(Equal(newAccessToken))
		Expect(oidcAuth.tokenCache.RefreshToken).To(Equal("rotated-refresh"))
	})

	It("should keep old refresh token when server doesn't return a new one", func() {
		var newAccessToken string

		oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, ".well-known") {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"authorization_endpoint": oidcServer.URL + "/auth",
					"token_endpoint":         oidcServer.URL + "/token",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": newAccessToken,
				"expires_in":   3600,
			})
		}))

		newAccessToken = makeValidTestJWT(oidcServer.URL, 1*time.Hour)

		cachePath := filepath.Join(tempDir, tokenCacheDir, tokenCacheFile)
		oidcAuth = &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: oidcServer.URL,
				ClientID:  "test-client",
			},
			cachePath: cachePath,
			tokenCache: &TokenCache{
				Token:        "old-expired-token",
				RefreshToken: "keep-this-refresh",
				Issuer:       oidcServer.URL,
			},
		}

		ctx := context.Background()
		_, err := oidcAuth.tryRefreshToken(ctx)
		Expect(err).NotTo(HaveOccurred())

		err = oidcAuth.loadTokenCache()
		Expect(err).NotTo(HaveOccurred())
		Expect(oidcAuth.tokenCache.RefreshToken).To(Equal("keep-this-refresh"))
	})
})

var _ = Describe("GetTokenWithStatus", func() {
	var (
		tempDir      string
		originalHome string
		oidcServer   *httptest.Server
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "caib-gettokenwithstatus-test-*")
		Expect(err).NotTo(HaveOccurred())

		originalHome = os.Getenv("HOME")
		Expect(os.Setenv("HOME", tempDir)).To(Succeed())
	})

	AfterEach(func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		_ = os.RemoveAll(tempDir)
		if oidcServer != nil {
			oidcServer.Close()
		}
	})

	It("should return cached token when still valid", func() {
		validToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		cachePath := filepath.Join(tempDir, tokenCacheDir, tokenCacheFile)

		oidcAuth := &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: "https://issuer.example.com",
				ClientID:  "test-client",
			},
			cachePath: cachePath,
		}

		Expect(oidcAuth.saveTokenCache(validToken, "some-refresh")).To(Succeed())

		ctx := context.Background()
		token, fromCache, err := oidcAuth.GetTokenWithStatus(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(validToken))
		Expect(fromCache).To(BeTrue())
	})

	It("should try refresh when cached token is expired and refresh token exists", func() {
		var newToken string

		oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, ".well-known") {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"authorization_endpoint": oidcServer.URL + "/auth",
					"token_endpoint":         oidcServer.URL + "/token",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  newToken,
				"refresh_token": "new-rt",
				"expires_in":    3600,
			})
		}))

		expiredToken := makeExpiredTestJWT(oidcServer.URL)
		newToken = makeValidTestJWT(oidcServer.URL, 1*time.Hour)

		cachePath := filepath.Join(tempDir, tokenCacheDir, tokenCacheFile)
		cacheDir := filepath.Dir(cachePath)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())

		cache := TokenCache{
			Token:        expiredToken,
			RefreshToken: "old-refresh",
			ExpiresAt:    time.Now().Add(-1 * time.Hour),
			Issuer:       oidcServer.URL,
		}
		data, _ := json.Marshal(cache)
		Expect(os.WriteFile(cachePath, data, 0600)).To(Succeed())

		oidcAuth := &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: oidcServer.URL,
				ClientID:  "test-client",
			},
			cachePath: cachePath,
		}

		ctx := context.Background()
		token, fromCache, err := oidcAuth.GetTokenWithStatus(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(newToken))
		Expect(fromCache).To(BeTrue())
	})

	It("should not return token about to expire within 5 minutes as cached", func() {
		var newToken string

		oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, ".well-known") {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"authorization_endpoint": oidcServer.URL + "/auth",
					"token_endpoint":         oidcServer.URL + "/token",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  newToken,
				"refresh_token": "new-rt",
				"expires_in":    3600,
			})
		}))

		almostExpiredToken := makeValidTestJWT(oidcServer.URL, 3*time.Minute)
		newToken = makeValidTestJWT(oidcServer.URL, 1*time.Hour)

		cachePath := filepath.Join(tempDir, tokenCacheDir, tokenCacheFile)
		cacheDir := filepath.Dir(cachePath)
		Expect(os.MkdirAll(cacheDir, 0700)).To(Succeed())

		cache := TokenCache{
			Token:        almostExpiredToken,
			RefreshToken: "my-refresh",
			ExpiresAt:    time.Now().Add(3 * time.Minute),
			Issuer:       oidcServer.URL,
		}
		data, _ := json.Marshal(cache)
		Expect(os.WriteFile(cachePath, data, 0600)).To(Succeed())

		oidcAuth := &OIDCAuth{
			config: OIDCConfig{
				IssuerURL: oidcServer.URL,
				ClientID:  "test-client",
			},
			cachePath: cachePath,
		}

		ctx := context.Background()
		token, fromCache, err := oidcAuth.GetTokenWithStatus(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal(newToken))
		Expect(fromCache).To(BeTrue())
	})
})

var _ = Describe("exchangeCodeForToken", func() {
	var tokenServer *httptest.Server

	AfterEach(func() {
		if tokenServer != nil {
			tokenServer.Close()
		}
	})

	It("should capture refresh_token from token response", func() {
		accessToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.FormValue("grant_type")).To(Equal("authorization_code"))
			Expect(r.FormValue("code")).To(Equal("auth-code"))
			Expect(r.FormValue("code_verifier")).To(Equal("pkce-verifier"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  accessToken,
				"refresh_token": "the-refresh-token",
				"id_token":      "some-id-token",
				"expires_in":    3600,
			})
		}))

		oidcAuth := &OIDCAuth{
			config: OIDCConfig{ClientID: "test-client"},
		}

		ctx := context.Background()
		resp, err := oidcAuth.exchangeCodeForToken(ctx, tokenServer.URL, "auth-code", "http://localhost/callback", "pkce-verifier")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AccessToken).To(Equal(accessToken))
		Expect(resp.RefreshToken).To(Equal("the-refresh-token"))
		Expect(resp.IDToken).To(Equal("some-id-token"))
	})

	It("should succeed without refresh_token in response", func() {
		accessToken := makeValidTestJWT("https://issuer.example.com", 1*time.Hour)
		tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": accessToken,
				"expires_in":   3600,
			})
		}))

		oidcAuth := &OIDCAuth{
			config: OIDCConfig{ClientID: "test-client"},
		}

		ctx := context.Background()
		resp, err := oidcAuth.exchangeCodeForToken(ctx, tokenServer.URL, "code", "http://localhost/callback", "verifier")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.AccessToken).To(Equal(accessToken))
		Expect(resp.RefreshToken).To(BeEmpty())
	})
})
