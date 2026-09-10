/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	"github.com/golang-jwt/jwt/v5"

	caibauth "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const (
	// Refresh tokens seeded into a caib cache. Neither is ever redeemed
	// successfully; they only stand for "this session can renew itself" and
	// "this session cannot".
	liveRefreshToken = "e2e-live-refresh-token"
	deadRefreshToken = "e2e-dead-refresh-token"

	// caibLoginTimeout bounds a `caib login`. Every login these specs drive
	// should return in seconds; the only thing that takes longer is the browser
	// flow, whose own timeout is 5 minutes.
	caibLoginTimeout = 90 * time.Second
)

var _ = Describe("OIDC Authentication", Label("auth"), Ordered, func() {
	var dexAvailable bool

	BeforeAll(func() {
		ensureOperatorDeployed()
		ensureBuildAPIAccess()

		dexAvailable = isDexDeployed()

		if !openShiftCluster && !dexAvailable {
			Skip("auth tests require either OpenShift or Dex; run hack/e2e/setup-dex.sh for Kind")
		}
	})

	AfterAll(func() {
		clearOIDCConfig()
	})

	// -----------------------------------------------------------------
	// OIDC config propagation (runs before any OIDC config is applied)
	// -----------------------------------------------------------------
	Context("Build API OIDC Configuration", func() {
		It("should return 404 when OIDC is not configured", func() {
			client := newInsecureHTTPClient()
			resp, err := client.Get(caibServer + "/v1/auth/config")
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()
			Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		})

		It("should serve OIDC config on /v1/auth/config", func() {
			if dexAvailable {
				ensureDexOIDC()
			} else {
				By("patching OperatorConfig with test OIDC configuration")
				oidcPatch := `{"spec":{"buildAPI":{"authentication":{"clientId":"test-client-id","jwt":[{"issuer":{"url":"https://issuer.example.com","audiences":["test-audience"]},"claimMappings":{"username":{"claim":"preferred_username","prefix":""}}}]}}}}`
				cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
					"-n", testNamespace, "--type=merge", "-p", oidcPatch)
				_, err := utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
			}

			client := newInsecureHTTPClient()
			var authBody string
			EventuallyWithOffset(1, func() error {
				resp, err := client.Get(caibServer + "/v1/auth/config")
				if err != nil {
					return err
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("unexpected status %d from /v1/auth/config", resp.StatusCode)
				}
				b, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					return readErr
				}
				if !strings.Contains(string(b), "jwt") || !strings.Contains(string(b), "clientId") {
					return fmt.Errorf("OIDC config not yet reflected: %s", string(b))
				}
				authBody = string(b)
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed(),
				"Build API did not serve OIDC config in time")
			Expect(authBody).To(And(ContainSubstring("jwt"), ContainSubstring("clientId")))
		})
	})

	// -----------------------------------------------------------------
	// Token validation (Dex OIDC token on Kind, SA TokenReview on OpenShift)
	// -----------------------------------------------------------------
	Context("Token Validation", func() {
		It("should authenticate with valid token", func() {
			var token string
			if dexAvailable {
				ensureDexOIDC()
				token = getDexToken()
			} else {
				By("creating a ServiceAccount token for TokenReview authentication")
				cmd := exec.Command("kubectl", "create", "token", "default",
					"-n", testNamespace, "--duration=10m")
				output, err := utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
				token = strings.TrimSpace(string(output))
			}

			client := newInsecureHTTPClient()
			// Use Eventually when Dex is the issuer: the OIDC authenticator fetches
			// the JWKS in the background after config is applied, so the first
			// validation attempt may fail until the key material is ready.
			if dexAvailable {
				EventuallyWithOffset(1, func() error {
					req, reqErr := http.NewRequest("GET", caibServer+"/v1/builds", nil)
					if reqErr != nil {
						return reqErr
					}
					req.Header.Set("Authorization", "Bearer "+token)
					resp, respErr := client.Do(req)
					if respErr != nil {
						return respErr
					}
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("expected 200 with valid Dex token, got %d", resp.StatusCode)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"Build API did not accept valid Dex token in time")
			} else {
				req, err := http.NewRequest("GET", caibServer+"/v1/builds", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				Expect(err).NotTo(HaveOccurred())
				defer func() { _ = resp.Body.Close() }()
				Expect(resp.StatusCode).To(Equal(http.StatusOK),
					fmt.Sprintf("expected 200 with valid token, got %d", resp.StatusCode))
			}
		})

		It("should reject invalid token with 401", func() {
			client := newInsecureHTTPClient()
			req, err := http.NewRequest("GET", caibServer+"/v1/builds", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer invalid-token-12345")

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()
			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("should reject request without token with 401", func() {
			client := newInsecureHTTPClient()
			req, err := http.NewRequest("GET", caibServer+"/v1/builds", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()
			Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
		})
	})

	// -----------------------------------------------------------------
	// Reuse of a token minted by `jmp login`, read from the Jumpstarter
	// client config. Requires Dex: the token has to be one this Build API
	// actually accepts, or caib would rightly refuse to reuse it.
	// -----------------------------------------------------------------
	Context("Jumpstarter Token Reuse", func() {
		BeforeAll(func() {
			if !dexAvailable {
				Skip("Jumpstarter token reuse tests require Dex; run hack/e2e/setup-dex.sh")
			}
			ensureDexOIDC()
			// Re-assert the Dex issuer rather than trust whatever the previous
			// context left behind: these specs need a server that accepts Dex
			// tokens, and a sibling context may have pointed it elsewhere.
			patchOperatorConfigWithDex()
			waitForOIDCConfig()
		})

		It("should adopt the Jumpstarter token when no caib session is cached", func() {
			jmpToken := getDexToken()
			session := newJumpstarterSession(jmpToken)

			output := session.mustRunCaib("login", caibServer)
			Expect(string(output)).To(ContainSubstring("Reusing the token from your Jumpstarter client config"))

			cache := session.tokenCache()
			Expect(cache.Token).To(Equal(jmpToken))
			Expect(cache.Issuer).To(Equal(dexIssuerURL))
			Expect(cache.RefreshToken).To(BeEmpty(),
				"an adopted token is stored without a refresh token; caib cannot renew it")

			By("running an authenticated command with nothing but the adopted token")
			out, err := session.runCaib("image", "list")
			Expect(err).NotTo(HaveOccurred(), string(out))
		})

		It("should keep a cached session that can still refresh itself", func() {
			jmpToken := getDexToken()
			session := newJumpstarterSession(jmpToken)

			By("seeding a live caib session holding a refresh token")
			cachedToken := craftCachedSessionToken(time.Now().Add(1 * time.Hour))
			session.seedTokenCache(cachedToken, liveRefreshToken, time.Now().Add(1*time.Hour))

			output := session.mustRunCaib("login", caibServer)
			Expect(string(output)).NotTo(ContainSubstring("Reusing the token from your Jumpstarter client config"),
				"a session that can mint new access tokens outranks the Jumpstarter token")

			cache := session.tokenCache()
			Expect(cache.Token).To(Equal(cachedToken))
			Expect(cache.RefreshToken).To(Equal(liveRefreshToken))
		})

		It("should fall back to the Jumpstarter token when the cached session can no longer refresh", func() {
			jmpToken := getDexToken()
			session := newJumpstarterSession(jmpToken)

			By("seeding an expired caib session whose refresh token no longer works")
			session.seedTokenCache(
				craftCachedSessionToken(time.Now().Add(-1*time.Hour)),
				deadRefreshToken,
				time.Now().Add(-1*time.Hour),
			)

			// mustRunCaib caps the run well below caib's own 5-minute browser-login
			// timeout, so a regression that reaches for a browser here fails the
			// spec instead of stalling the lane.
			output := session.mustRunCaib("login", caibServer)
			Expect(string(output)).To(ContainSubstring("Reusing the token from your Jumpstarter client config"))

			cache := session.tokenCache()
			Expect(cache.Token).To(Equal(jmpToken))
			Expect(cache.RefreshToken).To(BeEmpty(),
				"the dead session should have been replaced by the adopted token")
		})
	})

	// -----------------------------------------------------------------
	// Build API health
	// -----------------------------------------------------------------
	Context("Internal JWT Validation", func() {
		It("should have Build API pod running", func() {
			EventuallyWithOffset(1, func() error {
				cmd := exec.Command("kubectl", "get", "pod", "-l", "app.kubernetes.io/component=build-api",
					"-n", testNamespace, "-o", "jsonpath={.items[0].status.phase}")
				output, err := utils.Run(cmd)
				if err != nil {
					return fmt.Errorf("build-api pod not found: %w", err)
				}
				phase := strings.TrimSpace(string(output))
				if phase != statusRunning {
					return fmt.Errorf("build-api pod in %q phase", phase)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	// -----------------------------------------------------------------
	// CA certificate reference via Secret and ConfigMap
	// Requires Dex so that token validation against a real OIDC issuer
	// -----------------------------------------------------------------
	Context("CA Certificate Reference", func() {
		const (
			caSecretName    = "oidc-ca-secret"
			caConfigMapName = "oidc-ca-configmap"
			wrongCASecret   = "oidc-wrong-ca-secret"
		)

		BeforeAll(func() {
			if !dexAvailable {
				Skip("CA certificate reference tests require Dex; run hack/e2e/setup-dex.sh")
			}
		})

		AfterAll(func() {
			for _, name := range []string{caSecretName, wrongCASecret} {
				cmd := exec.Command("kubectl", "delete", "secret", name,
					"-n", testNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
			cmd := exec.Command("kubectl", "delete", "configmap", caConfigMapName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should authenticate tokens when CA is provided via a Secret", func() {
			clearOIDCConfig()

			By("creating Secret with Dex CA certificate")
			cmd := exec.Command("kubectl", "create", "secret", "generic", caSecretName,
				"-n", testNamespace, "--from-literal=ca.crt="+dexCACert)
			_, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("patching OperatorConfig to reference CA from Secret")
			oidcPatch := fmt.Sprintf(
				`{"spec":{"buildAPI":{"authentication":{"clientId":"caib-cli","jwt":[{"issuer":{"url":"https://dex.dex.svc.cluster.local:5556","audiences":["caib-cli"],"certificateAuthoritySecret":{"name":"%s","key":"ca.crt"}},"claimMappings":{"username":{"claim":"name","prefix":"dex:"}}}]}}}}`,
				caSecretName,
			)
			cmd = exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", testNamespace, "--type=merge", "-p", oidcPatch)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verifying a Dex token is accepted")
			token := getDexToken()
			client := newInsecureHTTPClient()
			EventuallyWithOffset(1, func() error {
				req, reqErr := http.NewRequest("GET", caibServer+"/v1/builds", nil)
				if reqErr != nil {
					return reqErr
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, respErr := client.Do(req)
				if respErr != nil {
					return respErr
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("expected 200 with valid Dex token and correct Secret CA, got %d", resp.StatusCode)
				}
				return nil
			}, 3*time.Minute, 5*time.Second).Should(Succeed(),
				"token authentication failed with correct CA from Secret")
		})

		It("should authenticate tokens when CA is provided via a ConfigMap", func() {
			clearOIDCConfig()

			By("creating ConfigMap with Dex CA certificate")
			cmd := exec.Command("kubectl", "create", "configmap", caConfigMapName,
				"-n", testNamespace, "--from-literal=ca.crt="+dexCACert)
			_, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("patching OperatorConfig to reference CA from ConfigMap")
			oidcPatch := fmt.Sprintf(
				`{"spec":{"buildAPI":{"authentication":{"clientId":"caib-cli","jwt":[{"issuer":{"url":"https://dex.dex.svc.cluster.local:5556","audiences":["caib-cli"],"certificateAuthorityConfigMap":{"name":"%s","key":"ca.crt"}},"claimMappings":{"username":{"claim":"name","prefix":"dex:"}}}]}}}}`,
				caConfigMapName,
			)
			cmd = exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", testNamespace, "--type=merge", "-p", oidcPatch)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verifying a Dex token is accepted")
			token := getDexToken()
			client := newInsecureHTTPClient()
			EventuallyWithOffset(1, func() error {
				req, reqErr := http.NewRequest("GET", caibServer+"/v1/builds", nil)
				if reqErr != nil {
					return reqErr
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, respErr := client.Do(req)
				if respErr != nil {
					return respErr
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("expected 200 with valid Dex token and correct ConfigMap CA, got %d", resp.StatusCode)
				}
				return nil
			}, 3*time.Minute, 5*time.Second).Should(Succeed(),
				"token authentication failed with correct CA from ConfigMap")
		})

		It("should reject tokens when the CA reference points to a wrong certificate", func() {
			clearOIDCConfig()

			By("reading kube-root-ca.crt as a CA that does not sign Dex's TLS certificate")
			cmd := exec.Command("kubectl", "get", "configmap", "kube-root-ca.crt",
				"-n", testNamespace, "-o", "jsonpath={.data.ca\\.crt}")
			output, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			wrongCA := strings.TrimSpace(string(output))
			ExpectWithOffset(1, wrongCA).NotTo(BeEmpty())

			By("creating Secret with wrong CA certificate")
			cmd = exec.Command("kubectl", "create", "secret", "generic", wrongCASecret,
				"-n", testNamespace, "--from-literal=ca.crt="+wrongCA)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("patching OperatorConfig to reference wrong CA from Secret")
			oidcPatch := fmt.Sprintf(
				`{"spec":{"buildAPI":{"authentication":{"clientId":"caib-cli","jwt":[{"issuer":{"url":"https://dex.dex.svc.cluster.local:5556","audiences":["caib-cli"],"certificateAuthoritySecret":{"name":"%s","key":"ca.crt"}},"claimMappings":{"username":{"claim":"name","prefix":"dex:"}}}]}}}}`,
				wrongCASecret,
			)
			cmd = exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", testNamespace, "--type=merge", "-p", oidcPatch)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verifying a Dex token is rejected due to TLS verification failure")
			token := getDexToken()
			client := newInsecureHTTPClient()
			EventuallyWithOffset(1, func() error {
				req, reqErr := http.NewRequest("GET", caibServer+"/v1/builds", nil)
				if reqErr != nil {
					return reqErr
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, respErr := client.Do(req)
				if respErr != nil {
					return respErr
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusUnauthorized {
					return fmt.Errorf("expected 401 with wrong CA, got %d", resp.StatusCode)
				}
				return nil
			}, 3*time.Minute, 5*time.Second).Should(Succeed(),
				"token authentication should have been rejected with wrong CA")
		})
	})
})

// jumpstarterSession is an isolated home for one `caib login`: caib's config
// directory, its token cache, and the Jumpstarter client config all live under a
// per-spec temp dir. Specs can seed a cache and read back what caib wrote without
// touching the real ~/.config of whoever runs the suite.
type jumpstarterSession struct {
	cachePath string
	env       []string
}

// newJumpstarterSession lays out that home, storing jmpToken where
// `jmp login` would have left it.
func newJumpstarterSession(jmpToken string) *jumpstarterSession {
	root := GinkgoT().TempDir()
	configHome := filepath.Join(root, "config")
	cacheHome := filepath.Join(root, "cache")
	jmpHome := filepath.Join(root, "jumpstarter")
	stubBin := filepath.Join(root, "bin")

	ExpectWithOffset(1, os.MkdirAll(filepath.Join(jmpHome, "clients"), 0o700)).To(Succeed())
	ExpectWithOffset(1, os.MkdirAll(stubBin, 0o700)).To(Succeed())

	writeSessionFile(filepath.Join(jmpHome, "config.yaml"),
		"config:\n  current-client: e2e\n", 0o600)
	writeSessionFile(filepath.Join(jmpHome, "clients", "e2e.yaml"),
		fmt.Sprintf("endpoint: grpc.jumpstarter.example.com:443\ntoken: %s\n", jmpToken), 0o600)

	// caib reaches for a browser via xdg-open when it falls through to a full
	// login. Shadow it with a stub that fails, so a regression cannot open a real
	// window on the machine running the suite.
	writeSessionFile(filepath.Join(stubBin, "xdg-open"), "#!/bin/sh\nexit 1\n", 0o700)

	env := envWithout(os.Environ(),
		"CAIB_TOKEN", "CAIB_SERVER", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
		"JMP_CLIENT_CONFIG_HOME", "PATH")
	env = append(env,
		"XDG_CONFIG_HOME="+configHome,
		"XDG_CACHE_HOME="+cacheHome,
		"JMP_CLIENT_CONFIG_HOME="+jmpHome,
		"CAIB_SERVER="+caibServer,
		"PATH="+stubBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	if openShiftCluster {
		env = append(env, "CAIB_INSECURE="+statusTrue)
	}

	return &jumpstarterSession{
		cachePath: filepath.Join(cacheHome, "caib", tokenCacheFileName),
		env:       env,
	}
}

// seedTokenCache writes the token cache a previous caib login would have left.
func (s *jumpstarterSession) seedTokenCache(token, refreshToken string, expiresAt time.Time) {
	ExpectWithOffset(1, os.MkdirAll(filepath.Dir(s.cachePath), 0o700)).To(Succeed())
	data, err := json.Marshal(caibauth.TokenCache{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Issuer:       dexIssuerURL,
	})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, os.WriteFile(s.cachePath, data, 0o600)).To(Succeed())
}

// tokenCache reads back the cache caib left behind.
func (s *jumpstarterSession) tokenCache() caibauth.TokenCache {
	data, err := os.ReadFile(s.cachePath)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "caib wrote no token cache at "+s.cachePath)
	var cache caibauth.TokenCache
	ExpectWithOffset(1, json.Unmarshal(data, &cache)).To(Succeed())
	return cache
}

// runCaib invokes the CLI against this session's isolated home.
func (s *jumpstarterSession) runCaib(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), caibLoginTimeout)
	defer cancel()

	output, err := utils.RunSafe(utils.NewCaibCommand(ctx, s.env, args...))
	appendCaibCommandLog(args, output, err)
	if ctx.Err() != nil {
		return output, fmt.Errorf("caib %s did not finish within %s, which is what a fallback to the "+
			"browser login flow looks like: %w", strings.Join(args, " "), caibLoginTimeout, ctx.Err())
	}
	return output, err
}

// mustRunCaib is runCaib with the command required to succeed.
func (s *jumpstarterSession) mustRunCaib(args ...string) []byte {
	output, err := s.runCaib(args...)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), string(output))
	return output
}

// craftCachedSessionToken builds the access token of a previously cached caib
// session. caib only reads its claims to decide whether the session is still
// usable — the token is never sent to the Build API on the paths these specs
// exercise — so it needs no signature Dex would recognise.
func craftCachedSessionToken(expiry time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": dexIssuerURL,
		"aud": dexClientID,
		"sub": "e2e-cached-session",
		"iat": time.Now().Unix(),
		"exp": expiry.Unix(),
	})
	signed, err := token.SignedString([]byte("e2e-cached-session"))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return signed
}

// envWithout returns env with every assignment of the named variables dropped.
func envWithout(env []string, names ...string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		drop := false
		for _, name := range names {
			if strings.HasPrefix(entry, name+"=") {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, entry)
		}
	}
	return kept
}

func writeSessionFile(path, content string, mode os.FileMode) {
	ExpectWithOffset(2, os.WriteFile(path, []byte(content), mode)).To(Succeed())
}
