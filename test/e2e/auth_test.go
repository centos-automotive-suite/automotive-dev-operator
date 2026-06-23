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
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
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
