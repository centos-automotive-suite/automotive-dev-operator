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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const (
	e2eTestNamespacePrefix         = "e2e-test-"
	archARM64                      = "arm64"
	aarch64                        = "aarch64"
	statusRunning                  = "Running"
	tektonTaskPushArtifactRegistry = "push-artifact-registry"
	artifactImageRepo              = "automotive-os-test"
	artifactImageName              = artifactImageRepo + ":latest"
	kindPushNamespace              = "myorg"
	defaultHTTPClientTimeout       = 5 * time.Second
	imageBuildFailureTimeout       = 5 * time.Minute

	caibImageBuildTimeout  = 15 * time.Minute
	caibImageShowTimeout   = 15 * time.Second
	caibImageDeleteTimeout = 30 * time.Second
	caibImageCancelTimeout = 30 * time.Second
	caibImageListTimeout   = 15 * time.Second
	statusTrue             = "true"
)

// Shared state populated lazily via sync.Once and consumed by test lanes.
var (
	testNamespace    string
	registryHost     string
	arch             string
	openShiftCluster bool
	caibServer       string
	caibToken        string
	caibEnv          []string
	portForwardCmd   *exec.Cmd

	operatorOnce  sync.Once
	buildAPIOnce  sync.Once
	registryOnce  sync.Once
	caibCredsOnce sync.Once
	dexOnce       sync.Once

	// Error flags: set when a setup panic is caught so subsequent lanes fail fast.
	operatorSetupErr  error
	buildAPISetupErr  error
	registrySetupErr  error
	caibCredsSetupErr error
	dexSetupErr       error

	// Dex OIDC state (populated by ensureDexOIDC).
	dexEndpoint   string
	dexPortFwdCmd *exec.Cmd
	dexCACert     string
)

// resolveNamespace returns the E2E_NAMESPACE env var if set, otherwise generates a random "e2e-test-<hex>" namespace.
func resolveNamespace() string {
	if ns := os.Getenv("E2E_NAMESPACE"); ns != "" {
		return ns
	}
	suffix, err := utils.GenerateRandomString(4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate random suffix: %v, falling back to timestamp\n", err)
		suffix = time.Now().Format("20060102150405")
	}
	return e2eTestNamespacePrefix + suffix
}

// detectArch returns the ARCH env var if set, otherwise detects the architecture from uname.
func detectArch() string {
	if a := os.Getenv("ARCH"); a != "" {
		return a
	}
	unameCmd := exec.Command("uname", "-m")
	out, _ := utils.Run(unameCmd)
	switch strings.TrimSpace(string(out)) {
	case archARM64, aarch64:
		return archARM64
	default:
		return "amd64"
	}
}

// ensureOperatorDeployed deploys the operator exactly once per test run.
// Every lane calls this in its BeforeAll; the actual work only happens on the first call.
// If the first call panics (e.g. Ginkgo Fail), subsequent callers fail fast via operatorSetupErr.
func ensureOperatorDeployed() {
	operatorOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				operatorSetupErr = fmt.Errorf("operator deployment panicked: %v", r)
				panic(r) // re-panic so the first caller still sees the failure
			}
		}()
		deployOperator()
	})
	if operatorSetupErr != nil {
		Fail("operator deployment failed in a previous step; cannot proceed")
	}
}

func deployOperator() {
	var err error

	openShiftCluster = utils.IsOpenShiftCluster()

	By("scaling down existing operator to stop finalizer reconciliation")
	cmd := exec.Command("kubectl", "scale", "deployment", "ado-operator",
		"-n", testNamespace, "--replicas=0")
	_, _ = utils.Run(cmd)
	// Give it a moment to stop before we try to strip finalizers
	cmd = exec.Command("kubectl", "wait", "deployment/ado-operator",
		"-n", testNamespace, "--for=jsonpath={.status.readyReplicas}=0", "--timeout=30s")
	_, _ = utils.Run(cmd)

	By("removing namespace if it exists")
	utils.CleanupNamespace(testNamespace)

	By("creating test namespace")
	cmd = exec.Command("kubectl", "create", "ns", testNamespace)
	_, _ = utils.Run(cmd)

	By("ensuring namespace has privileged PSA labels")
	for _, label := range []string{
		"pod-security.kubernetes.io/enforce=privileged",
		"pod-security.kubernetes.io/audit=privileged",
		"pod-security.kubernetes.io/warn=privileged",
	} {
		cmd = exec.Command("kubectl", "label", "namespace", testNamespace, label, "--overwrite")
		_, _ = utils.Run(cmd)
	}

	projectImage := fmt.Sprintf("automotive-dev-operator:test-%d", time.Now().Unix())
	deployedImage := utils.PrepareOperatorImage(projectImage, testNamespace)

	By("installing CRDs")
	cmd = exec.Command("make", "install")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("deploying the operator")
	cmd = exec.Command("make", "deploy",
		fmt.Sprintf("IMG=%s", deployedImage),
		fmt.Sprintf("NAMESPACE=%s", testNamespace))
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("waiting for operator deployment to be available")
	cmd = exec.Command("kubectl", "wait", "--for=condition=available",
		"--timeout=10m", "deployment/ado-operator", "-n", testNamespace)
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("applying OperatorConfig")
	raw, readErr := os.ReadFile("config/samples/automotive_v1_operatorconfig.yaml")
	ExpectWithOffset(1, readErr).NotTo(HaveOccurred())
	patched := regexp.MustCompile(`(?m)^(\s*)namespace:\s+\S+`).
		ReplaceAllString(string(raw), fmt.Sprintf("${1}namespace: %s", testNamespace))
	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(patched)
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("waiting for Build API deployment to be created and available")
	EventuallyWithOffset(1, func() error {
		cmd = exec.Command("kubectl", "get", "deployment", "ado-build-api",
			"-n", testNamespace, "-o", "jsonpath={.status.availableReplicas}")
		output, getErr := utils.Run(cmd)
		if getErr != nil {
			return getErr
		}
		if strings.TrimSpace(string(output)) != "1" {
			return fmt.Errorf("ado-build-api not yet available, replicas: %q", string(output))
		}
		return nil
	}, 8*time.Minute, 5*time.Second).Should(Succeed(), "Build API deployment did not become available")
}

// ensureRegistryConfigured patches the OperatorConfig for registry access
// and applies cluster-specific Tekton task patches. Runs once per test run.
func ensureRegistryConfigured() {
	registryOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				registrySetupErr = fmt.Errorf("registry configuration panicked: %v", r)
				panic(r)
			}
		}()
		setupRegistry()
	})
	if registrySetupErr != nil {
		Fail("registry configuration failed in a previous step; cannot proceed")
	}
}

func setupRegistry() {
	var err error

	By("patching OperatorConfig for registry")
	patch := fmt.Sprintf(`{"spec":{"osBuilds":{"clusterRegistryRoute":"%s:5000","insecureRegistry":true}}}`, registryHost)
	cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
		"-n", testNamespace, "--type=merge",
		"-p", patch)
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("waiting for " + tektonTaskPushArtifactRegistry + " Task to be created")
	waitForPushTask := func() error {
		taskCmd := exec.Command("kubectl", "get", "task", tektonTaskPushArtifactRegistry, "-n", testNamespace)
		_, taskErr := utils.Run(taskCmd)
		return taskErr
	}
	EventuallyWithOffset(1, waitForPushTask, 2*time.Minute, 5*time.Second).Should(Succeed(),
		tektonTaskPushArtifactRegistry+" Task was not created in time")

	if openShiftCluster {
		patchForOpenShift()
	} else {
		patchForKind()
	}
}

func patchForOpenShift() {
	var err error

	By("patching " + tektonTaskPushArtifactRegistry + " Task for OpenShift (OCI referrers compat)")
	cmd := exec.Command("kubectl", "annotate", "task", tektonTaskPushArtifactRegistry,
		"-n", testNamespace, "automotive.sdv.cloud.redhat.com/unmanaged=true", "--overwrite")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	err = utils.PatchTektonTaskStep(testNamespace, tektonTaskPushArtifactRegistry, 0,
		map[string]string{
			"--image-spec v1.1":                    "--image-spec v1.0",
			`oras" attach "${ORAS_EXTRA_ARGS[@]}"`: `oras" attach --distribution-spec v1.1-referrers-tag "${ORAS_EXTRA_ARGS[@]}"`,
		}, nil)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("pre-creating artifact ImageStream on OpenShift")
	cmd = exec.Command("oc", "create", "imagestream", artifactImageRepo, "-n", testNamespace)
	_, _ = utils.Run(cmd)
}

func patchForKind() {
	var err error

	By("patching " + tektonTaskPushArtifactRegistry + " Task for Kind (runAsUser 0)")
	cmd := exec.Command("kubectl", "annotate", "task", tektonTaskPushArtifactRegistry,
		"-n", testNamespace, "automotive.sdv.cloud.redhat.com/unmanaged=true", "--overwrite")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	err = utils.PatchTektonTaskStep(testNamespace, tektonTaskPushArtifactRegistry, 0,
		nil,
		map[string]any{"securityContext": map[string]any{"runAsUser": 0}})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

// ensureBuildAPIAccess sets up access to the Build API (route on OpenShift,
// port-forward on Kind). Runs once per test run.
func ensureBuildAPIAccess() {
	buildAPIOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				buildAPISetupErr = fmt.Errorf("Build API access setup panicked: %v", r)
				panic(r)
			}
		}()
		if openShiftCluster {
			setupBuildAPIRoute()
		} else {
			setupBuildAPIPortForward()
		}
	})
	if buildAPISetupErr != nil {
		Fail("Build API access setup failed in a previous step; cannot proceed")
	}
}

func setupBuildAPIRoute() {
	By("waiting for Build API route")
	EventuallyWithOffset(1, func() string {
		caibServer = utils.GetBuildAPIURL(testNamespace)
		return caibServer
	}, 2*time.Minute, 5*time.Second).ShouldNot(BeEmpty())

	httpClient := newInsecureHTTPClient()

	By("waiting for Build API route to respond")
	waitForBuildAPI := func() error {
		resp, httpErr := httpClient.Get(caibServer + "/v1/healthz")
		if httpErr != nil {
			return httpErr
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		return fmt.Errorf("unexpected status %d from Build API /v1/healthz", resp.StatusCode)
	}
	EventuallyWithOffset(1, waitForBuildAPI, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"Build API route did not become ready")

	By("waiting for Build API config endpoint to be ready (OperatorConfig processed)")
	waitForConfig := func() error {
		resp, httpErr := httpClient.Get(caibServer + "/v1/config")
		if httpErr != nil {
			return httpErr
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			return fmt.Errorf("Build API /v1/config still returning 503 (OperatorConfig not yet ready)")
		}
		return nil
	}
	EventuallyWithOffset(1, waitForConfig, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"Build API config endpoint did not become ready")
}

func setupBuildAPIPortForward() {
	By("ensuring port 8080 is free before starting port-forward")
	if conn, dialErr := net.DialTimeout("tcp", "localhost:8080", 500*time.Millisecond); dialErr == nil {
		_ = conn.Close()
		Fail("port 8080 is already in use; cannot set up port-forward to Build API")
	}

	By("setting up port-forward to Build API")
	portForwardCmd = exec.Command("kubectl", "port-forward",
		"-n", testNamespace, "svc/ado-build-api", "8080:8080")
	err := portForwardCmd.Start()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	httpClient := newInsecureHTTPClient()

	By("waiting for Build API to respond on port-forward")
	waitForBuildAPI := func() error {
		resp, httpErr := httpClient.Get("http://localhost:8080/v1/healthz")
		if httpErr != nil {
			return httpErr
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		return fmt.Errorf("unexpected status %d from Build API /v1/healthz", resp.StatusCode)
	}
	EventuallyWithOffset(1, waitForBuildAPI, 30*time.Second, 1*time.Second).Should(Succeed(),
		"Build API on localhost:8080 did not become ready")

	By("waiting for Build API config endpoint to be ready (OperatorConfig processed)")
	waitForConfig := func() error {
		resp, httpErr := httpClient.Get("http://localhost:8080/v1/config")
		if httpErr != nil {
			return httpErr
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			return fmt.Errorf("Build API /v1/config still returning 503 (OperatorConfig not yet ready)")
		}
		return nil
	}
	EventuallyWithOffset(1, waitForConfig, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"Build API config endpoint did not become ready")

	caibServer = "http://localhost:8080"
}

// ensureCaibCredentials creates the caib service account, token, and env vars.
// Runs once per test run.
func ensureCaibCredentials() {
	caibCredsOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				caibCredsSetupErr = fmt.Errorf("caib credentials setup panicked: %v", r)
				panic(r)
			}
		}()
		setupCaibCredentials()
	})
	if caibCredsSetupErr != nil {
		Fail("caib credentials setup failed in a previous step; cannot proceed")
	}
}

func setupCaibCredentials() {
	var err error

	By("creating service account and token")
	cmd := exec.Command("kubectl", "create", "serviceaccount", "caib",
		"-n", testNamespace, "--dry-run=client", "-o", "yaml")
	saYAML, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(saYAML))
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("creating caib token")
	cmd = exec.Command("kubectl", "create", "token", "caib",
		"-n", testNamespace, "--duration=1h")
	tokenOutput, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	caibToken = strings.TrimSpace(string(tokenOutput))
	ExpectWithOffset(1, caibToken).NotTo(BeEmpty(), "CAIB_TOKEN must not be empty")

	By("setting caib environment variables")
	caibEnv = append([]string{}, os.Environ()...)
	setEnv := func(key, value string) {
		prefix := key + "="
		filtered := caibEnv[:0]
		for _, entry := range caibEnv {
			if !strings.HasPrefix(entry, prefix) {
				filtered = append(filtered, entry)
			}
		}
		caibEnv = append(filtered, prefix+value)
	}
	setEnv("CAIB_TOKEN", caibToken)
	setEnv("CAIB_SERVER", caibServer)
	if openShiftCluster {
		setEnv("CAIB_INSECURE", statusTrue)
	}

	By("setting registry credentials")
	registryUsername := os.Getenv("REGISTRY_USERNAME")
	registryPassword := os.Getenv("REGISTRY_PASSWORD")
	if openShiftCluster {
		ocUser, ocErr := utils.Run(exec.Command("oc", "whoami"))
		ExpectWithOffset(1, ocErr).NotTo(HaveOccurred())
		ocToken, ocErr := utils.Run(exec.Command("oc", "whoami", "-t"))
		ExpectWithOffset(1, ocErr).NotTo(HaveOccurred())
		registryUsername = strings.TrimSpace(string(ocUser))
		registryPassword = strings.TrimSpace(string(ocToken))
	} else if registryUsername == "" {
		registryUsername = "kind"
		registryPassword = "kind"
	}
	if registryUsername != "" {
		setEnv("REGISTRY_USERNAME", registryUsername)
	}
	if registryPassword != "" {
		setEnv("REGISTRY_PASSWORD", registryPassword)
	}
}

// isDexDeployed returns true when the Dex deployment exists in the dex namespace.
func isDexDeployed() bool {
	cmd := exec.Command("kubectl", "get", "deployment", "dex", "-n", "dex", "--no-headers")
	_, err := utils.Run(cmd)
	return err == nil
}

// ensureDexOIDC configures Dex-based OIDC authentication for the Build API.
// It sets up a port-forward to Dex, patches OperatorConfig with Dex JWT settings,
// and waits for the Build API to serve the OIDC config. Runs once per test run.
func ensureDexOIDC() {
	dexOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				dexSetupErr = fmt.Errorf("Dex OIDC setup panicked: %v", r)
				panic(r)
			}
		}()
		setupDexOIDC()
	})
	if dexSetupErr != nil {
		Fail("Dex OIDC setup failed in a previous step; cannot proceed")
	}
}

func setupDexOIDC() {
	By("verifying Dex deployment is available")
	cmd := exec.Command("kubectl", "wait", "--for=condition=available",
		"--timeout=2m", "deployment/dex", "-n", "dex")
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("reading Dex CA certificate from ConfigMap")
	cmd = exec.Command("kubectl", "get", "configmap", "dex-ca", "-n", "dex",
		"-o", "jsonpath={.data.ca\\.crt}")
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	dexCACert = strings.TrimSpace(string(output))
	ExpectWithOffset(1, dexCACert).NotTo(BeEmpty(), "Dex CA cert not found in dex-ca ConfigMap")

	By("setting up port-forward to Dex")
	setupDexPortForward()

	By("patching OperatorConfig with Dex OIDC configuration")
	patchOperatorConfigWithDex()

	By("waiting for Build API to serve Dex OIDC config")
	waitForOIDCConfig()
}

func setupDexPortForward() {
	dexEndpoint = "https://localhost:5556"

	if conn, dialErr := net.DialTimeout("tcp", "localhost:5556", 500*time.Millisecond); dialErr == nil {
		_ = conn.Close()
		_, _ = fmt.Fprintf(GinkgoWriter, "port 5556 already in use, validating existing Dex endpoint\n")
		validateDexEndpoint()
		return
	}

	dexPortFwdCmd = exec.Command("kubectl", "port-forward",
		"-n", "dex", "svc/dex", "5556:5556")
	err := dexPortFwdCmd.Start()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	validateDexEndpoint()
}

func validateDexEndpoint() {
	httpClient := newInsecureHTTPClient()
	EventuallyWithOffset(2, func() error {
		resp, httpErr := httpClient.Get(dexEndpoint + "/.well-known/openid-configuration")
		if httpErr != nil {
			return httpErr
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Dex OIDC discovery returned %d", resp.StatusCode)
		}
		return nil
	}, 30*time.Second, 1*time.Second).Should(Succeed(), "Dex endpoint did not become ready")
}

func patchOperatorConfigWithDex() {
	escapedCA := strings.ReplaceAll(dexCACert, "\n", "\\n")
	oidcPatch := fmt.Sprintf(
		`{"spec":{"buildAPI":{"authentication":{"clientId":"caib-cli","jwt":[{"issuer":{"url":"https://dex.dex.svc.cluster.local:5556","audiences":["caib-cli"],"certificateAuthority":"%s"},"claimMappings":{"username":{"claim":"name","prefix":"dex:"}}}]}}}}`,
		escapedCA,
	)
	cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
		"-n", testNamespace, "--type=merge", "-p", oidcPatch)
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

func waitForOIDCConfig() {
	httpClient := newInsecureHTTPClient()
	EventuallyWithOffset(1, func() error {
		resp, err := httpClient.Get(caibServer + "/v1/auth/config")
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("/v1/auth/config returned %d, waiting for OIDC config", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "dex.dex.svc.cluster.local") {
			return fmt.Errorf("OIDC config does not contain Dex issuer yet: %s", string(b))
		}
		return nil
	}, 3*time.Minute, 5*time.Second).Should(Succeed(),
		"Build API did not serve Dex OIDC config in time")
}

// getDexToken obtains an OIDC id_token from Dex using the password grant.
func getDexToken() string {
	httpClient := newInsecureHTTPClient()

	data := url.Values{
		"grant_type": {"password"},
		"username":   {"test-user@example.com"},
		"password":   {"password"},
		"client_id":  {"caib-cli"},
		"scope":      {"openid profile email"},
	}

	resp, err := httpClient.PostForm(dexEndpoint+"/token", data)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, resp.StatusCode).To(Equal(http.StatusOK),
		fmt.Sprintf("Dex token request failed (%d): %s", resp.StatusCode, string(body)))

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	err = json.Unmarshal(body, &tokenResp)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, tokenResp.IDToken).NotTo(BeEmpty(), "Dex returned empty id_token")

	return tokenResp.IDToken
}

// clearOIDCConfig removes the authentication block from the OperatorConfig and
// waits for the Build API to reflect the change (404 on /v1/auth/config).
func clearOIDCConfig() {
	cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
		"-n", testNamespace, "--type=merge",
		"-p", `{"spec":{"buildAPI":{"authentication":null}}}`)
	_, _ = utils.Run(cmd)

	client := newInsecureHTTPClient()
	EventuallyWithOffset(1, func() error {
		resp, err := client.Get(caibServer + "/v1/auth/config")
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("expected 404 after clearing OIDC config, got %d", resp.StatusCode)
		}
		return nil
	}, 3*time.Minute, 5*time.Second).Should(Succeed(),
		"Build API did not reflect cleared OIDC config in time")
}

// killPortForwardCmd safely terminates a port-forward process and nils the pointer.
func killPortForwardCmd(cmd **exec.Cmd) {
	if *cmd != nil {
		if (*cmd).Process != nil {
			_ = (*cmd).Process.Kill()
		}
		_ = (*cmd).Wait()
		*cmd = nil
	}
}

// teardownOperator cleans up all test resources. Called from AfterSuite.
func teardownOperator() {
	killPortForwardCmd(&portForwardCmd)
	killPortForwardCmd(&dexPortFwdCmd)

	if testNamespace != "" {
		By("removing test namespace")
		utils.CleanupNamespace(testNamespace)
	}
}

// newInsecureHTTPClient returns an HTTP client that skips TLS verification.
func newInsecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // e2e test
		},
	}
}

// createServiceAccountToken creates a service account in the test namespace and returns a short-lived token.
func createServiceAccountToken(name string) string {
	cmd := exec.Command("kubectl", "create", "serviceaccount", name,
		"-n", testNamespace, "--dry-run=client", "-o", "yaml")
	saYAML, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(saYAML))
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	cmd = exec.Command("kubectl", "create", "token", name,
		"-n", testNamespace, "--duration=30m")
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	token := strings.TrimSpace(string(output))
	ExpectWithOffset(1, token).NotTo(BeEmpty())
	return token
}

// applyImageBuildCR applies an ImageBuild CR and returns a cleanup function that deletes it.
func applyImageBuildCR(name, crYAML string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(crYAML)
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to apply ImageBuild %s", name)
}

// deleteImageBuildCR deletes an ImageBuild CR by name, ignoring not-found errors.
func deleteImageBuildCR(name string) {
	cmd := exec.Command("kubectl", "delete", "imagebuild", name,
		"-n", testNamespace, "--ignore-not-found")
	_, _ = utils.Run(cmd)
}

// waitForImageBuildPhase polls until the ImageBuild reaches the given phase or times out.
func waitForImageBuildPhase(name, expectedPhase string, timeout time.Duration) {
	EventuallyWithOffset(1, func() error {
		cmd := exec.Command("kubectl", "get", "imagebuild", name,
			"-n", testNamespace, "-o", "jsonpath={.status.phase}")
		output, err := utils.Run(cmd)
		if err != nil {
			return err
		}
		phase := strings.TrimSpace(string(output))
		if phase != expectedPhase {
			return fmt.Errorf("ImageBuild %s phase is %q, want %q", name, phase, expectedPhase)
		}
		return nil
	}, timeout, 2*time.Second).Should(Succeed())
}

// waitForResourceDeleted polls until kubectl get --ignore-not-found returns no resource.
func waitForResourceDeleted(resourceType, name string, timeout time.Duration) {
	EventuallyWithOffset(1, func() error {
		cmd := exec.Command("kubectl", "get", resourceType, name,
			"-n", testNamespace, "--ignore-not-found", "-o", "name")
		output, err := utils.Run(cmd)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(output)) == "" {
			return nil
		}
		return fmt.Errorf("%s %s still exists", resourceType, name)
	}, timeout, 2*time.Second).Should(Succeed())
}

// waitForImageBuildDeleted polls until the ImageBuild CR no longer exists.
func waitForImageBuildDeleted(name string, timeout time.Duration) {
	waitForResourceDeleted("imagebuild", name, timeout)
}

// getImageBuildCRName returns the ImageBuild CR name for a build name prefix.
func getImageBuildCRName(prefix string) string {
	cmd := exec.Command("kubectl", "get", "imagebuild", "-n", testNamespace,
		"-o", "jsonpath={.items[*].metadata.name}")
	out, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, name := range strings.Fields(string(out)) {
		if strings.HasPrefix(name, prefix+"-") {
			return name
		}
	}
	ExpectWithOffset(1, false).To(BeTrue(),
		fmt.Sprintf("no ImageBuild with prefix %q in namespace %s", prefix, testNamespace))
	return ""
}

// operatorConfigAIBImage returns the configured automotive-image-builder image.
// It reads from OperatorConfig first, then falls back to the Task spec default
// so the test does not need to track the version string independently.
func operatorConfigAIBImage() string {
	cmd := exec.Command("kubectl", "get", "operatorconfig", "config",
		"-n", testNamespace,
		"-o", "jsonpath={.spec.images.automotiveImageBuilder}")
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	if img := strings.TrimSpace(string(output)); img != "" {
		return img
	}
	cmd = exec.Command("kubectl", "get", "task", "build-automotive-image",
		"-n", testNamespace,
		"-o", `jsonpath={.spec.params[?(@.name=="automotive-image-builder")].default}`)
	output, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	img := strings.TrimSpace(string(output))
	ExpectWithOffset(1, img).NotTo(BeEmpty(), "automotive-image-builder param default not found in task spec")
	return img
}

func pipelineRunNameForBuild(buildName string) (string, error) {
	cmd := exec.Command("kubectl", "get", "pipelinerun",
		"-l", fmt.Sprintf("automotive.sdv.cloud.redhat.com/imagebuild-name=%s", buildName),
		"-n", testNamespace, "-o", "jsonpath={.items[0].metadata.name}")
	output, err := utils.Run(cmd)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(output))
	if name == "" {
		return "", fmt.Errorf("no PipelineRun found for ImageBuild %s", buildName)
	}
	return name, nil
}

// waitForBuildTaskRunAIBImage waits for a build TaskRun to use the expected AIB image.
func waitForBuildTaskRunAIBImage(buildName, expectedImage string, timeout time.Duration) {
	EventuallyWithOffset(1, func() error {
		prName, err := pipelineRunNameForBuild(buildName)
		if err != nil {
			return err
		}
		cmd := exec.Command("kubectl", "get", "taskrun",
			"-n", testNamespace,
			"-l", fmt.Sprintf("tekton.dev/pipelineRun=%s,tekton.dev/pipelineTask=build-image", prName),
			"-o", `jsonpath={.items[0].spec.params[?(@.name=="automotive-image-builder")].value}`)
		output, err := utils.Run(cmd)
		if err != nil {
			return err
		}
		value := strings.TrimSpace(string(output))
		if value == "" {
			cmd = exec.Command("kubectl", "get", "task", "build-automotive-image",
				"-n", testNamespace,
				"-o", `jsonpath={.spec.params[?(@.name=="automotive-image-builder")].default}`)
			output, err = utils.Run(cmd)
			if err != nil {
				return err
			}
			value = strings.TrimSpace(string(output))
		}
		if value == "" {
			return fmt.Errorf("automotive-image-builder image not yet available for build %s", buildName)
		}
		if value != expectedImage {
			return fmt.Errorf("automotive-image-builder is %q, want %q", value, expectedImage)
		}
		return nil
	}, timeout, 5*time.Second).Should(Succeed())
}

// waitForPipelineRun polls until a PipelineRun is created for the given ImageBuild name and returns its name.
func waitForPipelineRun(buildName string, timeout time.Duration) string {
	var prName string
	EventuallyWithOffset(1, func() error {
		cmd := exec.Command("kubectl", "get", "pipelinerun",
			"-l", fmt.Sprintf("automotive.sdv.cloud.redhat.com/imagebuild-name=%s", buildName),
			"-n", testNamespace, "-o", "jsonpath={.items[0].metadata.name}")
		output, err := utils.Run(cmd)
		if err != nil {
			return err
		}
		name := strings.TrimSpace(string(output))
		if name == "" {
			return fmt.Errorf("no PipelineRun found for ImageBuild %s", buildName)
		}
		prName = name
		return nil
	}, timeout, 2*time.Second).Should(Succeed())
	return prName
}

// minimalImageBuildCR returns a minimal ImageBuild CR YAML for testing.
func minimalImageBuildCR(name string) string {
	return fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: ImageBuild
metadata:
  name: %s
  namespace: %s
spec:
  architecture: %s
  aib:
    distro: autosd
    target: qemu
    mode: image
    manifest: |
      name: %s
`, name, testNamespace, arch, name)
}

// runCaibCommand executes a caib CLI command with the shared caibEnv and returns its output.
func runCaibCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := utils.NewCaibCommand(ctx, caibEnv, args...)
	return utils.RunSafe(cmd)
}

// createBuildViaCaib creates a build via `caib image build-dev` and returns the server-assigned build name.
func createBuildViaCaib(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), caibImageBuildTimeout)
	defer cancel()

	output, err := runCaibCommand(ctx,
		"image", "build-dev",
		caibBuildManifest,
		"--name", name,
		"--arch", arch,
		"--mode", "image",
		"--internal-registry",
		"--wait=false",
	)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("caib image build-dev failed:\n%s", string(output)))

	buildName := parseCaibBuildName(string(output))
	ExpectWithOffset(1, buildName).NotTo(BeEmpty(), "could not parse build name from caib output: %s", string(output))
	return buildName
}

// parseCaibBuildName extracts the build name from caib output like "Build <name> accepted: ...".
func parseCaibBuildName(output string) string {
	re := regexp.MustCompile(`Build\s+(\S+)\s+accepted`)
	if m := re.FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	return ""
}

// showBuildViaCaib runs `caib image show` and returns the parsed JSON output.
func showBuildViaCaib(name string) map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), caibImageShowTimeout)
	defer cancel()

	output, err := runCaibCommand(ctx,
		"image", "show", name,
		"--output-format", "json")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("caib image show %s failed:\n%s", name, string(output)))

	var result map[string]interface{}
	ExpectWithOffset(1, json.Unmarshal(output, &result)).To(Succeed(),
		fmt.Sprintf("failed to parse caib show output: %s", string(output)))
	return result
}

// deleteBuildViaCaib deletes a build via `caib image delete`.
func deleteBuildViaCaib(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), caibImageDeleteTimeout)
	defer cancel()

	output, err := runCaibCommand(ctx, "image", "delete", name)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("caib image delete %s failed:\n%s", name, string(output)))
}

// listBuildsViaCaib runs `caib image list` and returns stdout.
func listBuildsViaCaib() string {
	ctx, cancel := context.WithTimeout(context.Background(), caibImageListTimeout)
	defer cancel()

	output, err := runCaibCommand(ctx, "image", "list")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		fmt.Sprintf("caib image list failed:\n%s", string(output)))
	return string(output)
}

// verifyCaibList asserts that a build with the given name prefix appears as Completed in caib image list.
func verifyCaibList(caibBuildName string) {
	output := listBuildsViaCaib()
	lines := strings.Split(output, "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(line, caibBuildName) {
			Expect(line).To(ContainSubstring("Completed"))
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(),
		fmt.Sprintf("build %q not found in caib list output:\n%s", caibBuildName, output))
}
