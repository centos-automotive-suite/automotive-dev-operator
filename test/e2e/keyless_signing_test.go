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
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const (
	chainsNamespace     = "openshift-pipelines"
	keylessSignTimeout  = 5 * time.Minute
	chainsSigningDelay  = 3 * time.Minute
	keylessBuildTimeout = 30 * time.Minute
)

var _ = Describe("Keyless Signing", Label("keyless"), Ordered, func() {
	var (
		chainsSigningIdentity string
		chainsOIDCIssuer      string
		savedChainsSpec       string
	)

	BeforeAll(func() {
		if registryHost == "" {
			Skip("REGISTRY_HOST not set; keyless signing tests require a registry")
		}
		if !openShiftCluster {
			Skip("keyless signing tests require an OpenShift cluster with Tekton Chains")
		}

		ensureTektonChainsInstalled()
		ensureOperatorDeployed()
		ensureRegistryConfigured()
		ensureBuildAPIAccess()
		ensureCaibCredentials()

		chainsSigningIdentity, chainsOIDCIssuer = discoverChainsIdentity()
		savedChainsSpec = saveChainsSpec()
		configureChainsKeyless()
		loginCosignToRegistry()
	})

	AfterAll(func() {
		if savedChainsSpec != "" {
			restoreChainsSpec(savedChainsSpec)
		}
	})

	It("should build, auto-sign via Chains, and verify keyless signature", func() {
		buildName := "e2e-keyless-sign"

		pushNamespace := testNamespace
		imageRef := fmt.Sprintf("%s:5000/%s/%s", registryHost, pushNamespace, "keyless-test:latest")

		ctx, cancel := context.WithTimeout(context.Background(), keylessBuildTimeout)
		defer cancel()

		type buildResult struct {
			output []byte
			err    error
		}
		ch := make(chan buildResult, 1)

		By("launching build")
		go func() {
			cmd := utils.NewCaibCommand(ctx, caibEnv,
				"image", "build",
				caibBuildManifest,
				"--name", buildName,
				"--arch", arch,
				"--push", imageRef,
				"--follow")
			out, err := utils.RunSafe(cmd)
			ch <- buildResult{output: out, err: err}
		}()

		select {
		case r := <-ch:
			By("verifying build completed successfully")
			_, _ = fmt.Fprintf(GinkgoWriter, "\n--- keyless signing build (%s) ---\n%s\n",
				buildName, string(r.output))
			ExpectWithOffset(1, r.err).NotTo(HaveOccurred(),
				fmt.Sprintf("build failed:\n%sError: %v\n", string(r.output), r.err))
		case <-ctx.Done():
			Fail(fmt.Sprintf("build did not complete within %v", keylessBuildTimeout))
		}

		By("verifying build appears in caib list")
		verifyCaibList(buildName)

		By("retrieving pushed image digest")
		digest := getImageDigest(buildName)
		Expect(digest).NotTo(BeEmpty(), "could not determine image digest from build")

		digestedRef := fmt.Sprintf("%s@%s", stripTag(imageRef), digest)

		By("waiting for Tekton Chains to sign the image")
		verifyChainsSignature(digestedRef, chainsSigningIdentity, chainsOIDCIssuer)
	})

	It("should reject a secure build when task bundle lacks a keyless signature", func() {
		By("resolving an unsigned image as the task bundle reference")
		unsignedRef := getUnsignedBundleRef()
		Expect(unsignedRef).NotTo(BeEmpty(), "could not resolve unsigned bundle reference")
		_, _ = fmt.Fprintf(GinkgoWriter, "unsigned bundle ref: %s\n", unsignedRef)

		By("patching OperatorConfig for keyless task bundle verification")
		patch := fmt.Sprintf(`{"spec":{"osBuilds":{"taskBundleVerify":true,"taskBundleRef":"%s","taskBundleCosignKeyless":{"certificateIdentity":"%s","certificateOIDCIssuer":"%s"}}}}`,
			unsignedRef, chainsSigningIdentity, chainsOIDCIssuer)
		cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
			"-n", testNamespace, "--type=merge", "-p", patch)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "failed to patch OperatorConfig for keyless verification")

		DeferCleanup(func() {
			By("restoring OperatorConfig: disabling task bundle verification")
			cleanup := `{"spec":{"osBuilds":{"taskBundleVerify":false,"taskBundleRef":"","taskBundleCosignKeyless":null}}}`
			cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", testNamespace, "--type=merge", "-p", cleanup)
			_, _ = utils.Run(cmd)
		})

		By("waiting for operator to reconcile configuration")
		time.Sleep(10 * time.Second)

		By("attempting a secure build (should be rejected)")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		buildCmd := utils.NewCaibCommand(ctx, caibEnv,
			"image", "build",
			caibBuildManifest,
			"--name", "e2e-keyless-reject",
			"--arch", arch,
			"--secure",
			"--follow")
		output, buildErr := utils.RunSafe(buildCmd)
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- keyless reject build output ---\n%s\n", string(output))

		Expect(buildErr).To(HaveOccurred(), "secure build should fail when bundle has no keyless signature")
		Expect(string(output)).To(ContainSubstring("keyless signature verification failed"),
			"error should indicate keyless verification failure")
	})
})

func ensureTektonChainsInstalled() {
	By("verifying Tekton Chains controller is running")
	cmd := exec.Command("kubectl", "get", "deployment", "tekton-chains-controller",
		"-n", chainsNamespace, "-o", "jsonpath={.status.availableReplicas}")
	output, err := utils.Run(cmd)
	if err != nil || strings.TrimSpace(string(output)) != "1" {
		Skip("Tekton Chains is not installed; skipping keyless signing tests")
	}
}

func discoverChainsIdentity() (identity, issuer string) {
	By("discovering Chains signing identity")

	cmd := exec.Command("kubectl", "get", "deployment", "tekton-chains-controller",
		"-n", chainsNamespace,
		"-o", "jsonpath={.spec.template.spec.serviceAccountName}")
	saOutput, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	sa := strings.TrimSpace(string(saOutput))
	if sa == "" {
		sa = "tekton-chains-controller"
	}

	cmd = exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
	oidcOutput, err := utils.Run(cmd)
	if err != nil {
		issuer = "https://kubernetes.default.svc"
	} else {
		var oidcConfig struct {
			Issuer string `json:"issuer"`
		}
		if jsonErr := json.Unmarshal(oidcOutput, &oidcConfig); jsonErr == nil && oidcConfig.Issuer != "" {
			issuer = oidcConfig.Issuer
		} else {
			issuer = "https://kubernetes.default.svc"
		}
	}

	identity = fmt.Sprintf("https://kubernetes.io/namespaces/%s/serviceaccounts/%s", chainsNamespace, sa)
	_, _ = fmt.Fprintf(GinkgoWriter, "Chains identity: %s\n", identity)
	_, _ = fmt.Fprintf(GinkgoWriter, "OIDC issuer:     %s\n", issuer)
	return identity, issuer
}

// saveChainsSpec returns the current TektonConfig chain spec as JSON.
func saveChainsSpec() string {
	cmd := exec.Command("kubectl", "get", "tektonconfig", "config",
		"-o", "jsonpath={.spec.chain}")
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}
	return string(output)
}

func configureChainsKeyless() {
	By("configuring Tekton Chains for keyless signing via TektonConfig")

	// Chains runs inside the cluster — always use internal service URLs.
	// SIGSTORE_REKOR_URL is the external route for cosign verify from the test runner.
	fulcioURL := "http://fulcio-server.fulcio-system.svc"
	rekorURL := "http://rekor-server.rekor-system.svc:80"

	patch := fmt.Sprintf(`{
		"spec": {
			"chain": {
				"artifacts.taskrun.format": "slsa/v1",
				"artifacts.taskrun.storage": "oci",
				"artifacts.pipelinerun.format": "slsa/v1",
				"artifacts.pipelinerun.storage": "oci",
				"signers.x509.fulcio.enabled": true,
				"signers.x509.fulcio.address": "%s",
				"transparency.enabled": true,
				"transparency.url": "%s"
			}
		}
	}`, fulcioURL, rekorURL)

	cmd := exec.Command("kubectl", "patch", "tektonconfig", "config",
		"--type=merge", "-p", patch)
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("waiting for Chains controller to reconcile configuration")
	time.Sleep(15 * time.Second)
	cmd = exec.Command("kubectl", "rollout", "status",
		"deployment/tekton-chains-controller", "-n", chainsNamespace,
		"--timeout=3m")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

// restoreChainsSpec patches TektonConfig back to the saved chain spec.
func restoreChainsSpec(savedJSON string) {
	By("restoring Tekton Chains configuration")
	patch := fmt.Sprintf(`{"spec":{"chain":%s}}`, savedJSON)
	cmd := exec.Command("kubectl", "patch", "tektonconfig", "config",
		"--type=merge", "-p", patch)
	_, _ = utils.Run(cmd)
}

func loginCosignToRegistry() {
	extHost := os.Getenv("REGISTRY_EXTERNAL_HOST")
	if extHost == "" {
		return
	}

	By("logging cosign into external registry: " + extHost)
	cmd := exec.Command("oc", "whoami", "-t")
	tokenOutput, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: could not get OCP token for cosign login: %v\n", err)
		return
	}
	token := strings.TrimSpace(string(tokenOutput))

	cmd = exec.Command("cosign", "login", extHost, "-u", "kubeadmin", "-p", token)
	output, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: cosign login failed: %v\n%s\n", err, string(output))
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "cosign registry login succeeded\n")
}

func getImageDigest(_ string) string {
	for _, task := range []string{"build-image", "collect-images-result"} {
		cmd := exec.Command("kubectl", "get", "taskrun",
			"-n", testNamespace,
			"-l", fmt.Sprintf("tekton.dev/pipelineTask=%s", task),
			"-o", "json")
		output, err := utils.Run(cmd)
		if err != nil {
			continue
		}

		var result struct {
			Items []struct {
				Status struct {
					Results []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"results"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(output, &result); err != nil || len(result.Items) == 0 {
			continue
		}
		for _, r := range result.Items[0].Status.Results {
			if r.Name == "IMAGE_DIGEST" && r.Value != "" {
				return r.Value
			}
		}
	}
	return ""
}

func stripTag(ref string) string {
	if idx := strings.LastIndex(ref, ":"); idx > 0 {
		afterColon := ref[idx+1:]
		if !strings.Contains(afterColon, "/") {
			return ref[:idx]
		}
	}
	return ref
}

// getUnsignedBundleRef returns a digest-pinned OCI reference to the operator image,
// which is unsigned and can serve as a test subject for signature rejection.
func getUnsignedBundleRef() string {
	cmd := exec.Command("oc", "get", "istag",
		"automotive-dev-operator:test",
		"-n", testNamespace,
		"-o", "jsonpath={.image.metadata.name}")
	output, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: could not get istag digest: %v\n", err)
		return ""
	}
	digest := strings.TrimSpace(string(output))
	if digest == "" {
		return ""
	}

	return fmt.Sprintf("%s:5000/%s/automotive-dev-operator@%s",
		registryHost, testNamespace, digest)
}

func verifyChainsSignature(imageRef, identity, issuer string) {
	verifyRef := imageRef
	if extHost := os.Getenv("REGISTRY_EXTERNAL_HOST"); extHost != "" {
		verifyRef = strings.Replace(imageRef, registryHost+":5000", extHost, 1)
	}

	By("verifying keyless signature on image: " + verifyRef)

	EventuallyWithOffset(1, func() error {
		args := []string{"verify",
			"--certificate-identity", identity,
			"--certificate-oidc-issuer", issuer,
		}

		fulcioRoot := os.Getenv("SIGSTORE_FULCIO_ROOT")

		if fulcioRoot != "" {
			args = append(args, "--certificate-chain", fulcioRoot)
			// Local Sigstore: skip tlog TLS verification (CRC routes use
			// self-signed ingress CA) and SCT checks (CTLog disabled).
			// Chains already uploaded entries — we verified via Chains logs.
			args = append(args, "--insecure-ignore-tlog=true", "--insecure-ignore-sct=true")
		}

		args = append(args, "--allow-insecure-registry", verifyRef)

		cmd := exec.Command("cosign", args...)
		output, err := utils.Run(cmd)
		if err != nil {
			return fmt.Errorf("cosign verify failed: %w\nOutput: %s", err, string(output))
		}
		_, _ = fmt.Fprintf(GinkgoWriter, "cosign verify succeeded:\n%s\n", string(output))
		return nil
	}, chainsSigningDelay+keylessSignTimeout, 15*time.Second).Should(Succeed(),
		"Tekton Chains did not sign the image within the expected timeframe")
}
