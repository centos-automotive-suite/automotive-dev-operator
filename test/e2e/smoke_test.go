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

// Smoke tests #5-19 from e2e-test-coverage-proposal.md.
// Tests #1-4 are in operator_test.go (existing tests with Label("smoke") added).

var _ = Describe("Smoke: CRD Availability", Label("smoke"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	// #6
	It("should have all CRDs installed", func() {
		cmd := exec.Command("kubectl", "get", "crd",
			"-o", "jsonpath={.items[*].metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		crds := string(output)
		for _, expected := range []string{
			"imagebuilds.automotive.sdv.cloud.redhat.com",
			"images.automotive.sdv.cloud.redhat.com",
			"catalogimages.automotive.sdv.cloud.redhat.com",
			"containerbuilds.automotive.sdv.cloud.redhat.com",
			"workspaces.automotive.sdv.cloud.redhat.com",
			"imagereseals.automotive.sdv.cloud.redhat.com",
			"operatorconfigs.automotive.sdv.cloud.redhat.com",
		} {
			Expect(crds).To(ContainSubstring(expected),
				fmt.Sprintf("CRD %s not found in cluster", expected))
		}
	})
})

var _ = Describe("Smoke: OperatorConfig", Label("smoke"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	// #7
	It("should have status phase Ready with osBuildsDeployed=true", func() {
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "operatorconfig", "config",
				"-n", testNamespace,
				"-o", "jsonpath={.status.phase} {.status.osBuildsDeployed}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			parts := strings.Fields(strings.TrimSpace(string(output)))
			if len(parts) < 2 || parts[0] != "Ready" || parts[1] != statusTrue {
				return fmt.Errorf("OperatorConfig not ready, got: %s", string(output))
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	// #8
	It("should have target defaults ConfigMap", func() {
		cmd := exec.Command("kubectl", "get", "configmap", "aib-target-defaults",
			"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).To(Equal("aib-target-defaults"))
	})

	// #9
	It("should have build ServiceAccount", func() {
		cmd := exec.Command("kubectl", "get", "serviceaccount", "ado-build",
			"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).To(Equal("ado-build"))
	})

	// #10
	It("should have internal JWT secret", func() {
		cmd := exec.Command("kubectl", "get", "secret", "ado-build-api-internal-jwt",
			"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).To(Equal("ado-build-api-internal-jwt"))
	})
})

var _ = Describe("Smoke: Build API Endpoints", Label("smoke"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	// #5
	It(healthzPath+" should return 200", func() {
		client := newInsecureHTTPClient()
		resp, err := client.Get(caibServer + healthzPath)
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	// #13
	It("/v1/openapi.yaml should respond with OpenAPI spec", func() {
		client := newInsecureHTTPClient()
		resp, err := client.Get(caibServer + "/v1/openapi.yaml")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("openapi"))
	})

	// #14
	It("/v1/auth/config should respond with 200 or 404", func() {
		client := newInsecureHTTPClient()
		resp, err := client.Get(caibServer + "/v1/auth/config")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(BeElementOf(http.StatusOK, http.StatusNotFound))
	})

	// #15
	It("/v1/config should return OperatorConfig fields", func() {
		client := newInsecureHTTPClient()
		req, err := http.NewRequest("GET", caibServer+"/v1/config", nil)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+caibToken)

		resp, err := client.Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		body, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("targetDefaults"))
	})

	// #16
	It("caib image list should succeed with valid credentials", func() {
		output := listBuildsViaCaib()
		Expect(output).NotTo(BeEmpty(), "caib image list should produce output")
	})

	// #17
	It("should return 401 for unauthenticated request to /v1/builds", func() {
		client := newInsecureHTTPClient()
		req, err := http.NewRequest("GET", caibServer+"/v1/builds", nil)
		Expect(err).NotTo(HaveOccurred())

		resp, err := client.Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
	})
})

var _ = Describe("Smoke: CR Lifecycle", Label("smoke"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	// #11
	It("ImageBuild should create a PipelineRun", func() {
		buildName := "smoke-test-pipelinerun"

		cr := fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
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
      name: smoke-test
`, buildName, testNamespace, arch)

		applyImageBuildCR(buildName, cr)
		DeferCleanup(func() { deleteImageBuildCR(buildName) })

		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "pipelinerun",
				"-l", fmt.Sprintf("automotive.sdv.cloud.redhat.com/imagebuild-name=%s", buildName),
				"-n", testNamespace, "-o", "jsonpath={.items[0].metadata.name}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) == "" {
				return fmt.Errorf("no PipelineRun found for ImageBuild %s", buildName)
			}
			return nil
		}, 30*time.Second, 2*time.Second).Should(Succeed())
	})

	// #12
	It("CatalogImage should reach Available with resolvedDigest", func() {
		catalogName := "smoke-test-catalog"

		cr := fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: CatalogImage
metadata:
  name: %s
  namespace: %s
spec:
  registryUrl: "registry.access.redhat.com/ubi9/ubi-micro:latest"
`, catalogName, testNamespace)

		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(cr)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		DeferCleanup(func() {
			cmd := exec.Command("kubectl", "delete", "catalogimage", catalogName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "catalogimage", catalogName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			phase := strings.TrimSpace(string(output))
			if phase != "Available" {
				return fmt.Errorf("CatalogImage phase is %q, want Available", phase)
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		cmd = exec.Command("kubectl", "get", "catalogimage", catalogName,
			"-n", testNamespace,
			"-o", "jsonpath={.status.registryMetadata.resolvedDigest}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).To(HavePrefix("sha256:"))
	})
})

var _ = Describe("Smoke: Negative / Guard Rails", Label("smoke"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	// #18 – secureBuild without taskBundleRef is a terminal validation error
	It("invalid ImageBuild should reach Failed with a status message", func() {
		buildName := "smoke-test-invalid"

		cr := fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: ImageBuild
metadata:
  name: %s
  namespace: %s
spec:
  architecture: %s
  secureBuild: true
  aib:
    distro: autosd
    target: qemu
    mode: image
    manifest: |
      name: invalid-test
`, buildName, testNamespace, arch)

		applyImageBuildCR(buildName, cr)
		DeferCleanup(func() { deleteImageBuildCR(buildName) })

		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "imagebuild", buildName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			phase := strings.TrimSpace(string(output))
			if phase != "Failed" {
				return fmt.Errorf("ImageBuild phase is %q, want Failed", phase)
			}
			return nil
		}, time.Minute, 2*time.Second).Should(Succeed())

		cmd := exec.Command("kubectl", "get", "imagebuild", buildName,
			"-n", testNamespace, "-o", "jsonpath={.status.message}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).NotTo(BeEmpty())
	})

	// #19
	It("ImageBuild deletion should garbage-collect PipelineRun", func() {
		imageBuildName := "smoke-test-cleanup"

		cr := fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
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
      name: cleanup-test
`, imageBuildName, testNamespace, arch)

		applyImageBuildCR(imageBuildName, cr)

		var pipelineRunName string
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "pipelinerun",
				"-l", fmt.Sprintf("automotive.sdv.cloud.redhat.com/imagebuild-name=%s", imageBuildName),
				"-n", testNamespace, "-o", "jsonpath={.items[0].metadata.name}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			name := strings.TrimSpace(string(output))
			if name == "" {
				return fmt.Errorf("no PipelineRun found for ImageBuild %s", imageBuildName)
			}
			pipelineRunName = name
			return nil
		}, 30*time.Second, 2*time.Second).Should(Succeed())

		cmd := exec.Command("kubectl", "delete", "imagebuild", imageBuildName,
			"-n", testNamespace, "--ignore-not-found")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "pipelinerun", pipelineRunName,
				"-n", testNamespace, "--ignore-not-found", "-o", "name")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) == "" {
				return nil
			}
			return fmt.Errorf("PipelineRun %s still exists after ImageBuild deletion", pipelineRunName)
		}, 30*time.Second, 2*time.Second).Should(Succeed())
	})
})
