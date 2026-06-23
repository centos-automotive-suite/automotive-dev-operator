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
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Phase 4 features E2E tests: #24, #25, #38, #44, #60.

// #25 — Default TTL populates ExpiresAt on completed/failed builds
var _ = Describe("TTL: Default TTL from OperatorConfig", Label("features"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	It("should populate expiresAt on a failed build using the default TTL", func() {
		buildName := "e2e-default-ttl"

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
      name: ttl-default-test
`, buildName, testNamespace, arch)

		applyImageBuildCR(buildName, cr)
		DeferCleanup(func() { deleteImageBuildCR(buildName) })

		By("waiting for build to reach Failed phase")
		waitForImageBuildPhase(buildName, "Failed", imageBuildFailureTimeout)

		By("verifying expiresAt is populated")
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "imagebuild", buildName,
				"-n", testNamespace,
				"-o", "jsonpath={.status.expiresAt}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			expiresAt := strings.TrimSpace(string(output))
			if expiresAt == "" {
				return fmt.Errorf("expiresAt not yet set")
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})
})

// #24 + #60 — TTL expiry cleanup: build with short TTL expires and resources are cleaned up
var _ = Describe("TTL: Expiry and Cleanup", Label("features"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	It("should transition a failed build to Expired after a short TTL and clean up resources", func() {
		buildName := "e2e-ttl-expiry"

		cr := fmt.Sprintf(`apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: ImageBuild
metadata:
  name: %s
  namespace: %s
spec:
  architecture: %s
  ttl: "30s"
  aib:
    distro: autosd
    target: qemu
    mode: image
    manifest: |
      name: expiry-test
`, buildName, testNamespace, arch)

		applyImageBuildCR(buildName, cr)
		DeferCleanup(func() { deleteImageBuildCR(buildName) })

		By("waiting for build to reach Failed phase")
		waitForImageBuildPhase(buildName, "Failed", imageBuildFailureTimeout)

		By("recording PipelineRun name before expiry")
		var prName string
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "imagebuild", buildName,
				"-n", testNamespace,
				"-o", "jsonpath={.status.pipelineRunName}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			prName = strings.TrimSpace(string(output))
			if prName == "" {
				return fmt.Errorf("pipelineRunName not yet set")
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for build to transition to Expired phase")
		waitForImageBuildPhase(buildName, "Expired", 3*time.Minute)

		By("verifying previousPhase is set")
		cmd := exec.Command("kubectl", "get", "imagebuild", buildName,
			"-n", testNamespace,
			"-o", "jsonpath={.status.previousPhase}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).To(Equal("Failed"))

		By("verifying PipelineRun is cleaned up")
		if prName != "" {
			waitForResourceDeleted("pipelinerun", prName, 2*time.Minute)
		}
	})
})

// #38 — Image propagation: OperatorConfig images are reflected in Tekton Tasks
var _ = Describe("Image Propagation in Tekton Tasks", Label("features"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	It("should propagate the default AIB image to the build-automotive-image Task", func() {
		expectedImage := operatorConfigAIBImage()
		buildName := "e2e-propagation-default"

		applyImageBuildCR(buildName, minimalImageBuildCR(buildName))
		DeferCleanup(func() { deleteImageBuildCR(buildName) })

		By("verifying the build TaskRun uses the OperatorConfig AIB image")
		waitForBuildTaskRunAIBImage(buildName, expectedImage, 2*time.Minute)
	})

	It("should update Task images when OperatorConfig images are changed", func() {
		customImage := "quay.io/test/custom-aib:v99"

		By("patching OperatorConfig with a custom AIB image")
		patch := fmt.Sprintf(`{"spec":{"images":{"automotiveImageBuilder":"%s"}}}`, customImage)
		cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
			"-n", testNamespace, "--type=merge", "-p", patch)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		DeferCleanup(func() {
			By("restoring default images in OperatorConfig")
			cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"images":null}}`)
			_, _ = utils.Run(cmd)

			EventuallyWithOffset(1, func() error {
				cmd := exec.Command("kubectl", "get", "task", "build-automotive-image",
					"-n", testNamespace,
					"-o", `jsonpath={.spec.params[?(@.name=="automotive-image-builder")].default}`)
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				img := strings.TrimSpace(string(output))
				if strings.Contains(img, "custom-aib") {
					return fmt.Errorf("task still has custom image: %s", img)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		By("waiting for the Task to reflect the custom image")
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "task", "build-automotive-image",
				"-n", testNamespace,
				"-o", `jsonpath={.spec.params[?(@.name=="automotive-image-builder")].default}`)
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			img := strings.TrimSpace(string(output))
			if img != customImage {
				return fmt.Errorf("task param is %q, want %q", img, customImage)
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying a new build uses the custom image at runtime")
		buildName := "e2e-propagation-custom-build"
		applyImageBuildCR(buildName, minimalImageBuildCR(buildName))
		DeferCleanup(func() { deleteImageBuildCR(buildName) })
		waitForBuildTaskRunAIBImage(buildName, customImage, 2*time.Minute)
	})
})

var _ = Describe("Build API: Log Streaming", Label("features"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	It("caib image logs should fail for a non-existent build", func() {
		ctx, cancel := context.WithTimeout(context.Background(), caibImageListTimeout)
		defer cancel()

		output, err := runCaibCommand(ctx, "image", "logs", "no-such-build-xyz")
		Expect(err).To(HaveOccurred(),
			fmt.Sprintf("expected caib image logs to fail for non-existent build, got:\n%s", string(output)))
	})
})
