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

// Tests #41, #42, #43, #47 from e2e-test-coverage-proposal.md.

var _ = Describe("Build API", Label("operator"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
		ensureRegistryConfigured()
	})

	// #41 — caib image build-dev creates an ImageBuild CR
	Context("Create Build", func() {
		var createdBuildName string

		AfterAll(func() {
			if createdBuildName != "" {
				deleteImageBuildCR(createdBuildName)
			}
		})

		It("caib image build-dev should create a build CR", func() {
			createdBuildName = createBuildViaCaib("e2e-api-create")

			By("verifying ImageBuild CR exists in cluster")
			EventuallyWithOffset(1, func() error {
				cmd := exec.Command("kubectl", "get", "imagebuild", createdBuildName,
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, getErr := utils.Run(cmd)
				if getErr != nil {
					return getErr
				}
				if strings.TrimSpace(string(output)) != createdBuildName {
					return fmt.Errorf("ImageBuild %s not found", createdBuildName)
				}
				return nil
			}, 15*time.Second, 2*time.Second).Should(Succeed())
		})
	})

	// #42 — caib image show returns build details
	Context("Get Build Details", func() {
		var buildName string

		BeforeAll(func() {
			buildName = createBuildViaCaib("e2e-api-get")
		})

		AfterAll(func() {
			if buildName != "" {
				deleteImageBuildCR(buildName)
			}
		})

		It("caib image show should return correct fields", func() {
			result := showBuildViaCaib(buildName)

			Expect(result["name"]).To(Equal(buildName))
			Expect(result).To(HaveKey("phase"))
			Expect(result).To(HaveKey("requestedBy"))
			Expect(result["requestedBy"]).NotTo(BeEmpty())

			if params, ok := result["parameters"].(map[string]interface{}); ok {
				Expect(params["architecture"]).To(Equal(arch))
			}
		})
	})

	// #43 — caib image delete removes a build
	Context("Delete Build", func() {
		It("caib image delete should delete the build and its CR", func() {
			buildName := createBuildViaCaib("e2e-api-delete")

			By("waiting for build to reach Building phase")
			waitForImageBuildPhase(buildName, "Building", 60*time.Second)

			By("deleting the build via caib")
			deleteBuildViaCaib(buildName)

			By("verifying ImageBuild CR is deleted")
			waitForImageBuildDeleted(buildName, time.Minute)
		})
	})

	// #47 — Build ownership enforcement (403 for another user's build)
	Context("Ownership Enforcement", func() {
		runCaibCommandWithToken := func(ctx context.Context, token string, args ...string) ([]byte, error) {
			env := append([]string{}, caibEnv...)
			const tokenPrefix = "CAIB_TOKEN="
			filtered := env[:0]
			for _, entry := range env {
				if !strings.HasPrefix(entry, tokenPrefix) {
					filtered = append(filtered, entry)
				}
			}
			filtered = append(filtered, tokenPrefix+token)
			cmd := utils.NewCaibCommand(ctx, filtered, args...)
			output, err := utils.RunSafe(cmd)
			appendCaibCommandLog(args, output, err)
			return output, err
		}

		It("should return 403 when a different user tries to cancel or delete another user's build", func() {
			By("creating two service accounts with separate tokens")
			tokenA := createServiceAccountToken("caib-user-a")
			tokenB := createServiceAccountToken("caib-user-b")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "serviceaccount",
					"caib-user-a", "caib-user-b",
					"-n", testNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			By("creating a build as user-a via caib")
			createCtx, createCancel := context.WithTimeout(context.Background(), caibImageBuildTimeout)
			defer createCancel()
			createOutput, err := runCaibCommandWithToken(createCtx, tokenA,
				"image", "build-dev",
				caibBuildManifest,
				"--name", "e2e-api-ownership",
				"--arch", arch,
				"--mode", "image",
				"--internal-registry",
				"--wait=false",
			)
			Expect(err).NotTo(HaveOccurred(),
				fmt.Sprintf("expected build creation by user-a to succeed:\n%s", string(createOutput)))
			buildName := parseCaibBuildName(string(createOutput))
			Expect(buildName).NotTo(BeEmpty(), "could not parse build name from caib output: %s", string(createOutput))

			DeferCleanup(func() {
				deleteImageBuildCR(buildName)
			})

			By("attempting to cancel as user-b (should fail with 403)")
			cancelCtx, cancelCancel := context.WithTimeout(context.Background(), caibImageCancelTimeout)
			defer cancelCancel()
			cancelOutput, err := runCaibCommandWithToken(cancelCtx, tokenB, "image", "cancel", buildName)
			Expect(err).To(HaveOccurred(),
				fmt.Sprintf("expected cancel by non-owner to fail, got:\n%s", string(cancelOutput)))
			Expect(strings.ToLower(string(cancelOutput))).To(SatisfyAny(
				ContainSubstring("403"),
				ContainSubstring("forbidden"),
			), fmt.Sprintf("expected 403/forbidden for cancel by non-owner, got:\n%s", string(cancelOutput)))

			By("attempting to delete as user-b (should fail with 403)")
			deleteCtx, deleteCancel := context.WithTimeout(context.Background(), caibImageDeleteTimeout)
			defer deleteCancel()
			deleteOutput, err := runCaibCommandWithToken(deleteCtx, tokenB, "image", "delete", buildName)
			Expect(err).To(HaveOccurred(),
				fmt.Sprintf("expected delete by non-owner to fail, got:\n%s", string(deleteOutput)))
			Expect(strings.ToLower(string(deleteOutput))).To(SatisfyAny(
				ContainSubstring("403"),
				ContainSubstring("forbidden"),
			), fmt.Sprintf("expected 403/forbidden for delete by non-owner, got:\n%s", string(deleteOutput)))

			By("verifying user-b can still read the build (show is not ownership-gated)")
			showCtx, showCancel := context.WithTimeout(context.Background(), caibImageShowTimeout)
			defer showCancel()
			showOutput, err := runCaibCommandWithToken(showCtx, tokenB,
				"image", "show", buildName, "--output-format", "json")
			Expect(err).NotTo(HaveOccurred(),
				fmt.Sprintf("expected show by non-owner to succeed, got:\n%s", string(showOutput)))
			Expect(string(showOutput)).To(ContainSubstring(buildName))
		})
	})
})
