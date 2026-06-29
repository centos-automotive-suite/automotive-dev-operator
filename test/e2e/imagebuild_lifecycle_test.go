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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Tests #21, #22 from e2e-test-coverage-proposal.md.

var _ = Describe("ImageBuild Lifecycle", Label("operator"), Ordered, func() {

	// #22 — Build cancellation via Build API
	Context("Build Cancellation", func() {
		BeforeAll(func() {
			ensureOperatorDeployed()
			ensureBuildAPIAccess()
			ensureCaibCredentials()
			ensureRegistryConfigured()
		})

		It("should cancel a running build and transition to Cancelled", func() {
			By("creating build via caib CLI")
			buildName := createBuildViaCaib("e2e-lifecycle-cancel")

			DeferCleanup(func() {
				deleteImageBuildCR(buildName)
			})

			By("waiting for build to reach Building phase")
			waitForImageBuildPhase(buildName, "Building", 1*time.Minute)

			By("cancelling the build via caib (retry on transient failure)")
			EventuallyWithOffset(1, func() error {
				ctx, cancel := context.WithTimeout(context.Background(), caibImageCancelTimeout)
				defer cancel()
				_, err := runCaibCommand(ctx, "image", "cancel", buildName)
				return err
			}, 30*time.Second, 1*time.Second).Should(Succeed())

			By("verifying ImageBuild transitions to Cancelled")
			waitForImageBuildPhase(buildName, "Cancelled", 2*time.Minute)

			By("verifying ImageBuild CR is preserved after cancel")
			cmd := exec.Command("kubectl", "get", "imagebuild", buildName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(output))).To(Equal(buildName))
		})
	})
})
