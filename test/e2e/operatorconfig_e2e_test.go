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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Test #37 from e2e-test-coverage-proposal.md.

var _ = Describe("OperatorConfig E2E", Label("operator"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	// #37 — Toggle osBuilds.enabled removes and recreates Tekton resources
	It("should remove Tekton resources when osBuilds is disabled and recreate when re-enabled", func() {
		By("verifying Tekton resources exist as pre-condition")
		verifyTektonResourcesExist()

		DeferCleanup(func() {
			By("ensuring osBuilds is re-enabled after test")
			cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", testNamespace, "--type=merge",
				"-p", `{"spec":{"osBuilds":{"enabled":true}}}`)
			_, _ = utils.Run(cmd)

			EventuallyWithOffset(1, func() error {
				cmd := exec.Command("kubectl", "get", "operatorconfig", "config",
					"-n", testNamespace,
					"-o", "jsonpath={.status.osBuildsDeployed}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if strings.TrimSpace(string(output)) != statusTrue {
					return fmt.Errorf("osBuildsDeployed not yet true")
				}
				return nil
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		By("disabling osBuilds")
		cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
			"-n", testNamespace, "--type=merge",
			"-p", `{"spec":{"osBuilds":{"enabled":false}}}`)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for Tekton resources to be removed")
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "tasks", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			tasks := strings.TrimSpace(string(output))
			if strings.Contains(tasks, "build-automotive-image") {
				return fmt.Errorf("build-automotive-image task still exists: %s", tasks)
			}
			return nil
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		waitForResourceDeleted("pipeline", "automotive-build-pipeline", 2*time.Minute)

		By("waiting for osBuildsDeployed to become false")
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "operatorconfig", "config",
				"-n", testNamespace,
				"-o", "jsonpath={.status.osBuildsDeployed}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			// false is omitted from status JSON (omitempty), so jsonpath returns empty.
			if strings.TrimSpace(string(output)) == statusTrue {
				return fmt.Errorf("osBuildsDeployed still true")
			}
			return nil
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("re-enabling osBuilds")
		cmd = exec.Command("kubectl", "patch", "operatorconfig", "config",
			"-n", testNamespace, "--type=merge",
			"-p", `{"spec":{"osBuilds":{"enabled":true}}}`)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for osBuildsDeployed to become true")
		EventuallyWithOffset(1, func() error {
			cmd := exec.Command("kubectl", "get", "operatorconfig", "config",
				"-n", testNamespace,
				"-o", "jsonpath={.status.osBuildsDeployed}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) != statusTrue {
				return fmt.Errorf("osBuildsDeployed not yet true")
			}
			return nil
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying Tekton resources are recreated")
		verifyTektonResourcesExist()
	})
})

func verifyTektonResourcesExist() {
	EventuallyWithOffset(2, func() error {
		cmd := exec.Command("kubectl", "get", "tasks", "-n", testNamespace,
			"-o", "jsonpath={.items[*].metadata.name}")
		output, err := utils.Run(cmd)
		if err != nil {
			return err
		}
		tasks := string(output)
		if !strings.Contains(tasks, "build-automotive-image") {
			return fmt.Errorf("build-automotive-image task not found, got: %s", tasks)
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed())

	EventuallyWithOffset(2, func() error {
		cmd := exec.Command("kubectl", "get", "pipeline", "automotive-build-pipeline",
			"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
		output, err := utils.Run(cmd)
		if err != nil {
			return err
		}
		if string(output) != "automotive-build-pipeline" {
			return fmt.Errorf("automotive-build-pipeline not found")
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}
