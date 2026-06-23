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

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Test #23 from e2e-test-coverage-proposal.md.

var _ = Describe("Package Mode Build", Label("package-mode"), Ordered, func() {

	BeforeAll(func() {
		if registryHost == "" {
			Skip("REGISTRY_HOST not set; package mode build tests require a registry")
		}
		ensureOperatorDeployed()
		ensureRegistryConfigured()
		ensureBuildAPIAccess()
		ensureCaibCredentials()

		if openShiftCluster {
			By("pre-creating ImageStream on OpenShift")
			cmd := exec.Command("oc", "create", "imagestream", artifactImageRepo, "-n", testNamespace)
			_, _ = utils.Run(cmd)
		}
	})

	// #23 — Full package mode disk image build
	It("should complete a package mode disk image build via caib build-dev", func() {
		buildName := "e2e-package-mode"
		var actualBuildName string

		ctx, cancel := context.WithTimeout(context.Background(), caibBuildTimeout)
		defer cancel()

		type buildResult struct {
			output []byte
			err    error
		}
		ch := make(chan buildResult, 1)

		pushNamespace := kindPushNamespace
		if openShiftCluster {
			pushNamespace = testNamespace
		}

		By("launching package mode build via caib build-dev")
		go func() {
			out, err := runCaibCommand(ctx,
				"image", "build-dev",
				caibBuildManifest,
				"--name", buildName,
				"--arch", arch,
				"--mode", "package",
				"--format", "qcow2",
				"--push", fmt.Sprintf("%s:5000/%s/%s", registryHost, pushNamespace, artifactImageName),
			)
			ch <- buildResult{output: out, err: err}
		}()

		DeferCleanup(func() {
			name := actualBuildName
			if name == "" {
				name = buildName
			}
			deleteImageBuildCR(name)
		})

		select {
		case r := <-ch:
			By("verifying package mode build completed successfully")
			_, _ = fmt.Fprintf(GinkgoWriter, "\n--- package mode build (%s) ---\n%s\n",
				buildName, string(r.output))
			Expect(r.err).NotTo(HaveOccurred(),
				fmt.Sprintf("package mode build failed:\n%sError: %v\n", string(r.output), r.err))
		case <-ctx.Done():
			Fail(fmt.Sprintf("package mode build did not complete within %v", caibBuildTimeout))
		}

		actualBuildName = getImageBuildCRName(buildName)

		By("verifying ImageBuild CR status fields")
		cmd := exec.Command("kubectl", "get", "imagebuild", actualBuildName,
			"-n", testNamespace,
			"-o", "jsonpath={.status.phase} {.status.startTime} {.status.completionTime} {.status.pipelineRunName}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		fields := strings.Fields(strings.TrimSpace(string(output)))
		Expect(len(fields)).To(BeNumerically(">=", 4),
			fmt.Sprintf("expected at least 4 status fields, got: %s", string(output)))
		Expect(fields[0]).To(Equal("Completed"))
		Expect(fields[1]).NotTo(BeEmpty(), "startTime should be populated")
		Expect(fields[2]).NotTo(BeEmpty(), "completionTime should be populated")
		Expect(fields[3]).NotTo(BeEmpty(), "pipelineRunName should be populated")

		By("verifying push-disk-artifact task ran in the PipelineRun")
		prName := fields[3]
		cmd = exec.Command("kubectl", "get", "pipelinerun", prName,
			"-n", testNamespace,
			"-o", `jsonpath={.status.childReferences[?(@.pipelineTaskName=="push-disk-artifact")].name}`)
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).NotTo(BeEmpty(),
			"push-disk-artifact TaskRun should exist in PipelineRun childReferences")

		By("verifying build mode is package in the CR spec")
		cmd = exec.Command("kubectl", "get", "imagebuild", actualBuildName,
			"-n", testNamespace, "-o", "jsonpath={.spec.aib.mode}")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(output))).To(Equal("package"))

		By("verifying build appears in caib image list")
		verifyCaibList(buildName)
	})
})
