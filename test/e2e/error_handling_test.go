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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Test #59 from e2e-test-coverage-proposal.md.

var _ = Describe("Error Handling", Label("operator"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	// #59 — Concurrent builds get independent resources
	It("should handle concurrent builds with independent PipelineRuns", func() {
		buildNameA := "e2e-concurrent-a"
		buildNameB := "e2e-concurrent-b"

		crA := minimalImageBuildCR(buildNameA)
		crB := minimalImageBuildCR(buildNameB)

		By("creating two ImageBuilds simultaneously")
		applyImageBuildCR(buildNameA, crA)
		applyImageBuildCR(buildNameB, crB)

		DeferCleanup(func() {
			deleteImageBuildCR(buildNameA)
			deleteImageBuildCR(buildNameB)
		})

		By("waiting for both PipelineRuns to be created")
		prNameA := waitForPipelineRun(buildNameA, 30*time.Second)
		prNameB := waitForPipelineRun(buildNameB, 30*time.Second)

		By("verifying PipelineRuns are distinct resources")
		Expect(prNameA).NotTo(Equal(prNameB),
			"concurrent builds must have independent PipelineRuns")
		Expect(prNameA).NotTo(BeEmpty())
		Expect(prNameB).NotTo(BeEmpty())

		By("verifying both builds have independent status")
		cmd := exec.Command("kubectl", "get", "imagebuild", buildNameA,
			"-n", testNamespace, "-o", "jsonpath={.status.pipelineRunName}")
		outputA, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		cmd = exec.Command("kubectl", "get", "imagebuild", buildNameB,
			"-n", testNamespace, "-o", "jsonpath={.status.pipelineRunName}")
		outputB, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		Expect(strings.TrimSpace(string(outputA))).To(Equal(prNameA))
		Expect(strings.TrimSpace(string(outputB))).To(Equal(prNameB))
	})
})
