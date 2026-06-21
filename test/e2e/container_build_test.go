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
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const (
	containerBuildTimeout = 15 * time.Minute
	containerBuildContext = "test/config/container-build-context"
)

func dumpContainerBuildLogs(buildName string) {
	// Dump BuildRun paramValues to verify registries-insecure is set
	brJSON, _ := utils.Run(exec.Command("kubectl", "get", "buildruns.shipwright.io",
		"-n", testNamespace,
		"-o", "jsonpath={.items[-1].spec.build.spec.paramValues}"))
	_, _ = fmt.Fprintf(GinkgoWriter, "\n--- BuildRun paramValues for %s ---\n%s\n", buildName, string(brJSON))

	// Dump ContainerBuild spec
	cbJSON, _ := utils.Run(exec.Command("kubectl", "get", "containerbuilds.automotive.sdv.cloud.redhat.com",
		"-n", testNamespace, buildName,
		"-o", "jsonpath={.spec}"))
	_, _ = fmt.Fprintf(GinkgoWriter, "\n--- ContainerBuild spec for %s ---\n%s\n", buildName, string(cbJSON))

	pods, _ := utils.Run(exec.Command("kubectl", "get", "pods",
		"-n", testNamespace,
		"-l", "buildrun.shipwright.io/name",
		"--sort-by=.metadata.creationTimestamp",
		"-o", "jsonpath={.items[-1].metadata.name}"))
	podName := string(pods)
	if podName == "" {
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- no build pod found for %s ---\n", buildName)
		return
	}
	for _, container := range []string{"step-source-local", "step-build-and-push"} {
		logs, _ := utils.Run(exec.Command("kubectl", "logs", podName,
			"-n", testNamespace, "--container="+container))
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- %s / %s ---\n%s\n", podName, container, string(logs))
	}

	// Dump operator controller logs for reconciliation debugging
	opLogs, _ := utils.Run(exec.Command("kubectl", "logs",
		"-n", testNamespace, "deployment/ado-operator",
		"--tail=50"))
	_, _ = fmt.Fprintf(GinkgoWriter, "\n--- operator controller logs (last 50 lines) ---\n%s\n", string(opLogs))
}

// isShipwrightInstalled checks if Shipwright CRDs are present on the cluster.
func isShipwrightInstalled() bool {
	cmd := exec.Command("kubectl", "api-resources", "--api-group=shipwright.io", "--no-headers")
	out, err := utils.Run(cmd)
	return err == nil && len(out) > 0
}

var _ = Describe("Container Build (Shipwright)", Label("container-build"), Ordered, func() {

	BeforeAll(func() {
		ensureOperatorDeployed()
		if !openShiftCluster {
			Skip("container build tests require OpenShift")
		}
		if !isShipwrightInstalled() {
			Skip("container build tests require Shipwright (OpenShift Builds)")
		}
		ensureRegistryConfigured()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	It("should build and push to internal registry", func() {
		buildName := "e2e-container-build"

		ctx, cancel := context.WithTimeout(context.Background(), containerBuildTimeout)
		defer cancel()

		By("launching container build with --internal-registry")
		cmd := utils.NewCaibCommand(ctx, caibEnv,
			"container", "build",
			"--containerfile", containerBuildContext+"/Containerfile",
			"--name", buildName,
			"--internal-registry",
			"--arch", arch,
			containerBuildContext)
		output, err := utils.RunSafe(cmd)

		By("verifying container build completed successfully")
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib container build (%s) ---\n%s\n",
			buildName, string(output))
		if err != nil {
			dumpContainerBuildLogs(buildName)
		}
		ExpectWithOffset(1, err).NotTo(HaveOccurred(),
			fmt.Sprintf("container build failed:\n%sError: %v\n", string(output), err))
	})

	It("should build with --build-arg", func() {
		buildName := "e2e-container-buildarg"

		ctx, cancel := context.WithTimeout(context.Background(), containerBuildTimeout)
		defer cancel()

		By("launching container build with --build-arg and --internal-registry")
		cmd := utils.NewCaibCommand(ctx, caibEnv,
			"container", "build",
			"--containerfile", containerBuildContext+"/Containerfile",
			"--name", buildName,
			"--internal-registry",
			"--build-arg", "VERSION=1.0-e2e",
			"--arch", arch,
			containerBuildContext)
		output, err := utils.RunSafe(cmd)

		By("verifying build-arg container build completed successfully")
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib container build with build-arg (%s) ---\n%s\n",
			buildName, string(output))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(),
			fmt.Sprintf("build-arg container build failed:\n%sError: %v\n", string(output), err))
	})
})
