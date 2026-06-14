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

const (
	caibBuildManifest = "test/config/test-manifest.aib.yml"
	caibBuildTimeout  = 30 * time.Minute
	caibListTimeout   = 30 * time.Second
)

var _ = Describe("Bootc Container Build", Label("bootc"), Ordered, func() {

	BeforeAll(func() {
		if registryHost == "" {
			Skip("REGISTRY_HOST not set; bootc build tests require a registry")
		}
		ensureOperatorDeployed()
		ensureRegistryConfigured()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	It("should build a container image via caib", func() {
		containerBuildName := "e2e-test-build-image"

		type buildResult struct {
			output []byte
			err    error
		}

		ctx, cancel := context.WithTimeout(context.Background(), caibBuildTimeout)
		defer cancel()

		containerCh := make(chan buildResult, 1)

		pushNamespace := kindPushNamespace
		if openShiftCluster {
			pushNamespace = testNamespace
		}

		By("launching bootc container build")
		go func() {
			cmd := utils.NewCaibCommand(ctx, caibEnv,
				"image", "build",
				caibBuildManifest,
				"--name", containerBuildName,
				"--arch", arch,
				"--push", fmt.Sprintf("%s:5000/%s/%s", registryHost, pushNamespace, artifactImageName),
				"--follow")
			out, err := utils.RunSafe(cmd)
			containerCh <- buildResult{output: out, err: err}
		}()

		select {
		case cr := <-containerCh:
			By("verifying container build completed successfully")
			_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib container build (%s) ---\n%s\n",
				containerBuildName, string(cr.output))
			ExpectWithOffset(1, cr.err).NotTo(HaveOccurred(),
				fmt.Sprintf("container build failed:\n%sError: %v\n", string(cr.output), cr.err))
		case <-ctx.Done():
			Fail(fmt.Sprintf("caib build did not complete within %v", caibBuildTimeout))
		}

		By("verifying container build appears in caib list")
		verifyCaibList(containerBuildName)
	})
})

var _ = Describe("Internal Registry Build", Label("internal-registry"), Ordered, func() {

	BeforeAll(func() {
		ensureOperatorDeployed()
		if !openShiftCluster {
			Skip("internal registry tests require an OpenShift cluster")
		}
		ensureBuildAPIAccess()
		ensureCaibCredentials()

		By("enabling insecure registry for internal registry builds")
		patch := `{"spec":{"osBuilds":{"insecureRegistry":true}}}`
		cmd := exec.Command("kubectl", "patch", "operatorconfig", "config",
			"-n", testNamespace, "--type=merge", "-p", patch)
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	})

	It("should build and push to the internal registry via --internal-registry", func() {
		buildName := "e2e-test-internal-registry"

		type buildResult struct {
			output []byte
			err    error
		}

		ctx, cancel := context.WithTimeout(context.Background(), caibBuildTimeout)
		defer cancel()

		ch := make(chan buildResult, 1)

		By("launching build with --internal-registry")
		go func() {
			cmd := utils.NewCaibCommand(ctx, caibEnv,
				"image", "build",
				caibBuildManifest,
				"--name", buildName,
				"--arch", arch,
				"--internal-registry",
				"--follow")
			out, err := utils.RunSafe(cmd)
			ch <- buildResult{output: out, err: err}
		}()

		select {
		case r := <-ch:
			By("verifying internal registry build completed successfully")
			_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib internal-registry build (%s) ---\n%s\n",
				buildName, string(r.output))
			ExpectWithOffset(1, r.err).NotTo(HaveOccurred(),
				fmt.Sprintf("internal registry build failed:\n%sError: %v\n", string(r.output), r.err))
		case <-ctx.Done():
			Fail(fmt.Sprintf("caib build did not complete within %v", caibBuildTimeout))
		}

		By("verifying build appears in caib list")
		verifyCaibList(buildName)
	})
})

func verifyCaibList(caibBuildName string) {
	ctx, cancel := context.WithTimeout(context.Background(), caibListTimeout)
	defer cancel()
	listCmd := utils.NewCaibCommand(ctx, caibEnv,
		"image", "list")
	listOutput, listErr := utils.Run(listCmd)
	Expect(listErr).NotTo(HaveOccurred())
	lines := strings.Split(string(listOutput), "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(line, caibBuildName) {
			Expect(line).To(ContainSubstring("Completed"))
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(),
		fmt.Sprintf("build %q not found in caib list output:\n%s", caibBuildName, string(listOutput)))
}
