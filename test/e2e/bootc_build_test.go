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
	caibBuildManifest   = "test/config/test-manifest.aib.yml"
	caibBuildTimeout    = 30 * time.Minute
	internalRegistryURL = "image-registry.openshift-image-registry.svc:5000"
)

var _ = Describe("Bootc Container Build", Label("bootc"), Ordered, func() {
	var actualBuildName string

	BeforeAll(func() {
		if registryHost == "" {
			Skip("REGISTRY_HOST not set; bootc build tests require a registry")
		}
		ensureOperatorDeployed()
		ensureRegistryConfigured()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	AfterAll(func() {
		name := actualBuildName
		if name == "" {
			name = "e2e-test-build-image"
		}
		deleteImageBuildCR(name)
	})

	// #20 — Full lifecycle (Pending→Building→Completed) via caib CLI
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
		pushURL := fmt.Sprintf("%s:5000/%s/%s", registryHost, pushNamespace, artifactImageName)

		By("launching bootc container build")
		go func() {
			out, err := runCaibCommand(ctx,
				"image", "build",
				caibBuildManifest,
				"--name", containerBuildName,
				"--arch", arch,
				"--push", pushURL,
				"--follow",
			)
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

		actualBuildName = getImageBuildCRName(containerBuildName)

		By("verifying status fields are populated")
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

		By("verifying container build appears in caib list")
		verifyCaibList(containerBuildName)
	})

	// #44 — caib image logs returns a response for a completed build
	It("should retrieve logs for the completed build via caib", func() {
		By("retrieving logs via caib CLI")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		output, err := runCaibCommand(ctx, "image", "logs", actualBuildName)
		Expect(err).NotTo(HaveOccurred(),
			fmt.Sprintf("caib image logs %s failed:\n%s", actualBuildName, string(output)))
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
			out, err := runCaibCommand(ctx,
				"image", "build",
				caibBuildManifest,
				"--name", buildName,
				"--arch", arch,
				"--internal-registry",
				"--follow",
			)
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

	// Hybrid build: --push sends the container elsewhere with the user's
	// credentials, while the disk goes to the internal registry with the SA
	// token Secret (spec.pushSecretRef).
	It("should push the disk to the internal registry when --push sends the container elsewhere", func() {
		if registryHost == "" {
			Skip("REGISTRY_HOST not set; the hybrid build needs a registry for the container push")
		}
		ensureRegistryConfigured()

		buildName := "e2e-test-hybrid-registry"
		pushURL := fmt.Sprintf("%s:5000/%s/%s", registryHost, testNamespace, artifactImageName)

		ctx, cancel := context.WithTimeout(context.Background(), caibBuildTimeout)
		defer cancel()

		By("launching a build with --push, --internal-registry and --disk")
		output, err := runCaibCommand(ctx,
			"image", "build",
			caibBuildManifest,
			"--name", buildName,
			"--arch", arch,
			"--push", pushURL,
			"--internal-registry",
			"--disk",
			"--follow",
		)
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib hybrid-registry build (%s) ---\n%s\n", buildName, string(output))
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("hybrid registry build failed:\n%sError: %v\n", string(output), err))

		actualBuildName := getImageBuildCRName(buildName)
		jsonPath := func(kind, name, path string) string {
			out, err := utils.Run(exec.Command("kubectl", "get", kind, name, "-n", testNamespace, "-o", "jsonpath="+path))
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			return strings.TrimSpace(string(out))
		}

		By("verifying the disk push mounted the push Secret, not the build Secret")
		secretRef := jsonPath("imagebuild", actualBuildName, "{.spec.secretRef}")
		pushSecretRef := jsonPath("imagebuild", actualBuildName, "{.spec.pushSecretRef}")
		Expect(pushSecretRef).NotTo(BeEmpty())
		Expect(pushSecretRef).NotTo(Equal(secretRef), "a hybrid build needs separate container and disk push Secrets")
		pipelineRun := jsonPath("imagebuild", actualBuildName, "{.status.pipelineRunName}")
		taskRun := jsonPath("pipelinerun", pipelineRun,
			`{.status.childReferences[?(@.pipelineTaskName=="push-disk-artifact")].name}`)
		Expect(taskRun).NotTo(BeEmpty(), "push-disk-artifact TaskRun should exist in PipelineRun childReferences")
		Expect(jsonPath("taskrun", taskRun, `{.spec.params[?(@.name=="secret-ref")].value}`)).To(Equal(pushSecretRef))

		By("verifying the disk artifact is in the internal registry")
		Expect(jsonPath("imagebuild", actualBuildName, `{.status.artifacts[?(@.kind=="disk")].url}`)).To(
			HavePrefix(internalRegistryURL + "/" + testNamespace + "/"))
	})
})
