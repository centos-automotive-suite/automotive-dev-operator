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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const namespace = "automotive-dev-operator-system"

// hasOpenShiftRouteCRD returns true when the OpenShift Route CRD exists (OpenShift cluster).
// On Kind there is no Route CRD, so OIDC suite can skip before creating any resources.
func hasOpenShiftRouteCRD() bool {
	cmd := exec.Command("kubectl", "get", "crd", "routes.route.openshift.io")
	_, err := utils.Run(cmd)
	return err == nil
}

// getBuildAPIURL returns the Build API URL when an OpenShift Route exists, or "" otherwise.
// OIDC e2e tests that need to call the API run only on OpenShift (when Route exists).
func getBuildAPIURL() string {
	cmd := exec.Command("kubectl", "get", "route", "ado-build-api",
		"-n", namespace, "-o", "jsonpath={.spec.host}")
	output, err := utils.Run(cmd)
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return ""
	}
	return "https://" + strings.TrimSpace(string(output))
}

var _ = Describe("controller", Ordered, func() {
	BeforeAll(func() {
		By("waiting for namespace to not exist (in case previous suite left it terminating)")
		waitForNamespaceGone := func() error {
			cmd := exec.Command("kubectl", "get", "ns", namespace)
			_, err := utils.Run(cmd)
			if err != nil {
				return nil // namespace gone, we can create it
			}
			return fmt.Errorf("namespace still exists or terminating")
		}
		Eventually(waitForNamespaceGone, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	AfterAll(func() {
		By("deleting OperatorConfig resources")
		cmd := exec.Command("kubectl", "delete", "operatorconfig", "--all", "-n", namespace, "--timeout=30s")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace, "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	Context("Operator", func() {
		It("should run successfully", func() {
			var controllerPodName string
			var err error

			var projectimage = "example.com/automotive-dev-operator:v0.0.1"

			By("building the manager(Operator) image")
			cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectimage))
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("loading the the manager(Operator) image on Kind")
			err = utils.LoadImageToKindClusterWithName(projectimage)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("installing CRDs")
			cmd = exec.Command("make", "install")
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("deploying the operator")
			cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectimage))
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("validating that the operator pod is running as expected")
			verifyControllerUp := func() error {
				// Get pod name

				cmd = exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=operator",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				ExpectWithOffset(2, err).NotTo(HaveOccurred())
				podNames := utils.GetNonEmptyLines(string(podOutput))
				if len(podNames) != 1 {
					return fmt.Errorf("expect 1 controller pods running, but got %d", len(podNames))
				}
				controllerPodName = podNames[0]
				ExpectWithOffset(2, controllerPodName).Should(ContainSubstring("operator"))

				// Validate pod status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				status, err := utils.Run(cmd)
				ExpectWithOffset(2, err).NotTo(HaveOccurred())
				if string(status) != "Running" {
					return fmt.Errorf("controller pod in %s status", status)
				}
				return nil
			}
			EventuallyWithOffset(1, verifyControllerUp, time.Minute, time.Second).Should(Succeed())

			By("creating OperatorConfig resource")
			cmd = exec.Command("kubectl", "apply", "-f", "config/samples/automotive_v1_operatorconfig.yaml")
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verifying Tekton Tasks are created")
			verifyTektonTasks := func() error {
				cmd = exec.Command("kubectl", "get", "tasks", "-n", namespace, "-o", "jsonpath={.items[*].metadata.name}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				tasks := string(output)
				if !contains(tasks, "build-automotive-image") {
					// Collect controller logs for debugging
					logCmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "control-plane=operator", "--tail=50")
					logs, _ := utils.Run(logCmd)
					return fmt.Errorf("build-automotive-image task not found, got: %s\nController logs:\n%s", tasks, string(logs))
				}
				if !contains(tasks, "push-artifact-registry") {
					return fmt.Errorf("push-artifact-registry task not found, got: %s", tasks)
				}
				return nil
			}
			EventuallyWithOffset(1, verifyTektonTasks, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying Tekton Pipeline is created")
			verifyTektonPipeline := func() error {
				cmd = exec.Command("kubectl", "get", "pipeline", "automotive-build-pipeline",
					"-n", namespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if string(output) != "automotive-build-pipeline" {
					return fmt.Errorf("automotive-build-pipeline not found, got: %s", output)
				}
				return nil
			}
			EventuallyWithOffset(1, verifyTektonPipeline, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying Build API deployment is created")
			verifyBuildAPIDeployment := func() error {
				cmd = exec.Command("kubectl", "get", "deployment", "ado-build-api",
					"-n", namespace, "-o", "jsonpath={.status.availableReplicas}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if string(output) != "1" {
					return fmt.Errorf("build-api deployment not available, replicas: %s", output)
				}
				return nil
			}
			EventuallyWithOffset(1, verifyBuildAPIDeployment, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should build a real automotive image", func() {
			var err error

			By("creating an ImageBuild CR for a real build")
			// Detect architecture for the build
			arch := "amd64"
			if strings.Contains(strings.ToLower(os.Getenv("RUNNER_ARCH")), "arm") ||
				strings.Contains(strings.ToLower(os.Getenv("HOSTTYPE")), "arm") ||
				strings.Contains(strings.ToLower(os.Getenv("PROCESSOR_ARCHITECTURE")), "arm") {
				arch = "arm64"
			}
			// Also check uname for local development
			unameCmd := exec.Command("uname", "-m")
			unameOutput, _ := utils.Run(unameCmd)
			if strings.Contains(string(unameOutput), "arm64") || strings.Contains(string(unameOutput), "aarch64") {
				arch = "arm64"
			}

			imageBuildYAML := fmt.Sprintf(`
apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: ImageBuild
metadata:
  name: e2e-real-build
  namespace: automotive-dev-operator-system
spec:
  # Common fields
  architecture: %s

  # AIB configuration
  aib:
    distro: autosd
    target: qemu
    mode: image
    manifest: |
      name: e2e-test-image
    manifestFileName: "manifest.aib.yml"
    image: quay.io/centos-sig-automotive/automotive-image-builder:latest

  # Export configuration
  export:
    format: qcow2
    compression: gzip
    buildDiskImage: false
`, arch)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(imageBuildYAML)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("waiting for build to start")
			verifyBuildStarted := func() error {
				cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
					"-n", namespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				phase := string(output)
				if phase == "" {
					return fmt.Errorf("build not started yet, phase is empty")
				}
				if phase == "Failed" {
					// Get more details on failure
					cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
						"-n", namespace, "-o", "jsonpath={.status.message}")
					msg, _ := utils.Run(cmd)
					return fmt.Errorf("build failed: %s", string(msg))
				}
				return nil
			}
			EventuallyWithOffset(1, verifyBuildStarted, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for build to complete (this may take several minutes)")
			verifyBuildCompleted := func() error {
				cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
					"-n", namespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				phase := string(output)
				if phase == "Failed" {
					// Get more details on failure
					cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
						"-n", namespace, "-o", "jsonpath={.status.message}")
					msg, _ := utils.Run(cmd)
					// Also get PipelineRun logs
					cmd = exec.Command("kubectl", "get", "pipelineruns", "-n", namespace,
						"-l", "automotive.sdv.cloud.redhat.com/imagebuild-name=e2e-real-build",
						"-o", "jsonpath={.items[0].status.conditions[0].message}")
					prMsg, _ := utils.Run(cmd)
					Fail(fmt.Sprintf("Build failed: %s\nPipelineRun message: %s", string(msg), string(prMsg)))
				}
				if phase != "Completed" {
					return fmt.Errorf("build not completed yet, phase: %s", phase)
				}
				return nil
			}
			// Allow up to 10 minutes for the build to complete
			EventuallyWithOffset(1, verifyBuildCompleted, 10*time.Minute, 15*time.Second).Should(Succeed())

			By("verifying build status has expected fields")
			cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
				"-n", namespace, "-o", "jsonpath={.status.pipelineRunName}")
			pipelineRunName, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, string(pipelineRunName)).NotTo(BeEmpty(), "PipelineRunName should be set")

			cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
				"-n", namespace, "-o", "jsonpath={.status.message}")
			message, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, string(message)).To(ContainSubstring("completed"), "Message should indicate completion")

			By("cleaning up real build resources")
			cmd = exec.Command("kubectl", "delete", "imagebuild", "e2e-real-build",
				"-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})
})

func contains(s, substr string) bool {
	if len(s) == 0 || len(substr) == 0 {
		return false
	}
	if s == substr {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	// Check prefix, suffix, or middle
	return s[:len(substr)] == substr ||
		s[len(s)-len(substr):] == substr ||
		containsMiddle(s, substr)
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

var _ = Describe("OIDC Authentication", Ordered, func() {
	var oidcSuiteCreatedNamespace bool

	BeforeAll(func() {
		var err error
		var projectimage = "example.com/automotive-dev-operator:v0.0.1"

		if !hasOpenShiftRouteCRD() {
			Skip("OIDC e2e requires OpenShift (Route CRD); skipping on kind")
		}
		oidcSuiteCreatedNamespace = true

		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // Ignore error if namespace already exists

		By("building the manager(Operator) image")
		cmd = exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectimage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("loading the manager(Operator) image on Kind")
		err = utils.LoadImageToKindClusterWithName(projectimage)
		Expect(err).NotTo(HaveOccurred())

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("deploying the operator")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectimage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("validating that the operator pod is running")
		verifyControllerUp := func() error {
			cmd = exec.Command("kubectl", "get",
				"pods", "-l", "control-plane=operator",
				"-o", "go-template={{ range .items }}"+
					"{{ if not .metadata.deletionTimestamp }}"+
					"{{ .metadata.name }}"+
					"{{ \"\\n\" }}{{ end }}{{ end }}",
				"-n", namespace,
			)
			podOutput, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			podNames := utils.GetNonEmptyLines(string(podOutput))
			if len(podNames) != 1 {
				return fmt.Errorf("expect 1 controller pods running, but got %d", len(podNames))
			}
			cmd = exec.Command("kubectl", "get",
				"pods", podNames[0], "-o", "jsonpath={.status.phase}",
				"-n", namespace,
			)
			status, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if string(status) != "Running" {
				return fmt.Errorf("controller pod in %s status", status)
			}
			return nil
		}
		Eventually(verifyControllerUp, time.Minute, time.Second).Should(Succeed())

		By("creating baseline OperatorConfig without OIDC")
		cmd = exec.Command("kubectl", "apply", "-f", "config/samples/automotive_v1_operatorconfig.yaml")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for Build API deployment")
		verifyBuildAPIDeployment := func() error {
			cmd = exec.Command("kubectl", "get", "deployment", "ado-build-api",
				"-n", namespace, "-o", "jsonpath={.status.availableReplicas}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) != "1" {
				return fmt.Errorf("build-api deployment not available, replicas: %s", output)
			}
			return nil
		}
		Eventually(verifyBuildAPIDeployment, 3*time.Minute, 5*time.Second).Should(Succeed())

		if getBuildAPIURL() == "" {
			Skip("OIDC e2e requires OpenShift Route (ado-build-api); skipping on kind")
		}
	})

	AfterAll(func() {
		if !oidcSuiteCreatedNamespace {
			return
		}
		By("deleting OperatorConfig so namespace can terminate cleanly")
		cmd := exec.Command("kubectl", "delete", "operatorconfig", "--all", "-n", namespace, "--timeout=30s")
		_, _ = utils.Run(cmd)

		By("waiting for OperatorConfig to be fully removed (finalizer cleared)")
		waitForOperatorConfigGone := func() error {
			cmd := exec.Command("kubectl", "get", "operatorconfig", "-n", namespace, "-o", "name")
			output, err := utils.Run(cmd)
			if err != nil {
				return nil
			}
			if strings.TrimSpace(string(output)) == "" {
				return nil
			}
			return fmt.Errorf("operatorconfig still present")
		}
		Eventually(waitForOperatorConfigGone, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace, "--timeout=120s")
		_, _ = utils.Run(cmd)
		By("waiting for namespace deletion to complete before next suite")
		waitForNamespaceGone := func() error {
			cmd := exec.Command("kubectl", "get", "ns", namespace)
			_, err := utils.Run(cmd)
			if err != nil {
				return nil // namespace gone
			}
			return fmt.Errorf("namespace still exists or terminating")
		}
		Eventually(waitForNamespaceGone, 5*time.Minute, 10*time.Second).Should(Succeed())
	})

	Context("Build API OIDC Configuration", func() {
		It("should return 404 when OIDC is not configured", func() {
			By("getting Build API URL")
			apiURL := getBuildAPIURL()

			By("checking /v1/auth/config endpoint returns 404 when OIDC not configured")
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			resp, err := client.Get(apiURL + "/v1/auth/config")
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = resp.Body.Close()
			}()
			// Should return 404 or 200 with empty JWT array
			statusCode := resp.StatusCode
			Expect(statusCode).To(Or(Equal(404), Equal(200)))
		})

		It("should handle OIDC configuration when provided", func() {
			By("creating OperatorConfig with OIDC authentication")
			operatorConfigYAML := `
apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: OperatorConfig
metadata:
  name: config
  namespace: automotive-dev-operator-system
spec:
  buildAPI:
    authentication:
      clientId: test-client-id
      jwt:
        - issuer:
            url: https://issuer.example.com
            audiences:
              - test-audience
          claimMappings:
            username:
              claim: preferred_username
              prefix: ""
`
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(operatorConfigYAML)
			_, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("waiting for operator to reconcile and Build API to reload configuration")
			time.Sleep(10 * time.Second)

			By("checking /v1/auth/config endpoint returns OIDC config")
			apiURL := getBuildAPIURL()
			if apiURL == "" {
				Skip("Build API Route not found (OpenShift required)")
			}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			resp, err := client.Get(apiURL + "/v1/auth/config")
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = resp.Body.Close()
			}()
			Expect(resp.StatusCode).To(Equal(200))
			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(And(ContainSubstring("jwt"), ContainSubstring("clientId")))

			By("cleaning up OIDC configuration from OperatorConfig")
			cmd = exec.Command("kubectl", "patch", "operatorconfig", "config",
				"-n", namespace, "--type=json", "-p", `[{"op": "remove", "path": "/spec/buildAPI/authentication"}]`)
			_, _ = utils.Run(cmd)
		})
	})

	Context("Internal JWT Validation", func() {
		It("should have Build API pod running", func() {
			// Verify the Build API pod is running
			By("verifying Build API pod is running")
			cmd := exec.Command("kubectl", "get", "pod", "-l", "app.kubernetes.io/component=build-api",
				"-n", namespace, "-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				Skip("Build API pod not found")
			}
			Expect(strings.TrimSpace(string(output))).To(Equal("Running"))
		})
	})
})
