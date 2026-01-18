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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const namespace = "automotive-dev-operator-system"

var _ = Describe("controller", Ordered, func() {
	BeforeAll(func() {
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

			By("deploying the controller-manager")
			cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectimage))
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func() error {
				// Get pod name

				cmd = exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
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
				ExpectWithOffset(2, controllerPodName).Should(ContainSubstring("controller-manager"))

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
					logCmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "control-plane=controller-manager", "--tail=50")
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
				cmd = exec.Command("kubectl", "get", "pipeline", "automotive-build-pipeline", "-n", namespace, "-o", "jsonpath={.metadata.name}")
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
				cmd = exec.Command("kubectl", "get", "deployment", "ado-build-api", "-n", namespace, "-o", "jsonpath={.status.availableReplicas}")
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

		It("should download artifacts via caib CLI", func() {
			var err error

			By("building the caib CLI")
			cmd := exec.Command("make", "build-caib")
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("creating a mock completed ImageBuild CR")
			imageBuildYAML := `
apiVersion: automotive.sdv.cloud.redhat.com/v1alpha1
kind: ImageBuild
metadata:
  name: test-download-build
  namespace: automotive-dev-operator-system
spec:
  distro: autosd
  target: qemu
  architecture: arm64
  exportFormat: qcow2
  mode: image
  serveArtifact: true
  compression: gzip
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(imageBuildYAML)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("creating a mock artifact pod with test file")
			artifactPodYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: test-download-artifact-pod
  namespace: automotive-dev-operator-system
  labels:
    app.kubernetes.io/name: artifact-pod
    automotive.sdv.cloud.redhat.com/imagebuild-name: test-download-build
spec:
  containers:
  - name: fileserver
    image: busybox:latest
    command: ["sh", "-c", "mkdir -p /workspace/shared && echo 'test artifact content for e2e download test' > /workspace/shared/test-artifact.qcow2.gz && sleep 3600"]
    readinessProbe:
      exec:
        command: ["test", "-f", "/workspace/shared/test-artifact.qcow2.gz"]
      initialDelaySeconds: 1
      periodSeconds: 1
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(artifactPodYAML)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("waiting for artifact pod to be ready")
			verifyArtifactPodReady := func() error {
				cmd = exec.Command("kubectl", "get", "pod", "test-download-artifact-pod",
					"-n", namespace, "-o", "jsonpath={.status.containerStatuses[0].ready}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if string(output) != "true" {
					return fmt.Errorf("artifact pod not ready yet: %s", output)
				}
				return nil
			}
			EventuallyWithOffset(1, verifyArtifactPodReady, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("patching ImageBuild status to Completed")
			statusPatch := `{"status":{"phase":"Completed","artifactFileName":"test-artifact.qcow2.gz","message":"Build completed successfully"}}`
			cmd = exec.Command("kubectl", "patch", "imagebuild", "test-download-build",
				"-n", namespace, "--type=merge", "--subresource=status", "-p", statusPatch)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("getting a ServiceAccount token for authentication")
			cmd = exec.Command("kubectl", "create", "token", "ado-controller-manager", "-n", namespace)
			tokenOutput, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			token := strings.TrimSpace(string(tokenOutput))
			ExpectWithOffset(1, token).NotTo(BeEmpty())

			By("creating output directory for download")
			projectDir, err := utils.GetProjectDir()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			outputDir := filepath.Join(projectDir, "test-download-output")
			err = os.MkdirAll(outputDir, 0755)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			defer os.RemoveAll(outputDir)

			By("running caib download via port-forward")
			// Start port-forward to build-api service
			portForwardCmd := exec.Command("kubectl", "port-forward",
				"service/ado-build-api", "18080:8080", "-n", namespace)
			err = portForwardCmd.Start()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			defer func() {
				if portForwardCmd.Process != nil {
					_ = portForwardCmd.Process.Kill()
				}
			}()

			// Wait for port-forward to be ready
			time.Sleep(3 * time.Second)

			// Run caib download
			caibPath := filepath.Join(projectDir, "bin", "caib")
			downloadCmd := exec.Command(caibPath, "download",
				"--server", "http://localhost:18080",
				"--token", token,
				"--name", "test-download-build",
				"--output-dir", outputDir,
			)
			downloadOutput, err := utils.Run(downloadCmd)
			if err != nil {
				// Collect debug info on failure
				debugCmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "app.kubernetes.io/component=build-api", "--tail=50")
				logs, _ := utils.Run(debugCmd)
				Fail(fmt.Sprintf("caib download failed: %v\nOutput: %s\nBuild API logs:\n%s", err, downloadOutput, logs))
			}

			By("verifying the downloaded file exists")
			downloadedFile := filepath.Join(outputDir, "test-artifact.qcow2.gz")
			_, err = os.Stat(downloadedFile)
			ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Downloaded file should exist")

			By("verifying the downloaded file has correct content")
			content, err := os.ReadFile(downloadedFile)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, strings.TrimSpace(string(content))).To(Equal("test artifact content for e2e download test"))

			By("cleaning up test resources")
			cmd = exec.Command("kubectl", "delete", "imagebuild", "test-download-build", "-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "pod", "test-download-artifact-pod", "-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		It("should build a real automotive image", func() {
			var err error

			By("creating a manifest ConfigMap")
			manifestYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: e2e-real-build-manifest
  namespace: automotive-dev-operator-system
data:
  manifest.aib.yml: |
    name: e2e-test-image
`
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(manifestYAML)
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

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
  distro: autosd
  target: qemu
  architecture: %s
  exportFormat: qcow2
  mode: image
  manifestConfigMap: e2e-real-build-manifest
  compression: gzip
  automotiveImageBuilder: quay.io/centos-sig-automotive/automotive-image-builder:latest
`, arch)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
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
				"-n", namespace, "-o", "jsonpath={.status.artifactFileName}")
			artifactFileName, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, string(artifactFileName)).To(ContainSubstring("qcow2"), "Artifact filename should contain qcow2")

			cmd = exec.Command("kubectl", "get", "imagebuild", "e2e-real-build",
				"-n", namespace, "-o", "jsonpath={.status.message}")
			message, err := utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, string(message)).To(ContainSubstring("completed"), "Message should indicate completion")

			By("cleaning up real build resources")
			cmd = exec.Command("kubectl", "delete", "imagebuild", "e2e-real-build", "-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "configmap", "e2e-real-build-manifest", "-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})
})

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
