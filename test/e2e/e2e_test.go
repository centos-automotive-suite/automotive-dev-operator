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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const (
	namespace = "automotive-dev-operator-system"
	archARM64 = "arm64"
	aarch64   = "aarch64"
)

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
				if !strings.Contains(tasks, "build-automotive-image") {
					// Collect controller logs for debugging
					logCmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "control-plane=operator", "--tail=50")
					logs, _ := utils.Run(logCmd)
					return fmt.Errorf("build-automotive-image task not found, got: %s\nController logs:\n%s", tasks, string(logs))
				}
				if !strings.Contains(tasks, "push-artifact-registry") {
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

		Context("caib image build", func() {
			var portForwardCmd *exec.Cmd
			var registryHost string
			var arch string
			var caibToken string
			var projectimage = "automotive-dev-operator:test"
			var caibBuildTimeout = 45 * time.Minute // max timeout for caib builds

			BeforeAll(func() {
				registryHost = os.Getenv("REGISTRY_HOST")
				if registryHost == "" {
					Skip("REGISTRY_HOST not set; caib build tests require a local registry")
				}

				arch = os.Getenv("ARCH")
				if arch == "" {
					unameCmd := exec.Command("uname", "-m")
					unameOutput, _ := utils.Run(unameCmd)
					switch strings.TrimSpace(string(unameOutput)) {
					case archARM64, aarch64:
						arch = archARM64
					default:
						arch = "amd64"
					}
				}

				By("ensuring namespace has privileged PSA labels")
				cmd := exec.Command("kubectl", "label", "namespace", namespace,
					"pod-security.kubernetes.io/enforce=privileged", "--overwrite")
				_, err := utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
				cmd = exec.Command("kubectl", "label", "namespace", namespace,
					"pod-security.kubernetes.io/audit=privileged", "--overwrite")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "label", "namespace", namespace,
					"pod-security.kubernetes.io/warn=privileged", "--overwrite")
				_, _ = utils.Run(cmd)

				By("building the manager(Operator) image")
				cmd = exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectimage))
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

				By("waiting for operator deployment to be available")
				cmd = exec.Command("kubectl", "wait", "--for=condition=available",
					"--timeout=10m", "deployment/ado-operator", "-n", namespace)
				_, err = utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				By("waiting for Build API deployment to be available")
				cmd = exec.Command("kubectl", "apply", "-f",
					"config/samples/automotive_v1_operatorconfig.yaml")
				_, err = utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				By("waiting for Build API deployment to be available")
				cmd = exec.Command("kubectl", "wait", "--for=condition=available",
					"--timeout=8m", "deployment/ado-build-api", "-n", namespace)
				_, err = utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				By("patching OperatorConfig for Kind registry")
				cmd = exec.Command("kubectl", "patch", "operatorconfig", "config",
					"-n", namespace, "--type=merge",
					"-p", fmt.Sprintf(`{"spec":{"osBuilds":{"clusterRegistryRoute":"%s:5000"}}}`, registryHost))
				_, err = utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				By("waiting for push-artifact-registry Task to be created")
				waitForPushTask := func() error {
					taskCmd := exec.Command("kubectl", "get", "task", "push-artifact-registry", "-n", namespace)
					_, taskErr := utils.Run(taskCmd)
					return taskErr
				}
				EventuallyWithOffset(1, waitForPushTask, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"push-artifact-registry Task was not created in time")

				// Kind-specific workaround: the local registry uses plain HTTP (no TLS),
				// so oras push needs --plain-http. On OpenShift the internal registry has
				// TLS and this flag is not required.
				// runAsUser: 0 is needed because plain Kubernetes lacks OpenShift's SCC
				// (Security Context Constraints) that would grant the push step access to
				// root-owned build artifacts in the shared workspace.
				By("patching push-artifact-registry Task for Kind (plain-http + runAsUser 0)")
				cmd = exec.Command("kubectl", "annotate", "task", "push-artifact-registry",
					"-n", namespace, "automotive.sdv.cloud.redhat.com/unmanaged=true", "--overwrite")
				_, err = utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				cmd = exec.Command("bash", "-c",
					`kubectl get task push-artifact-registry -n `+namespace+` -o json `+
						`| jq '.spec.steps[0].script |= gsub("push --disable-path-validation"; "push --plain-http --disable-path-validation")' `+
						`| jq '.spec.steps[0].securityContext = {"runAsUser": 0}' `+
						`| kubectl replace -f -`)
				_, err = utils.Run(cmd)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				By("ensuring port 8080 is free before starting port-forward")
				if conn, dialErr := net.DialTimeout("tcp", "localhost:8080", 500*time.Millisecond); dialErr == nil {
					_ = conn.Close()
					Fail("port 8080 is already in use; cannot set up port-forward to Build API")
				}

				By("setting up port-forward to Build API")
				portForwardCmd = exec.Command("kubectl", "port-forward",
					"-n", namespace, "svc/ado-build-api", "8080:8080")
				err = portForwardCmd.Start()
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				By("waiting for Build API to respond on port-forward")
				httpClient := &http.Client{Timeout: 2 * time.Second}
				waitForBuildAPI := func() error {
					resp, httpErr := httpClient.Get("http://localhost:8080/v1/healthz")
					if httpErr != nil {
						return httpErr
					}
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return nil
					}
					return fmt.Errorf("unexpected status %d from Build API /v1/healthz", resp.StatusCode)
				}
				EventuallyWithOffset(1, waitForBuildAPI, 30*time.Second, 1*time.Second).Should(Succeed(),
					"Build API on localhost:8080 did not become ready")

				By("creating service account and token")
				cmd = exec.Command("kubectl", "create", "serviceaccount", "caib",
					"-n", namespace, "--dry-run=client", "-o", "yaml")
				saYAML, saErr := utils.Run(cmd)
				ExpectWithOffset(1, saErr).NotTo(HaveOccurred())
				cmd = exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = strings.NewReader(string(saYAML))
				_, saErr = utils.Run(cmd)
				ExpectWithOffset(1, saErr).NotTo(HaveOccurred())

				By("creating caib token")
				cmd = exec.Command("kubectl", "create", "token", "caib",
					"-n", namespace, "--duration=1h")
				tokenOutput, tokenErr := utils.Run(cmd)
				ExpectWithOffset(1, tokenErr).NotTo(HaveOccurred())
				caibToken = strings.TrimSpace(string(tokenOutput))
				ExpectWithOffset(1, caibToken).NotTo(BeEmpty(), "CAIB_TOKEN must not be empty")
				prevToken, hadPrevToken := os.LookupEnv("CAIB_TOKEN")
				prevServer, hadPrevServer := os.LookupEnv("CAIB_SERVER")
				DeferCleanup(func() {
					if hadPrevToken {
						_ = os.Setenv("CAIB_TOKEN", prevToken)
					} else {
						_ = os.Unsetenv("CAIB_TOKEN")
					}
					if hadPrevServer {
						_ = os.Setenv("CAIB_SERVER", prevServer)
					} else {
						_ = os.Unsetenv("CAIB_SERVER")
					}
				})
				setErr := os.Setenv("CAIB_TOKEN", caibToken)
				ExpectWithOffset(1, setErr).NotTo(HaveOccurred())
				setErr = os.Setenv("CAIB_SERVER", "http://localhost:8080")
				ExpectWithOffset(1, setErr).NotTo(HaveOccurred())
			})

			AfterAll(func() {
				if portForwardCmd != nil {
					if portForwardCmd.Process != nil {
						_ = portForwardCmd.Process.Kill()
					}
					_ = portForwardCmd.Wait()
				}
			})

			verifyCaibList := func(caibBuildName string) {
				listCmd := exec.Command("bin/caib", "image", "list")
				listOutput, listErr := utils.Run(listCmd)
				ExpectWithOffset(2, listErr).NotTo(HaveOccurred())
				lines := strings.Split(string(listOutput), "\n")
				found := false
				for _, line := range lines {
					if strings.Contains(line, caibBuildName) {
						ExpectWithOffset(2, line).To(ContainSubstring("Completed"))
						found = true
						break
					}
				}
				ExpectWithOffset(2, found).To(BeTrue(),
					fmt.Sprintf("build %q not found in caib list output:\n%s", caibBuildName, string(listOutput)))
			}

			It("should build container and disk images in parallel via caib", func() {
				containerBuildName := "e2e-test-build-image"
				diskBuildName := "e2e-test-build-disk-image"
				diskDir, tmpErr := os.MkdirTemp("", "caib-disk-*")
				ExpectWithOffset(1, tmpErr).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = os.RemoveAll(diskDir) })
				diskImageOutput := diskDir + "/automotive-os-test2-latest.qcow2"

				type buildResult struct {
					output []byte
					err    error
				}

				ctx, cancel := context.WithTimeout(context.Background(), caibBuildTimeout)
				defer cancel()

				var wg sync.WaitGroup
				containerCh := make(chan buildResult, 1)
				diskCh := make(chan buildResult, 1)

				By("launching container build and disk build in parallel")
				wg.Add(2)

				go func() {
					defer wg.Done()
					cmd := exec.CommandContext(ctx, "bin/caib", "image", "build", "test/config/test-manifest.aib.yml",
						"--name", containerBuildName,
						"--arch", arch,
						"--push", fmt.Sprintf("%s:5000/myorg/automotive-os-test1:latest", registryHost),
						"--follow")
					out, err := utils.RunSafe(cmd)
					containerCh <- buildResult{output: out, err: err}
				}()

				go func() {
					defer wg.Done()
					cmd := exec.CommandContext(ctx, "bin/caib", "image", "build", "test/config/test-manifest.aib.yml",
						"--name", diskBuildName,
						"--arch", arch,
						"--push", fmt.Sprintf("%s:5000/myorg/automotive-os-test2:latest", registryHost),
						"--target", "qemu",
						"--disk",
						"--format", "qcow2",
						"--push-disk", fmt.Sprintf("%s:5000/myorg/automotive-os-test2:latest-disk", registryHost),
						"--output", diskImageOutput,
						"--follow")
					out, err := utils.RunSafe(cmd)
					diskCh <- buildResult{output: out, err: err}
				}()

				done := make(chan struct{})
				go func() {
					wg.Wait()
					close(done)
				}()
				select {
				case <-done:
				case <-ctx.Done():
					Fail(fmt.Sprintf("caib builds did not complete within %v", caibBuildTimeout))
				}
				By("verifying container build completed successfully")
				cr := <-containerCh
				_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib container build (%s) ---\n%s\n", containerBuildName, string(cr.output))
				ExpectWithOffset(1, cr.err).NotTo(HaveOccurred(),
					fmt.Sprintf("container build failed:\n%sError: %v\n", string(cr.output), cr.err))
				ExpectWithOffset(1, string(cr.output)).To(ContainSubstring("Completed"))

				By("verifying disk build completed successfully")
				dr := <-diskCh
				_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib disk build (%s) ---\n%s\n", diskBuildName, string(dr.output))
				ExpectWithOffset(1, dr.err).NotTo(HaveOccurred(),
					fmt.Sprintf("disk build failed:\n%sError: %v\n", string(dr.output), dr.err))
				ExpectWithOffset(1, string(dr.output)).To(ContainSubstring("Completed"))

				By("verifying container build appears in caib list")
				verifyCaibList(containerBuildName)

				By("verifying disk build appears in caib list")
				verifyCaibList(diskBuildName)

				By("verifying disk image file was downloaded")
				diskImageDownloadFile := fmt.Sprintf("%s.gz", diskImageOutput)
				info, statErr := os.Stat(diskImageDownloadFile)
				ExpectWithOffset(1, statErr).NotTo(HaveOccurred())
				ExpectWithOffset(1, info.Mode().IsRegular()).To(BeTrue())
				ExpectWithOffset(1, info.Size()).To(BeNumerically(">", 0))
			})
		})
	})
})

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
