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

var _ = Describe("Operator Health", Label("operator", "smoke"), Ordered, func() {
	BeforeAll(func() {
		ensureOperatorDeployed()
	})

	It("should have the controller pod running", func() {
		verifyControllerUp := func() error {
			cmd := exec.Command("kubectl", "get",
				"pods", "-l", "control-plane=operator",
				"-o", "go-template={{ range .items }}"+
					"{{ if not .metadata.deletionTimestamp }}"+
					"{{ .metadata.name }}"+
					"{{ \"\\n\" }}{{ end }}{{ end }}",
				"-n", testNamespace,
			)
			podOutput, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			podNames := utils.GetNonEmptyLines(string(podOutput))
			if len(podNames) != 1 {
				return fmt.Errorf("expect 1 controller pods running, but got %d", len(podNames))
			}
			ExpectWithOffset(2, podNames[0]).Should(ContainSubstring("operator"))

			cmd = exec.Command("kubectl", "get",
				"pods", podNames[0], "-o", "jsonpath={.status.phase}",
				"-n", testNamespace,
			)
			status, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			phase := strings.TrimSpace(string(status))
			if phase != statusRunning {
				return fmt.Errorf("controller pod in %s status", phase)
			}
			return nil
		}
		EventuallyWithOffset(1, verifyControllerUp, time.Minute, time.Second).Should(Succeed())
	})

	It("should have Tekton Tasks created", func() {
		verifyTektonTasks := func() error {
			cmd := exec.Command("kubectl", "get", "tasks", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			tasks := string(output)
			if !strings.Contains(tasks, "build-automotive-image") {
				logCmd := exec.Command("kubectl", "logs", "-n", testNamespace,
					"-l", "control-plane=operator", "--tail=50")
				logs, _ := utils.Run(logCmd)
				return fmt.Errorf("build-automotive-image task not found, got: %s\nController logs:\n%s",
					tasks, string(logs))
			}
			if !strings.Contains(tasks, tektonTaskPushArtifactRegistry) {
				return fmt.Errorf("%s task not found, got: %s", tektonTaskPushArtifactRegistry, tasks)
			}
			return nil
		}
		EventuallyWithOffset(1, verifyTektonTasks, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should have the Tekton Pipeline created", func() {
		verifyTektonPipeline := func() error {
			cmd := exec.Command("kubectl", "get", "pipeline", "automotive-build-pipeline",
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
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
	})

	It("should have the Build API deployment available", func() {
		verifyBuildAPIDeployment := func() error {
			cmd := exec.Command("kubectl", "get", "deployment", "ado-build-api",
				"-n", testNamespace, "-o", "jsonpath={.status.availableReplicas}")
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
})
