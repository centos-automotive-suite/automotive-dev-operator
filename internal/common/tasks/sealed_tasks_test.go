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

package tasks

import (
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

func TestSealedTasks(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sealed Tasks Suite")
}

var _ = Describe("Sealed Tasks", func() {

	Describe("SealedTaskName", func() {
		It("should prefix operation with 'sealed-'", func() {
			Expect(SealedTaskName("prepare-reseal")).To(Equal("sealed-prepare-reseal"))
			Expect(SealedTaskName("reseal")).To(Equal("sealed-reseal"))
			Expect(SealedTaskName("extract-for-signing")).To(Equal("sealed-extract-for-signing"))
			Expect(SealedTaskName("inject-signed")).To(Equal("sealed-inject-signed"))
		})
	})

	Describe("SealedOperationNames", func() {
		It("should contain all four operations", func() {
			Expect(SealedOperationNames).To(HaveLen(4))
			Expect(SealedOperationNames).To(ContainElements(
				"prepare-reseal", "reseal", "extract-for-signing", "inject-signed",
			))
		})
	})

	Describe("GenerateSealedTaskForOperation", func() {
		It("should set correct name and namespace", func() {
			task := GenerateSealedTaskForOperation("test-ns", "prepare-reseal")
			Expect(task.Name).To(Equal("sealed-prepare-reseal"))
			Expect(task.Namespace).To(Equal("test-ns"))
		})

		It("should set managed-by labels", func() {
			task := GenerateSealedTaskForOperation("test-ns", "reseal")
			Expect(task.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "automotive-dev-operator"))
			Expect(task.Labels).To(HaveKeyWithValue("app.kubernetes.io/part-of", "automotive-dev"))
		})

		It("should have correct TypeMeta", func() {
			task := GenerateSealedTaskForOperation("test-ns", "reseal")
			Expect(task.TypeMeta.APIVersion).To(Equal("tekton.dev/v1"))
			Expect(task.TypeMeta.Kind).To(Equal("Task"))
		})
	})

	Describe("GenerateSealedTasks", func() {
		It("should generate tasks for all operations", func() {
			allTasks := GenerateSealedTasks("test-ns")
			Expect(allTasks).To(HaveLen(4))
			names := make([]string, len(allTasks))
			for i, t := range allTasks {
				names[i] = t.Name
			}
			Expect(names).To(ContainElements(
				"sealed-prepare-reseal", "sealed-reseal",
				"sealed-extract-for-signing", "sealed-inject-signed",
			))
		})
	})

	Describe("sealedTaskSpec", func() {
		var findParam = func(operation, paramName string) *string {
			task := GenerateSealedTaskForOperation("test-ns", operation)
			for _, p := range task.Spec.Params {
				if p.Name == paramName {
					if p.Default != nil {
						return &p.Default.StringVal
					}
					return nil
				}
			}
			return nil
		}

		var findEnvVar = func(operation, envName string) *string {
			task := GenerateSealedTaskForOperation("test-ns", operation)
			for _, step := range task.Spec.Steps {
				for _, env := range step.Env {
					if env.Name == envName {
						return &env.Value
					}
				}
			}
			return nil
		}

		Describe("params", func() {
			It("should have all required params", func() {
				task := GenerateSealedTaskForOperation("test-ns", "prepare-reseal")
				paramNames := make([]string, len(task.Spec.Params))
				for i, p := range task.Spec.Params {
					paramNames[i] = p.Name
				}
				Expect(paramNames).To(ContainElements(
					"input-ref", "output-ref", "signed-ref",
					"aib-image", "builder-image", "architecture",
				))
			})

			It("should have default for aib-image", func() {
				val := findParam("reseal", "aib-image")
				Expect(val).NotTo(BeNil())
				Expect(*val).To(Equal(AutomotiveImageBuilder))
			})

			It("should have empty defaults for optional params", func() {
				for _, param := range []string{"output-ref", "signed-ref", "builder-image", "architecture"} {
					val := findParam("reseal", param)
					Expect(val).NotTo(BeNil(), "param %s should have a default", param)
					Expect(*val).To(Equal(""), "param %s should default to empty", param)
				}
			})
		})

		Describe("environment variables", func() {
			It("should set OPERATION to the correct operation name", func() {
				for _, op := range SealedOperationNames {
					val := findEnvVar(op, "OPERATION")
					Expect(val).NotTo(BeNil())
					Expect(*val).To(Equal(op))
				}
			})

			It("should map params to env vars", func() {
				envParamMap := map[string]string{
					"INPUT_REF":          "$(params.input-ref)",
					"OUTPUT_REF":         "$(params.output-ref)",
					"SIGNED_REF":         "$(params.signed-ref)",
					"BUILDER_IMAGE":      "$(params.builder-image)",
					"ARCHITECTURE":       "$(params.architecture)",
					"WORKSPACE":          "/workspace/shared",
					"REGISTRY_AUTH_PATH": "/workspace/registry-auth",
				}
				for envName, expectedVal := range envParamMap {
					val := findEnvVar("prepare-reseal", envName)
					Expect(val).NotTo(BeNil(), "env var %s should be set", envName)
					Expect(*val).To(Equal(expectedVal), "env var %s should be %s", envName, expectedVal)
				}
			})
		})

		Describe("workspaces", func() {
			It("should declare all required workspaces", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				wsNames := make([]string, len(task.Spec.Workspaces))
				for i, ws := range task.Spec.Workspaces {
					wsNames[i] = ws.Name
				}
				Expect(wsNames).To(ContainElements(
					"shared", "registry-auth", "sealing-key", "sealing-key-password",
				))
			})

			It("should mark optional workspaces as optional", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				for _, ws := range task.Spec.Workspaces {
					switch ws.Name {
					case "registry-auth", "sealing-key", "sealing-key-password":
						Expect(ws.Optional).To(BeTrue(), "workspace %s should be optional", ws.Name)
					case "shared":
						Expect(ws.Optional).To(BeFalse(), "workspace 'shared' should not be optional")
					}
				}
			})
		})

		Describe("security context", func() {
			It("should run as privileged", func() {
				task := GenerateSealedTaskForOperation("test-ns", "prepare-reseal")
				Expect(task.Spec.StepTemplate).NotTo(BeNil())
				Expect(task.Spec.StepTemplate.SecurityContext).NotTo(BeNil())
				Expect(task.Spec.StepTemplate.SecurityContext.Privileged).NotTo(BeNil())
				Expect(*task.Spec.StepTemplate.SecurityContext.Privileged).To(BeTrue())
			})

			It("should have unconfined_t SELinux type", func() {
				task := GenerateSealedTaskForOperation("test-ns", "prepare-reseal")
				Expect(task.Spec.StepTemplate.SecurityContext.SELinuxOptions).NotTo(BeNil())
				Expect(task.Spec.StepTemplate.SecurityContext.SELinuxOptions.Type).To(Equal("unconfined_t"))
			})
		})

		Describe("volumes", func() {
			It("should mount /dev, container-storage, and run-osbuild", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				volNames := make([]string, len(task.Spec.Volumes))
				for i, v := range task.Spec.Volumes {
					volNames[i] = v.Name
				}
				Expect(volNames).To(ContainElements("dev", "container-storage", "run-osbuild"))
			})

			It("should set SizeLimit on memory-backed volumes", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				for _, v := range task.Spec.Volumes {
					if v.Name == "container-storage" || v.Name == "run-osbuild" {
						Expect(v.EmptyDir).NotTo(BeNil(), "volume %s should be emptyDir", v.Name)
						Expect(v.EmptyDir.SizeLimit).NotTo(BeNil(), "volume %s should have a SizeLimit", v.Name)
						Expect(v.EmptyDir.SizeLimit.String()).To(Equal("4Gi"), "volume %s SizeLimit", v.Name)
					}
				}
			})
		})

		Describe("step", func() {
			It("should have a single step named sealed-op", func() {
				task := GenerateSealedTaskForOperation("test-ns", "inject-signed")
				Expect(task.Spec.Steps).To(HaveLen(1))
				Expect(task.Spec.Steps[0].Name).To(Equal("sealed-op"))
			})

			It("should use aib-image param as the step image", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				Expect(task.Spec.Steps[0].Image).To(Equal("$(params.aib-image)"))
			})

			It("should have a 2-hour timeout", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				Expect(task.Spec.Steps[0].Timeout).NotTo(BeNil())
				Expect(task.Spec.Steps[0].Timeout.Duration.Hours()).To(Equal(2.0))
			})

			It("should embed the sealed operation script", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				Expect(task.Spec.Steps[0].Script).To(Equal(SealedOperationScript))
				Expect(task.Spec.Steps[0].Script).NotTo(BeEmpty())
			})
		})

		Describe("results", func() {
			It("should declare sealed-container result", func() {
				task := GenerateSealedTaskForOperation("test-ns", "reseal")
				Expect(task.Spec.Results).To(HaveLen(1))
				Expect(task.Spec.Results[0].Name).To(Equal("sealed-container"))
			})
		})
	})
})
