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

package operatorconfig

import (
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
)

func TestResources(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OperatorConfig Resources Suite")
}

var _ = Describe("OperatorConfig Resources", func() {
	var r *OperatorConfigReconciler

	BeforeEach(func() {
		r = &OperatorConfigReconciler{}
	})

	Describe("buildBuildAPIDeployment", func() {
		It("should use ado-operator service account", func() {
			deployment := r.buildBuildAPIDeployment("test-namespace", false)
			Expect(deployment.Spec.Template.Spec.ServiceAccountName).To(Equal("ado-operator"))
		})

		It("should use ado-operator service account on OpenShift", func() {
			deployment := r.buildBuildAPIDeployment("test-namespace", true)
			Expect(deployment.Spec.Template.Spec.ServiceAccountName).To(Equal("ado-operator"))
		})
	})

	Describe("buildBuildAPIContainers", func() {
		It("should not include oauth-proxy on non-OpenShift", func() {
			containers := r.buildBuildAPIContainers("test-namespace", false)
			Expect(containers).To(HaveLen(1))
			Expect(containers[0].Name).To(Equal("build-api"))
		})

		It("should include oauth-proxy on OpenShift with ado-operator SA", func() {
			containers := r.buildBuildAPIContainers("test-namespace", true)
			Expect(containers).To(HaveLen(2))

			oauthProxy := containers[1]
			Expect(oauthProxy.Name).To(Equal("oauth-proxy"))
			Expect(oauthProxy.Args).To(ContainElement("--openshift-service-account=ado-operator"))
		})

		It("should not reference ado-controller-manager in oauth-proxy args", func() {
			containers := r.buildBuildAPIContainers("test-namespace", true)
			for _, arg := range containers[1].Args {
				Expect(arg).NotTo(ContainSubstring("controller-manager"))
			}
		})

		It("should set BUILD_API_NAMESPACE environment variable to provided namespace", func() {
			testNamespace := "custom-test-namespace"
			containers := r.buildBuildAPIContainers(testNamespace, false)

			buildAPIContainer := containers[0]
			var foundBuildAPINamespace bool
			for _, envVar := range buildAPIContainer.Env {
				if envVar.Name == "BUILD_API_NAMESPACE" {
					foundBuildAPINamespace = true
					Expect(envVar.Value).To(Equal(testNamespace))
					Expect(envVar.ValueFrom).To(BeNil(), "should use direct value, not field reference")
					break
				}
			}
			Expect(foundBuildAPINamespace).To(BeTrue(), "BUILD_API_NAMESPACE environment variable should be present")
		})

		It("should have health check probes configured for build-api container", func() {
			containers := r.buildBuildAPIContainers("test-namespace", false)
			buildAPIContainer := containers[0]

			// Check liveness probe
			Expect(buildAPIContainer.LivenessProbe).NotTo(BeNil())
			Expect(buildAPIContainer.LivenessProbe.HTTPGet).NotTo(BeNil())
			Expect(buildAPIContainer.LivenessProbe.HTTPGet.Path).To(Equal("/v1/healthz"))
			Expect(buildAPIContainer.LivenessProbe.HTTPGet.Port.IntVal).To(Equal(int32(8080)))

			// Check readiness probe
			Expect(buildAPIContainer.ReadinessProbe).NotTo(BeNil())
			Expect(buildAPIContainer.ReadinessProbe.HTTPGet).NotTo(BeNil())
			Expect(buildAPIContainer.ReadinessProbe.HTTPGet.Path).To(Equal("/v1/healthz"))
			Expect(buildAPIContainer.ReadinessProbe.HTTPGet.Port.IntVal).To(Equal(int32(8080)))

			// Check startup probe
			Expect(buildAPIContainer.StartupProbe).NotTo(BeNil())
			Expect(buildAPIContainer.StartupProbe.HTTPGet).NotTo(BeNil())
			Expect(buildAPIContainer.StartupProbe.HTTPGet.Path).To(Equal("/v1/healthz"))
			Expect(buildAPIContainer.StartupProbe.HTTPGet.Port.IntVal).To(Equal(int32(8080)))
			Expect(buildAPIContainer.StartupProbe.FailureThreshold).To(Equal(int32(30))) // 150s startup window
		})
	})

	Describe("targetDefaultsYAML", func() {
		It("should be valid YAML", func() {
			var parsed map[string]interface{}
			err := yaml.Unmarshal([]byte(targetDefaultsYAML), &parsed)
			Expect(err).NotTo(HaveOccurred(), "targetDefaultsYAML should be valid YAML")
		})

		It("should have a targets key with entries", func() {
			var parsed struct {
				Targets map[string]struct {
					Architecture string   `yaml:"architecture"`
					ExtraArgs    []string `yaml:"extraArgs"`
					Include      []string `yaml:"include"`
				} `yaml:"targets"`
			}
			err := yaml.Unmarshal([]byte(targetDefaultsYAML), &parsed)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsed.Targets).NotTo(BeEmpty(), "should have at least one target")
		})

		It("should have a valid architecture for every target", func() {
			var parsed struct {
				Targets map[string]struct {
					Architecture string `yaml:"architecture"`
				} `yaml:"targets"`
			}
			Expect(yaml.Unmarshal([]byte(targetDefaultsYAML), &parsed)).To(Succeed())

			validArchitectures := map[string]bool{"arm64": true, "amd64": true}
			for name, t := range parsed.Targets {
				Expect(t.Architecture).NotTo(BeEmpty(), "target %q should have an architecture", name)
				Expect(validArchitectures).To(HaveKey(t.Architecture),
					"target %q has unexpected architecture %q", name, t.Architecture)
			}
		})
	})

	Describe("buildBuildControllerDeployment", func() {
		It("should use ado-build-controller service account", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace")
			Expect(deployment.Spec.Template.Spec.ServiceAccountName).To(Equal("ado-build-controller"))
		})

		It("should run in build mode", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace")
			container := deployment.Spec.Template.Spec.Containers[0]
			Expect(container.Args).To(ContainElement("--mode=build"))
		})

		It("should set pod-level RunAsNonRoot", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace")
			podSec := deployment.Spec.Template.Spec.SecurityContext
			Expect(podSec).NotTo(BeNil())
			Expect(podSec.RunAsNonRoot).NotTo(BeNil())
			Expect(*podSec.RunAsNonRoot).To(BeTrue())
		})

		It("should drop all capabilities and disallow privilege escalation", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace")
			container := deployment.Spec.Template.Spec.Containers[0]
			sec := container.SecurityContext
			Expect(sec).NotTo(BeNil())
			Expect(sec.AllowPrivilegeEscalation).NotTo(BeNil())
			Expect(*sec.AllowPrivilegeEscalation).To(BeFalse())
			Expect(sec.Capabilities).NotTo(BeNil())
			Expect(sec.Capabilities.Drop).To(ContainElement(corev1.Capability("ALL")))
		})

		It("should set WATCH_NAMESPACE environment variable to provided namespace", func() {
			testNamespace := "custom-test-namespace"
			deployment := r.buildBuildControllerDeployment(testNamespace)
			container := deployment.Spec.Template.Spec.Containers[0]

			var foundWatchNamespace bool
			for _, envVar := range container.Env {
				if envVar.Name == "WATCH_NAMESPACE" {
					foundWatchNamespace = true
					Expect(envVar.Value).To(Equal(testNamespace))
					break
				}
			}
			Expect(foundWatchNamespace).To(BeTrue(), "WATCH_NAMESPACE environment variable should be present")
		})
	})
})
