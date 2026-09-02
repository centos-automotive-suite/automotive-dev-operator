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

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestResources(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OperatorConfig Resources Suite")
}

func defaultTestConfig() *automotivev1alpha1.OperatorConfig {
	return &automotivev1alpha1.OperatorConfig{
		Spec: automotivev1alpha1.OperatorConfigSpec{
			OSBuilds: &automotivev1alpha1.OSBuildsConfig{Enabled: true},
		},
	}
}

var _ = Describe("OperatorConfig Resources", func() {
	var r *OperatorConfigReconciler

	BeforeEach(func() {
		r = &OperatorConfigReconciler{}
	})

	Describe("buildBuildAPIDeployment", func() {
		It("should use ado-operator service account", func() {
			deployment := r.buildBuildAPIDeployment("test-namespace", defaultTestConfig())
			Expect(deployment.Spec.Template.Spec.ServiceAccountName).To(Equal("ado-operator"))
		})
	})

	Describe("buildBuildAPIContainers", func() {
		It("should set BUILD_API_NAMESPACE environment variable to provided namespace", func() {
			testNamespace := "custom-test-namespace"
			containers := r.buildBuildAPIContainers(testNamespace, defaultTestConfig())

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
			containers := r.buildBuildAPIContainers("test-namespace", defaultTestConfig())
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
			var parsed map[string]any
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

		It("should have a valid architecture for every target that specifies one", func() {
			var parsed struct {
				Targets map[string]struct {
					Architecture string `yaml:"architecture"`
				} `yaml:"targets"`
			}
			Expect(yaml.Unmarshal([]byte(targetDefaultsYAML), &parsed)).To(Succeed())

			validArchitectures := map[string]bool{"arm64": true, "amd64": true}
			for name, t := range parsed.Targets {
				if t.Architecture == "" {
					continue
				}
				Expect(validArchitectures).To(HaveKey(t.Architecture),
					"target %q has unexpected architecture %q", name, t.Architecture)
			}
		})
	})

	Describe("buildServiceMonitor", func() {
		It("should have correct GVK for ServiceMonitor", func() {
			config := &automotivev1alpha1.MonitoringConfig{Enabled: true}
			sm := r.buildServiceMonitor("test-ns", config)
			Expect(sm.GetKind()).To(Equal("ServiceMonitor"))
			Expect(sm.GroupVersionKind().Group).To(Equal("monitoring.coreos.com"))
			Expect(sm.GroupVersionKind().Version).To(Equal("v1"))
		})

		It("should select services with control-plane=operator label", func() {
			config := &automotivev1alpha1.MonitoringConfig{Enabled: true}
			sm := r.buildServiceMonitor("test-ns", config)
			selector := sm.Object["spec"].(map[string]any)["selector"].(map[string]any)
			matchLabels := selector["matchLabels"].(map[string]any)
			Expect(matchLabels["control-plane"]).To(Equal("operator"))
		})

		It("should use bearerTokenSecret referencing the token secret", func() {
			config := &automotivev1alpha1.MonitoringConfig{Enabled: true}
			sm := r.buildServiceMonitor("test-ns", config)
			endpoints := sm.Object["spec"].(map[string]any)["endpoints"].([]any)
			ep := endpoints[0].(map[string]any)
			tokenRef := ep["bearerTokenSecret"].(map[string]any)
			Expect(tokenRef["name"]).To(Equal(serviceMonitorTokenSecret))
			Expect(tokenRef["key"]).To(Equal("token"))
		})

		It("should use default interval when not specified", func() {
			config := &automotivev1alpha1.MonitoringConfig{Enabled: true}
			sm := r.buildServiceMonitor("test-ns", config)
			endpoints := sm.Object["spec"].(map[string]any)["endpoints"].([]any)
			ep := endpoints[0].(map[string]any)
			Expect(ep["interval"]).To(Equal("30s"))
		})

		It("should use custom interval when specified", func() {
			config := &automotivev1alpha1.MonitoringConfig{Enabled: true, Interval: "15s"}
			sm := r.buildServiceMonitor("test-ns", config)
			endpoints := sm.Object["spec"].(map[string]any)["endpoints"].([]any)
			ep := endpoints[0].(map[string]any)
			Expect(ep["interval"]).To(Equal("15s"))
		})

		It("should scrape /metrics on port https", func() {
			config := &automotivev1alpha1.MonitoringConfig{Enabled: true}
			sm := r.buildServiceMonitor("test-ns", config)
			endpoints := sm.Object["spec"].(map[string]any)["endpoints"].([]any)
			ep := endpoints[0].(map[string]any)
			Expect(ep["path"]).To(Equal("/metrics"))
			Expect(ep["port"]).To(Equal("https"))
			Expect(ep["scheme"]).To(Equal("https"))
		})
	})

	Describe("buildMetricsTokenSecret", func() {
		It("should be a ServiceAccountToken type referencing ado-operator", func() {
			secret := r.buildMetricsTokenSecret("test-ns")
			Expect(secret.Type).To(Equal(corev1.SecretTypeServiceAccountToken))
			Expect(secret.Annotations["kubernetes.io/service-account.name"]).To(Equal("ado-operator"))
		})
	})

	Describe("buildMetricsReaderRoleBinding", func() {
		It("should grant prometheus-user-workload SA from the correct namespace", func() {
			binding := r.buildMetricsReaderRoleBinding("test-ns")
			Expect(binding.Subjects).To(HaveLen(1))
			Expect(binding.Subjects[0]).To(Equal(rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "prometheus-user-workload",
				Namespace: "openshift-user-workload-monitoring",
			}))
		})
	})

	Describe("buildMetricsReaderClusterRoleBinding", func() {
		It("should reference metrics-reader ClusterRole and ado-operator SA", func() {
			binding := r.buildMetricsReaderClusterRoleBinding("test-ns")
			Expect(binding.RoleRef.Name).To(Equal("metrics-reader"))
			Expect(binding.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(binding.Subjects).To(HaveLen(1))
			Expect(binding.Subjects[0].Name).To(Equal("ado-operator"))
			Expect(binding.Subjects[0].Namespace).To(Equal("test-ns"))
		})
	})

	Describe("buildMetricsReaderRole", func() {
		It("should scope secret access to only the metrics token secret", func() {
			role := r.buildMetricsReaderRole("test-ns")
			Expect(role.Rules).To(HaveLen(1))
			Expect(role.Rules[0].Resources).To(Equal([]string{"secrets"}))
			Expect(role.Rules[0].ResourceNames).To(Equal([]string{serviceMonitorTokenSecret}))
			Expect(role.Rules[0].Verbs).To(Equal([]string{"get"}))
		})
	})

	Describe("buildBuildControllerDeployment", func() {
		It("should use ado-build-controller service account", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace", defaultTestConfig())
			Expect(deployment.Spec.Template.Spec.ServiceAccountName).To(Equal("ado-build-controller"))
		})

		It("should run in build mode", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace", defaultTestConfig())
			container := deployment.Spec.Template.Spec.Containers[0]
			Expect(container.Args).To(ContainElement("--mode=build"))
		})

		It("should set pod-level RunAsNonRoot", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace", defaultTestConfig())
			podSec := deployment.Spec.Template.Spec.SecurityContext
			Expect(podSec).NotTo(BeNil())
			Expect(podSec.RunAsNonRoot).NotTo(BeNil())
			Expect(*podSec.RunAsNonRoot).To(BeTrue())
		})

		It("should drop all capabilities and disallow privilege escalation", func() {
			deployment := r.buildBuildControllerDeployment("test-namespace", defaultTestConfig())
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
			deployment := r.buildBuildControllerDeployment(testNamespace, defaultTestConfig())
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
