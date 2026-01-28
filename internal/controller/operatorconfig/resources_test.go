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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func TestResources(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OperatorConfig Resources Suite")
}

var _ = Describe("generateAuthenticationConfigYAML", func() {
	It("should return default config when config is nil", func() {
		result := generateAuthenticationConfigYAML(nil)
		Expect(result).To(ContainSubstring("authentication:"))
		Expect(result).To(ContainSubstring("internal:"))
		Expect(result).To(Or(ContainSubstring("prefix: \"internal:\""), ContainSubstring("prefix: 'internal:'")))
		Expect(result).To(ContainSubstring("jwt:"))
	})

	It("should return default config when BuildAPI is nil", func() {
		config := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{},
		}
		result := generateAuthenticationConfigYAML(config)
		Expect(result).To(ContainSubstring("authentication:"))
		Expect(result).To(ContainSubstring("jwt:"))
	})

	It("should return default config when Authentication is nil", func() {
		config := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{},
			},
		}
		result := generateAuthenticationConfigYAML(config)
		Expect(result).To(ContainSubstring("authentication:"))
		Expect(result).To(ContainSubstring("jwt:"))
	})

	It("should generate config with clientId and JWT authenticators", func() {
		config := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{
					Authentication: &automotivev1alpha1.AuthenticationConfig{
						ClientID: "test-client-id",
						JWT: []apiserverv1beta1.JWTAuthenticator{
							{
								Issuer: apiserverv1beta1.Issuer{
									URL:       "https://issuer.example.com",
									Audiences: []string{"test-audience"},
								},
								ClaimMappings: apiserverv1beta1.ClaimMappings{
									Username: apiserverv1beta1.PrefixedClaimOrExpression{
										Claim:  "preferred_username",
										Prefix: func() *string { s := ""; return &s }(),
									},
								},
							},
						},
					},
				},
			},
		}
		result := generateAuthenticationConfigYAML(config)
		Expect(result).To(ContainSubstring("authentication:"))
		Expect(result).To(ContainSubstring("clientId: test-client-id"))
		Expect(result).To(ContainSubstring("jwt:"))
		Expect(result).To(ContainSubstring("url: https://issuer.example.com"))
		Expect(result).To(ContainSubstring("audiences:"))
		Expect(result).To(ContainSubstring("- test-audience"))
		Expect(result).To(ContainSubstring("claimMappings:"))
		Expect(result).To(ContainSubstring("claim: preferred_username"))
	})

	It("should generate config with custom internal prefix", func() {
		customPrefix := "custom:"
		config := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{
					Authentication: &automotivev1alpha1.AuthenticationConfig{
						Internal: &automotivev1alpha1.InternalAuthConfig{
							Prefix: customPrefix,
						},
					},
				},
			},
		}
		result := generateAuthenticationConfigYAML(config)
		Expect(result).To(ContainSubstring("authentication:"))
		Expect(result).To(ContainSubstring("internal:"))
		Expect(result).To(Or(ContainSubstring("prefix: \""+customPrefix+"\""), ContainSubstring("prefix: '"+customPrefix+"'")))
	})

	It("should not include clientId when empty", func() {
		config := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{
					Authentication: &automotivev1alpha1.AuthenticationConfig{
						ClientID: "",
						JWT:      []apiserverv1beta1.JWTAuthenticator{},
					},
				},
			},
		}
		result := generateAuthenticationConfigYAML(config)
		Expect(result).NotTo(ContainSubstring("clientId:"))
		Expect(result).To(ContainSubstring("jwt:"))
	})

	It("should handle multiple JWT authenticators", func() {
		config := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{
					Authentication: &automotivev1alpha1.AuthenticationConfig{
						JWT: []apiserverv1beta1.JWTAuthenticator{
							{
								Issuer: apiserverv1beta1.Issuer{
									URL:       "https://issuer1.example.com",
									Audiences: []string{"audience1"},
								},
							},
							{
								Issuer: apiserverv1beta1.Issuer{
									URL:       "https://issuer2.example.com",
									Audiences: []string{"audience2"},
								},
							},
						},
					},
				},
			},
		}
		result := generateAuthenticationConfigYAML(config)
		Expect(result).To(ContainSubstring("https://issuer1.example.com"))
		Expect(result).To(ContainSubstring("https://issuer2.example.com"))
		Expect(result).To(ContainSubstring("audience1"))
		Expect(result).To(ContainSubstring("audience2"))
	})
})

var _ = Describe("buildBuildAPIAuthConfigMap", func() {
	var reconciler *OperatorConfigReconciler

	BeforeEach(func() {
		reconciler = &OperatorConfigReconciler{}
	})

	It("should create ConfigMap with default config when owner is nil", func() {
		configMap := reconciler.buildBuildAPIAuthConfigMap(nil)
		Expect(configMap).NotTo(BeNil())
		Expect(configMap.Name).To(Equal("ado-build-api-authentication"))
		Expect(configMap.Namespace).To(Equal("automotive-dev-operator-system"))
		Expect(configMap.Data).To(HaveKey("config"))
		Expect(configMap.Data["config"]).To(ContainSubstring("authentication:"))
		Expect(configMap.OwnerReferences).To(BeEmpty())
		Expect(configMap.Labels).To(HaveKeyWithValue("app.kubernetes.io/name", "automotive-dev-operator"))
		Expect(configMap.Labels).To(HaveKeyWithValue("app.kubernetes.io/component", "build-api"))
		Expect(configMap.Labels).To(HaveKeyWithValue("app.kubernetes.io/part-of", "automotive-dev-operator"))
	})

	It("should create ConfigMap with owner reference when owner is provided", func() {
		owner := &automotivev1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "config",
				Namespace: "automotive-dev-operator-system",
				UID:       types.UID("test-uid"),
			},
			TypeMeta: metav1.TypeMeta{
				APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
				Kind:       "OperatorConfig",
			},
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{
					Authentication: &automotivev1alpha1.AuthenticationConfig{
						ClientID: "test-client",
					},
				},
			},
		}
		configMap := reconciler.buildBuildAPIAuthConfigMap(owner)
		Expect(configMap).NotTo(BeNil())
		Expect(configMap.OwnerReferences).To(HaveLen(1))
		ownerRef := configMap.OwnerReferences[0]
		Expect(ownerRef.Name).To(Equal("config"))
		Expect(ownerRef.UID).To(Equal(types.UID("test-uid")))
		Expect(ownerRef.Kind).To(Equal("OperatorConfig"))
		Expect(ownerRef.APIVersion).To(Equal("automotive.sdv.cloud.redhat.com/v1alpha1"))
		Expect(ownerRef.Controller).NotTo(BeNil())
		Expect(*ownerRef.Controller).To(BeTrue())
		Expect(configMap.Data["config"]).To(ContainSubstring("clientId: test-client"))
	})

	It("should generate ConfigMap with authentication config from owner spec", func() {
		owner := &automotivev1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "config",
				Namespace: "automotive-dev-operator-system",
			},
			Spec: automotivev1alpha1.OperatorConfigSpec{
				BuildAPI: &automotivev1alpha1.BuildAPIConfig{
					Authentication: &automotivev1alpha1.AuthenticationConfig{
						ClientID: "my-client",
						JWT: []apiserverv1beta1.JWTAuthenticator{
							{
								Issuer: apiserverv1beta1.Issuer{
									URL:       "https://sso.example.com",
									Audiences: []string{"my-audience"},
								},
								ClaimMappings: apiserverv1beta1.ClaimMappings{
									Username: apiserverv1beta1.PrefixedClaimOrExpression{
										Claim:  "email",
										Prefix: func() *string { s := "user:"; return &s }(),
									},
								},
							},
						},
					},
				},
			},
		}
		configMap := reconciler.buildBuildAPIAuthConfigMap(owner)
		Expect(configMap.Data["config"]).To(ContainSubstring("clientId: my-client"))
		Expect(configMap.Data["config"]).To(ContainSubstring("https://sso.example.com"))
		Expect(configMap.Data["config"]).To(ContainSubstring("my-audience"))
		Expect(configMap.Data["config"]).To(ContainSubstring("claim: email"))
		Expect(configMap.Data["config"]).To(Or(ContainSubstring("prefix: \"user:\""), ContainSubstring("prefix: 'user:'")))
	})
})
