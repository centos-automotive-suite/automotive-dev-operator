package buildapi

import (
	"context"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

const testPEM = `-----BEGIN CERTIFICATE-----
MIIBvzCCAWWgAwIBAgIUfake0000000000000000000000000000000wDQYJKoZI
hvcNAQELBQAwDjEMMAoGA1UEAxMDY2EwHhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAx
MDAwMDAwWjAOMQwwCgYDVQQDEwNjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7
-----END CERTIFICATE-----`

var _ = Describe("resolveCAForIssuer", func() {
	const (
		operatorNS = "automotive-dev"
		secretNS   = "openshift-ingress-operator"
		cmNS       = "kube-system"
	)

	var (
		ctx    context.Context
		scheme = newRegistryTestScheme()
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	Describe("inline certificateAuthority", func() {
		It("returns the PEM string directly without any k8s lookup", func() {
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthority: testPEM,
			}
			pem, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme), issuer, operatorNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(pem).To(Equal(testPEM))
		})

		It("returns empty string when no CA is configured", func() {
			issuer := automotivev1alpha1.JWTIssuerConfig{}
			pem, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme), issuer, operatorNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(pem).To(BeEmpty())
		})
	})

	Describe("certificateAuthoritySecret", func() {
		It("reads the PEM from the named key", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "router-ca", Namespace: secretNS},
				Data:       map[string][]byte{"tls.crt": []byte(testPEM)},
			}
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
					Name: "router-ca", Namespace: secretNS, Key: "tls.crt",
				},
			}
			pem, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme, secret), issuer, operatorNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(pem).To(Equal(testPEM))
		})

		It("defaults to the operator namespace when Namespace is omitted", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "local-ca", Namespace: operatorNS},
				Data:       map[string][]byte{"ca.crt": []byte(testPEM)},
			}
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
					Name: "local-ca", Key: "ca.crt",
				},
			}
			pem, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme, secret), issuer, operatorNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(pem).To(Equal(testPEM))
		})

		It("returns an error when the Secret does not exist", func() {
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
					Name: "missing-ca", Namespace: secretNS, Key: "tls.crt",
				},
			}
			_, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme), issuer, operatorNS)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("missing-ca"))
		})

		It("returns an error when the key is absent from the Secret", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "router-ca", Namespace: secretNS},
				Data:       map[string][]byte{"other-key": []byte("data")},
			}
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
					Name: "router-ca", Namespace: secretNS, Key: "tls.crt",
				},
			}
			_, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme, secret), issuer, operatorNS)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("tls.crt"))
		})
	})

	Describe("certificateAuthorityConfigMap", func() {
		It("reads the PEM from the named key", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-root-ca.crt", Namespace: cmNS},
				Data:       map[string]string{"ca.crt": testPEM},
			}
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthorityConfigMap: &automotivev1alpha1.ConfigMapKeySelector{
					Name: "kube-root-ca.crt", Namespace: cmNS, Key: "ca.crt",
				},
			}
			pem, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme, cm), issuer, operatorNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(pem).To(Equal(testPEM))
		})

		It("defaults to the operator namespace when Namespace is omitted", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "local-ca-cm", Namespace: operatorNS},
				Data:       map[string]string{"ca.crt": testPEM},
			}
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthorityConfigMap: &automotivev1alpha1.ConfigMapKeySelector{
					Name: "local-ca-cm", Key: "ca.crt",
				},
			}
			pem, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme, cm), issuer, operatorNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(pem).To(Equal(testPEM))
		})

		It("returns an error when the ConfigMap does not exist", func() {
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthorityConfigMap: &automotivev1alpha1.ConfigMapKeySelector{
					Name: "missing-cm", Namespace: cmNS, Key: "ca.crt",
				},
			}
			_, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme), issuer, operatorNS)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("missing-cm"))
		})

		It("returns an error when the key is absent from the ConfigMap", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-root-ca.crt", Namespace: cmNS},
				Data:       map[string]string{"other-key": "data"},
			}
			issuer := automotivev1alpha1.JWTIssuerConfig{
				CertificateAuthorityConfigMap: &automotivev1alpha1.ConfigMapKeySelector{
					Name: "kube-root-ca.crt", Namespace: cmNS, Key: "ca.crt",
				},
			}
			_, err := resolveCAForIssuer(ctx, newRegistryTestClient(scheme, cm), issuer, operatorNS)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ca.crt"))
		})
	})
})

var _ = Describe("toUpstreamJWTAuthenticators", func() {
	const operatorNS = "automotive-dev"

	var (
		ctx    context.Context
		scheme = newRegistryTestScheme()
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("converts an inline CA config to the upstream type", func() {
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:                  "https://keycloak.example.com/realms/openshift",
					Audiences:            []string{"caib-cli"},
					CertificateAuthority: testPEM,
				},
			},
		}

		result, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme), configs, operatorNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(HaveLen(1))
		Expect(result[0].Issuer.URL).To(Equal("https://keycloak.example.com/realms/openshift"))
		Expect(result[0].Issuer.Audiences).To(ConsistOf("caib-cli"))
		Expect(result[0].Issuer.CertificateAuthority).To(Equal(testPEM))
	})

	It("resolves a CA from a Secret and injects it into the upstream type", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "router-ca", Namespace: "openshift-ingress-operator"},
			Data:       map[string][]byte{"tls.crt": []byte(testPEM)},
		}
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:       "https://keycloak.example.com/realms/openshift",
					Audiences: []string{"caib-cli"},
					CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
						Name:      "router-ca",
						Namespace: "openshift-ingress-operator",
						Key:       "tls.crt",
					},
				},
			},
		}

		result, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme, secret), configs, operatorNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(HaveLen(1))
		Expect(result[0].Issuer.CertificateAuthority).To(Equal(testPEM))
	})

	It("resolves a CA from a ConfigMap and injects it into the upstream type", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-root-ca.crt", Namespace: "kube-system"},
			Data:       map[string]string{"ca.crt": testPEM},
		}
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:       "https://keycloak.example.com/realms/openshift",
					Audiences: []string{"caib-cli"},
					CertificateAuthorityConfigMap: &automotivev1alpha1.ConfigMapKeySelector{
						Name:      "kube-root-ca.crt",
						Namespace: "kube-system",
						Key:       "ca.crt",
					},
				},
			},
		}

		result, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme, cm), configs, operatorNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(HaveLen(1))
		Expect(result[0].Issuer.CertificateAuthority).To(Equal(testPEM))
	})

	It("sets DiscoveryURL pointer when the field is non-empty", func() {
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:          "https://keycloak.example.com/realms/openshift",
					Audiences:    []string{"caib-cli"},
					DiscoveryURL: "https://oidc.local/.well-known/openid-configuration",
				},
			},
		}

		result, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme), configs, operatorNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result[0].Issuer.DiscoveryURL).NotTo(BeNil())
		Expect(*result[0].Issuer.DiscoveryURL).To(Equal("https://oidc.local/.well-known/openid-configuration"))
	})

	It("leaves DiscoveryURL nil when the field is empty", func() {
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:       "https://keycloak.example.com/realms/openshift",
					Audiences: []string{"caib-cli"},
				},
			},
		}

		result, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme), configs, operatorNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result[0].Issuer.DiscoveryURL).To(BeNil())
	})

	It("returns an error when a referenced Secret is missing", func() {
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:       "https://keycloak.example.com/realms/openshift",
					Audiences: []string{"caib-cli"},
					CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
						Name: "missing-ca", Namespace: "some-ns", Key: "tls.crt",
					},
				},
			},
		}

		_, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme), configs, operatorNS)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("missing-ca"))
	})

	It("converts multiple issuers independently", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ca-secret", Namespace: operatorNS},
			Data:       map[string][]byte{"tls.crt": []byte(testPEM)},
		}
		configs := []automotivev1alpha1.JWTAuthenticatorConfig{
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL: "https://issuer1.example.com", Audiences: []string{"aud1"},
				},
			},
			{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:       "https://issuer2.example.com",
					Audiences: []string{"aud2"},
					CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{
						Name: "ca-secret", Key: "tls.crt",
					},
				},
			},
		}

		result, err := toUpstreamJWTAuthenticators(ctx, newRegistryTestClient(scheme, secret), configs, operatorNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(HaveLen(2))
		Expect(result[0].Issuer.URL).To(Equal("https://issuer1.example.com"))
		Expect(result[0].Issuer.CertificateAuthority).To(BeEmpty())
		Expect(result[1].Issuer.URL).To(Equal("https://issuer2.example.com"))
		Expect(result[1].Issuer.CertificateAuthority).To(Equal(testPEM))
	})
})
