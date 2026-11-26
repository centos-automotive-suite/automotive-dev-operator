package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/sealedsecrets"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var ctx = context.Background()

var _ = Describe("Sealed secret helpers", func() {
	Describe("buildSealedRegistrySecretData", func() {
		It("builds secret data for username/password auth", func() {
			creds := &buildcontract.RegistryCredentials{
				AuthType:    authTypeUsernamePassword,
				RegistryURL: "quay.io",
				Username:    "user",
				Password:    "pass",
			}

			data, err := buildSealedRegistrySecretData(creds)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(HaveKeyWithValue("REGISTRY_URL", []byte("quay.io")))
			Expect(data).To(HaveKeyWithValue("REGISTRY_USERNAME", []byte("user")))
			Expect(data).To(HaveKeyWithValue("REGISTRY_PASSWORD", []byte("pass")))
			Expect(data).To(HaveKey(".dockerconfigjson"))

			var cfg map[string]map[string]map[string]string
			Expect(json.Unmarshal(data[".dockerconfigjson"], &cfg)).To(Succeed())
			Expect(cfg["auths"]["quay.io"]["auth"]).To(Equal(base64.StdEncoding.EncodeToString([]byte("user:pass"))))
		})

		It("builds secret data for token auth", func() {
			creds := &buildcontract.RegistryCredentials{
				AuthType:    authTypeToken,
				RegistryURL: "quay.io",
				Token:       "token-123",
			}

			data, err := buildSealedRegistrySecretData(creds)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(HaveKeyWithValue("REGISTRY_URL", []byte("quay.io")))
			Expect(data).To(HaveKeyWithValue("REGISTRY_TOKEN", []byte("token-123")))
		})

		It("builds secret data for docker config auth", func() {
			creds := &buildcontract.RegistryCredentials{
				AuthType:     authTypeDockerConfig,
				DockerConfig: `{"auths":{"quay.io":{"auth":"xxx"}}}`,
			}

			data, err := buildSealedRegistrySecretData(creds)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(HaveKeyWithValue("REGISTRY_AUTH_FILE_CONTENT", []byte(creds.DockerConfig)))
			Expect(data).To(HaveKeyWithValue(".dockerconfigjson", []byte(creds.DockerConfig)))
		})

		It("returns error for unsupported auth type", func() {
			creds := &buildcontract.RegistryCredentials{AuthType: "unknown"}
			_, err := buildSealedRegistrySecretData(creds)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported authentication type"))
		})

		It("returns error when required fields are missing", func() {
			creds := &buildcontract.RegistryCredentials{
				AuthType:    authTypeUsernamePassword,
				RegistryURL: "quay.io",
			}
			_, err := buildSealedRegistrySecretData(creds)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("required for username-password authentication"))
		})
	})

	Describe("planSealedSecrets", func() {
		It("derives names for the transient Secrets a full request needs", func() {
			req := &buildcontract.SealedRequest{
				Name:        "job",
				KeyContent:  "key-material",
				KeyPassword: "key-pass",
				RegistryCredentials: &buildcontract.RegistryCredentials{
					Enabled:  true,
					AuthType: authTypeUsernamePassword,
				},
			}
			refs := planSealedSecrets(req)
			Expect(refs.secretRef).To(Equal("job" + sealedsecrets.RegistryAuthSuffix))
			Expect(refs.keySecretRef).To(Equal("job" + sealedsecrets.SealKeySuffix))
			Expect(refs.keyPasswordSecretRef).To(Equal("job" + sealedsecrets.SealKeyPasswordSuffix))
		})

		It("keeps the refs the requester supplied", func() {
			req := &buildcontract.SealedRequest{
				Name:                 "job",
				KeySecretRef:         "external-key",
				KeyPasswordSecretRef: "external-key-password",
			}
			refs := planSealedSecrets(req)
			Expect(refs.secretRef).To(BeEmpty())
			Expect(refs.keySecretRef).To(Equal("external-key"))
			Expect(refs.keyPasswordSecretRef).To(Equal("external-key-password"))
		})
	})

	Describe("createSealedSecrets", func() {
		var (
			cs  *k8sfake.Clientset
			job *api.ImageReseal
		)
		requestWithEverything := func() *buildcontract.SealedRequest {
			return &buildcontract.SealedRequest{
				Name:        "job",
				KeyContent:  "key-material",
				KeyPassword: "key-pass",
				RegistryCredentials: &buildcontract.RegistryCredentials{
					Enabled:     true,
					AuthType:    authTypeUsernamePassword,
					RegistryURL: "quay.io",
					Username:    "user",
					Password:    "pass",
				},
			}
		}

		BeforeEach(func() {
			cs = k8sfake.NewSimpleClientset()
			job = &api.ImageReseal{ObjectMeta: metav1.ObjectMeta{
				Name:      "job",
				Namespace: "test-ns",
				UID:       "job-uid",
			}}
		})

		getSecret := func(ctx context.Context, name string) *corev1.Secret {
			secret, err := cs.CoreV1().Secrets("test-ns").Get(ctx, name, metav1.GetOptions{})
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			return secret
		}

		It("creates each planned Secret born owned by the job", func() {
			req := requestWithEverything()
			refs := planSealedSecrets(req)
			Expect(createSealedSecrets(ctx, cs, "test-ns", req, refs, job)).To(Succeed())

			for suffix, resourceType := range map[string]string{
				sealedsecrets.RegistryAuthSuffix:    "registry-auth",
				sealedsecrets.SealKeySuffix:         "seal-key",
				sealedsecrets.SealKeyPasswordSuffix: "seal-key-password",
			} {
				secret := getSecret(ctx, "job"+suffix)
				Expect(secret.Labels).To(Equal(map[string]string{
					labels.ImageReseal:  "job",
					labels.Transient:    labels.ValueTrue,
					labels.ManagedBy:    labels.ValueBuildAPI,
					labels.PartOf:       labels.ValueAutomotiveDev,
					labels.CreatedBy:    labels.ValueBuildAPICreator,
					labels.ResourceType: resourceType,
				}))
				Expect(secret.OwnerReferences).To(ContainElement(metav1.OwnerReference{
					APIVersion: api.GroupVersion.String(),
					Kind:       "ImageReseal",
					Name:       "job",
					UID:        "job-uid",
				}))
			}
		})

		It("leaves the refs the requester supplied untouched", func() {
			req := &buildcontract.SealedRequest{
				Name:         "job",
				KeySecretRef: "external-key",
			}
			refs := planSealedSecrets(req)
			Expect(createSealedSecrets(ctx, cs, "test-ns", req, refs, job)).To(Succeed())

			_, err := cs.CoreV1().Secrets("test-ns").Get(ctx, "job"+sealedsecrets.SealKeySuffix, metav1.GetOptions{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})
	})
})
