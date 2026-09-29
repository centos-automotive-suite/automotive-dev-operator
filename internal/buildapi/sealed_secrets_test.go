package buildapi

import (
	"encoding/base64"
	"encoding/json"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

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

	Describe("transientSealedSecretRefs", func() {
		It("returns only transient refs and excludes external key refs", func() {
			req := &buildcontract.SealedRequest{
				KeySecretRef:         "external-key",
				KeyPasswordSecretRef: "external-key-password",
			}
			refs := &sealedSecretRefs{
				secretRef:            "generated-registry",
				keySecretRef:         "external-key",
				keyPasswordSecretRef: "generated-key-password",
			}

			names := transientSealedSecretRefs(req, refs)
			Expect(names).To(ContainElements("generated-registry", "generated-key-password"))
			Expect(names).NotTo(ContainElement("external-key"))
			Expect(names).NotTo(ContainElement("external-key-password"))
		})
	})
})
