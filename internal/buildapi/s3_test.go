package buildapi

import (
	"context"
	"net/http"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

var _ = Describe("S3 Integration", func() {

	Describe("createS3Secret", func() {
		It("creates secret with correct data and labels", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			creds := &S3Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			}

			secretName, err := createS3Secret(context.Background(), k8sClient, "my-build", "ns", creds)
			Expect(err).NotTo(HaveOccurred())
			Expect(secretName).To(Equal("my-build-s3-auth"))

			// Verify secret was created
			secret := &corev1.Secret{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      "my-build-s3-auth",
				Namespace: "ns",
			}, secret)
			Expect(err).NotTo(HaveOccurred())

			// Verify data
			Expect(secret.Data["access-key-id"]).To(Equal([]byte("AKIAIOSFODNN7EXAMPLE")))
			Expect(secret.Data["secret-access-key"]).To(Equal([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")))

			// Verify labels
			Expect(secret.Labels).To(HaveKeyWithValue(labels.ManagedBy, labels.ValueBuildAPI))
			Expect(secret.Labels).To(HaveKeyWithValue(labels.BuildName, "my-build"))
			Expect(secret.Labels).To(HaveKeyWithValue(labels.ResourceType, "s3-auth"))
			Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
		})

		It("returns empty string when credentials are nil", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			secretName, err := createS3Secret(context.Background(), k8sClient, "build", "ns", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(secretName).To(BeEmpty())
		})

		It("returns error when access key ID is empty", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			creds := &S3Credentials{
				AccessKeyID:     "",
				SecretAccessKey: "secret",
			}

			_, err := createS3Secret(context.Background(), k8sClient, "build", "ns", creds)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("access key ID"))
		})

		It("returns error when secret access key is empty", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			creds := &S3Credentials{
				AccessKeyID:     "AKIA...",
				SecretAccessKey: "",
			}

			_, err := createS3Secret(context.Background(), k8sClient, "build", "ns", creds)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secret access key"))
		})

	})

	Describe("resolveS3Credentials", func() {
		It("is a no-op when S3Bucket is empty", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			req := &BuildRequest{}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(0))
		})

		It("returns error when both s3Credentials and s3CredentialsSecretName are set", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "existing-secret",
				S3Credentials: &S3Credentials{
					AccessKeyID:     "AKIA...",
					SecretAccessKey: "secret",
				},
			}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).To(HaveOccurred())
			Expect(status).To(Equal(http.StatusBadRequest))
			Expect(err.Error()).To(ContainSubstring("cannot specify both"))
		})

		It("creates secret from inline credentials", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			req := &BuildRequest{
				Name:     "my-build",
				S3Bucket: "my-bucket",
				S3Credentials: &S3Credentials{
					AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
					SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(0))
			Expect(req.S3CredentialsSecretName).To(Equal("my-build-s3-auth"))
		})

		It("returns error when inline credentials have empty keys", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			req := &BuildRequest{
				Name:     "my-build",
				S3Bucket: "my-bucket",
				S3Credentials: &S3Credentials{
					AccessKeyID:     "",
					SecretAccessKey: "",
				},
			}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).To(HaveOccurred())
			Expect(status).To(Equal(http.StatusBadRequest))
		})

		It("succeeds when existing secret is found", func() {
			scheme := newRegistryTestScheme()
			existingSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shared-s3-creds",
					Namespace: "ns",
				},
			}
			k8sClient := newRegistryTestClient(scheme, existingSecret)

			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "shared-s3-creds",
			}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(0))
		})

		It("returns error when existing secret is not found", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "nonexistent-secret",
			}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).To(HaveOccurred())
			Expect(status).To(Equal(http.StatusBadRequest))
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("succeeds when S3Bucket set without credentials for IAM-based auth", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			req := &BuildRequest{
				S3Bucket: "my-bucket",
			}

			status, err := resolveS3Credentials(context.Background(), k8sClient, req, "ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(0))
			Expect(req.S3CredentialsSecretName).To(BeEmpty())
		})
	})

	Describe("buildExportSpec", func() {

		It("creates S3 export with all fields", func() {
			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3Prefix:                "builds/test",
				S3Endpoint:              "https://s3.example.com",
				S3Region:                "us-west-2",
				S3CredentialsSecretName: "my-build-s3-auth",
				S3InsecureSkipTLSVerify: true,
			}

			export := buildExportSpec(req)

			Expect(export.Disk).NotTo(BeNil())
			Expect(export.Disk.S3).NotTo(BeNil())
			Expect(export.Disk.S3.Bucket).To(Equal("my-bucket"))
			Expect(export.Disk.S3.Prefix).To(Equal("builds/test"))
			Expect(export.Disk.S3.Endpoint).To(Equal("https://s3.example.com"))
			Expect(export.Disk.S3.Region).To(Equal("us-west-2"))
			Expect(export.Disk.S3.CredentialsSecret).To(Equal("my-build-s3-auth"))
			Expect(export.Disk.S3.InsecureSkipTLSVerify).To(BeTrue())
		})

		It("creates S3 export with shared secret", func() {
			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "shared-s3-creds",
			}

			export := buildExportSpec(req)

			Expect(export.Disk).NotTo(BeNil())
			Expect(export.Disk.S3).NotTo(BeNil())
			Expect(export.Disk.S3.Bucket).To(Equal("my-bucket"))
			Expect(export.Disk.S3.CredentialsSecret).To(Equal("shared-s3-creds"))
		})

		It("defaults region to us-east-1 when not specified", func() {
			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "my-secret",
			}

			export := buildExportSpec(req)

			Expect(export.Disk.S3.Region).To(Equal("us-east-1"))
		})

		It("creates S3 export without credentials secret for IAM role", func() {
			req := &BuildRequest{
				S3Bucket: "my-bucket",
				// No credentials or secret name - uses IAM role
			}

			export := buildExportSpec(req)

			Expect(export.Disk).NotTo(BeNil())
			Expect(export.Disk.S3).NotTo(BeNil())
			Expect(export.Disk.S3.Bucket).To(Equal("my-bucket"))
			Expect(export.Disk.S3.CredentialsSecret).To(BeEmpty())
		})

		It("does not create S3 export when bucket not specified", func() {
			req := &BuildRequest{
				ExportOCI: "registry.io/image:tag",
			}

			export := buildExportSpec(req)

			Expect(export.Disk).NotTo(BeNil()) // Created for OCI
			Expect(export.Disk.S3).To(BeNil()) // But no S3
		})

		It("creates both OCI and S3 exports", func() {
			req := &BuildRequest{
				ExportOCI:               "registry.io/image:tag",
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "my-secret",
			}

			export := buildExportSpec(req)

			Expect(export.Disk).NotTo(BeNil())
			Expect(export.Disk.OCI).To(Equal("registry.io/image:tag"))
			Expect(export.Disk.S3).NotTo(BeNil())
			Expect(export.Disk.S3.Bucket).To(Equal("my-bucket"))
		})

		It("handles empty string region as default", func() {
			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3Region:                "", // Empty string
				S3CredentialsSecretName: "my-secret",
			}

			export := buildExportSpec(req)

			Expect(export.Disk.S3.Region).To(Equal("us-east-1"))
		})

		It("passes through InsecureSkipTLSVerify when true", func() {
			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "my-secret",
				S3InsecureSkipTLSVerify: true,
			}

			export := buildExportSpec(req)

			Expect(export.Disk.S3.InsecureSkipTLSVerify).To(BeTrue())
		})

		It("defaults InsecureSkipTLSVerify to false", func() {
			req := &BuildRequest{
				S3Bucket:                "my-bucket",
				S3CredentialsSecretName: "my-secret",
			}

			export := buildExportSpec(req)

			Expect(export.Disk.S3.InsecureSkipTLSVerify).To(BeFalse())
		})
	})

	Describe("S3 owner reference handling", func() {
		It("sets owner reference on created secrets", func() {
			scheme := newRegistryTestScheme()
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-build-s3-auth",
					Namespace: "ns",
				},
			}
			build := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-build",
					Namespace: "ns",
					UID:       "test-uid-123",
				},
			}
			k8sClient := newRegistryTestClient(scheme, secret, build)

			err := setSecretOwnerRef(context.Background(), k8sClient, "ns", "my-build-s3-auth", build)
			Expect(err).NotTo(HaveOccurred())

			// Verify owner reference was set
			updated := &corev1.Secret{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      "my-build-s3-auth",
				Namespace: "ns",
			}, updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.OwnerReferences).To(HaveLen(1))
			Expect(updated.OwnerReferences[0].Name).To(Equal("my-build"))
			Expect(updated.OwnerReferences[0].Kind).To(Equal("ImageBuild"))
		})
	})
})
