package buildapi

import (
	"context"
	"net/http"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/bundleverify"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(objs ...runtime.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = automotivev1alpha1.AddToScheme(scheme)
	clientObjs := make([]client.Object, len(objs))
	for i, o := range objs {
		clientObjs[i] = o.(client.Object)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientObjs...).Build()
}

var _ = Describe("verifyTaskBundle", func() {
	var (
		ctx       context.Context
		namespace string
		bundleRef string
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = testNamespace
		bundleRef = "quay.io/example/bundle@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	})

	It("should skip verification when taskBundleVerify is false", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				OSBuilds: &automotivev1alpha1.OSBuildsConfig{
					TaskBundleVerify: false,
				},
			},
		}

		k8sClient := newFakeClient()
		status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(0))
	})

	It("should skip verification when OSBuilds is nil", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{}

		k8sClient := newFakeClient()
		status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(0))
	})

	It("should reject when taskBundleVerify is true but cosignKeyRef is empty", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				OSBuilds: &automotivev1alpha1.OSBuildsConfig{
					TaskBundleVerify: true,
				},
			},
		}

		k8sClient := newFakeClient()
		status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cosign key reference is not configured"))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should reject with 400 when ConfigMap does not exist", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				OSBuilds: &automotivev1alpha1.OSBuildsConfig{
					TaskBundleVerify: true,
					TaskBundleCosignKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "nonexistent-cm"},
						Key:                  "cosign.pub",
					},
				},
			},
		}

		k8sClient := newFakeClient()
		status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should reject when ConfigMap lacks specified key", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				OSBuilds: &automotivev1alpha1.OSBuildsConfig{
					TaskBundleVerify: true,
					TaskBundleCosignKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-cosign-key"},
						Key:                  "cosign.pub",
					},
				},
			},
		}

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cosign-key", Namespace: namespace},
			Data:       map[string]string{"wrong-key": "some-data"},
		}
		k8sClient := newFakeClient(cm)
		status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not contain key \"cosign.pub\""))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should attempt keyless verification when taskBundleCosignKeyless is set", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				FeatureGates: map[string]bool{"KeylessSignatureVerification": true},
				OSBuilds: &automotivev1alpha1.OSBuildsConfig{
					TaskBundleVerify: true,
					TaskBundleCosignKeyless: &automotivev1alpha1.CosignKeylessIdentity{
						CertificateIdentity:   "https://kubernetes.io/namespaces/default/serviceaccounts/pipeline",
						CertificateOIDCIssuer: "https://kubernetes.default.svc",
					},
				},
			},
		}

		k8sClient := newFakeClient()
		status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		// Keyless verification will fail (no Sigstore infra in test), but should
		// attempt it rather than falling through to key-based path.
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("keyless"))
		Expect(status).To(Equal(http.StatusForbidden))
	})

	It("should not require cosignKeyRef when keyless is configured", func() {
		operatorConfig := &automotivev1alpha1.OperatorConfig{
			Spec: automotivev1alpha1.OperatorConfigSpec{
				FeatureGates: map[string]bool{"KeylessSignatureVerification": true},
				OSBuilds: &automotivev1alpha1.OSBuildsConfig{
					TaskBundleVerify: true,
					TaskBundleCosignKeyless: &automotivev1alpha1.CosignKeylessIdentity{
						CertificateIdentity:   "test@example.com",
						CertificateOIDCIssuer: "https://issuer.example.com",
					},
				},
			},
		}

		k8sClient := newFakeClient()
		_, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, bundleRef)
		// Should NOT contain "cosign key reference is not configured" —
		// keyless path should be used instead.
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).ToNot(ContainSubstring("cosign key reference is not configured"))
	})
})

var _ = Describe("verifyWorkspaceImage", func() {
	var (
		ctx       context.Context
		namespace string
		imageRef  string
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = testNamespace
		imageRef = "quay.io/example/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	})

	It("should skip verification when wsConfig is nil", func() {
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, nil, imageRef, nil, featuregates.New(nil))
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(0))
	})

	It("should skip verification when ImageVerify is false", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{ImageVerify: false}
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, featuregates.New(nil))
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(0))
	})

	It("should reject when ImageVerify is true but cosignKeyRef is empty", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{ImageVerify: true}
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, featuregates.New(nil))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cosign key reference is not configured"))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should reject with 400 when ConfigMap does not exist", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{
			ImageVerify: true,
			ImageCosignKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "nonexistent-cm"},
				Key:                  "cosign.pub",
			},
		}
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, featuregates.New(nil))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should reject when ConfigMap lacks specified key", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{
			ImageVerify: true,
			ImageCosignKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "ws-cosign-key"},
				Key:                  "cosign.pub",
			},
		}
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "ws-cosign-key", Namespace: namespace},
			Data:       map[string]string{"wrong-key": "some-data"},
		}
		k8sClient := newFakeClient(cm)
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, featuregates.New(nil))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not contain key \"cosign.pub\""))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should reject keyless verification when feature gate is disabled", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{
			ImageVerify: true,
			ImageCosignKeyless: &automotivev1alpha1.CosignKeylessIdentity{
				CertificateIdentity:   "test@example.com",
				CertificateOIDCIssuer: "https://issuer.example.com",
			},
		}
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, featuregates.New(nil))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("feature gate"))
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should attempt keyless verification when feature gate is enabled", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{
			ImageVerify: true,
			ImageCosignKeyless: &automotivev1alpha1.CosignKeylessIdentity{
				CertificateIdentity:   "test@example.com",
				CertificateOIDCIssuer: "https://issuer.example.com",
			},
		}
		k8sClient := newFakeClient()
		keylessGates := featuregates.New(map[featuregates.FeatureName]bool{
			featuregates.KeylessSignatureVerification: true,
		})
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, keylessGates)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("keyless"))
		Expect(status).To(Equal(http.StatusForbidden))
	})

	It("should not require cosignKeyRef when keyless is configured and gate enabled", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{
			ImageVerify: true,
			ImageCosignKeyless: &automotivev1alpha1.CosignKeylessIdentity{
				CertificateIdentity:   "test@example.com",
				CertificateOIDCIssuer: "https://issuer.example.com",
			},
		}
		k8sClient := newFakeClient()
		keylessGates := featuregates.New(map[featuregates.FeatureName]bool{
			featuregates.KeylessSignatureVerification: true,
		})
		_, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil, keylessGates)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).ToNot(ContainSubstring("cosign key reference is not configured"))
	})
})

var _ = Describe("KeylessIdentityFromAPI", func() {
	It("should map all fields from API type to bundleverify type", func() {
		apiIdentity := &automotivev1alpha1.CosignKeylessIdentity{
			CertificateIdentity:         "https://kubernetes.io/namespaces/ns/serviceaccounts/sa",
			CertificateIdentityRegExp:   "https://kubernetes.io/namespaces/.*/serviceaccounts/.*",
			CertificateOIDCIssuer:       "https://kubernetes.default.svc",
			CertificateOIDCIssuerRegExp: "https://kubernetes\\..*",
			RekorURL:                    "https://rekor.example.com",
		}

		result := bundleverify.KeylessIdentityFromAPI(apiIdentity)
		Expect(result.Subject).To(Equal(apiIdentity.CertificateIdentity))
		Expect(result.SubjectRegExp).To(Equal(apiIdentity.CertificateIdentityRegExp))
		Expect(result.Issuer).To(Equal(apiIdentity.CertificateOIDCIssuer))
		Expect(result.IssuerRegExp).To(Equal(apiIdentity.CertificateOIDCIssuerRegExp))
		Expect(result.RekorURL).To(Equal(apiIdentity.RekorURL))
	})
})

var _ = Describe("resolveTaskBundleRef", func() {
	It("should return empty when secureBuild is false", func() {
		req := &BuildRequest{SecureBuild: false}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).ToNot(HaveOccurred())
		Expect(ref).To(BeEmpty())
		Expect(status).To(Equal(0))
	})

	It("should reject non-digest-pinned explicit ref", func() {
		origFn := loadOperatorConfigFn
		defer func() { loadOperatorConfigFn = origFn }()
		loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{}, nil
		}

		req := &BuildRequest{
			SecureBuild:   true,
			TaskBundleRef: "quay.io/example/bundle:latest",
		}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).To(HaveOccurred())
		Expect(ref).To(BeEmpty())
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should resolve from OperatorConfig when TaskBundleRef is empty", func() {
		origFn := loadOperatorConfigFn
		defer func() { loadOperatorConfigFn = origFn }()
		configRef := "quay.io/example/bundle@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{
						TaskBundleRef:    configRef,
						TaskBundleVerify: false,
					},
				},
			}, nil
		}

		req := &BuildRequest{SecureBuild: true}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).ToNot(HaveOccurred())
		Expect(ref).To(Equal(configRef))
		Expect(status).To(Equal(0))
	})

	It("should reject when OperatorConfig TaskBundleRef is not set", func() {
		origFn := loadOperatorConfigFn
		defer func() { loadOperatorConfigFn = origFn }()
		loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{},
				},
			}, nil
		}

		req := &BuildRequest{SecureBuild: true}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("taskBundleRef is not set"))
		Expect(ref).To(BeEmpty())
		Expect(status).To(Equal(http.StatusBadRequest))
	})

	It("should reject when OperatorConfig is nil", func() {
		origFn := loadOperatorConfigFn
		defer func() { loadOperatorConfigFn = origFn }()
		loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return nil, nil
		}

		req := &BuildRequest{SecureBuild: true}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("OperatorConfig is nil"))
		Expect(ref).To(BeEmpty())
		Expect(status).To(Equal(http.StatusInternalServerError))
	})

	It("should fail closed when OperatorConfig cannot be loaded", func() {
		origFn := loadOperatorConfigFn
		defer func() { loadOperatorConfigFn = origFn }()
		loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return nil, context.DeadlineExceeded
		}

		req := &BuildRequest{SecureBuild: true}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("OperatorConfig could not be read"))
		Expect(ref).To(BeEmpty())
		Expect(status).To(Equal(http.StatusInternalServerError))
	})
})
