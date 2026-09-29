package buildapi

import (
	"context"
	"net/http"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
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
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, nil, imageRef, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(0))
	})

	It("should skip verification when ImageVerify is false", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{ImageVerify: false}
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(status).To(Equal(0))
	})

	It("should reject when ImageVerify is true but cosignKeyRef is empty", func() {
		wsConfig := &automotivev1alpha1.WorkspacesConfig{ImageVerify: true}
		k8sClient := newFakeClient()
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil)
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
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil)
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
		status, err := verifyWorkspaceImage(ctx, k8sClient, namespace, wsConfig, imageRef, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not contain key \"cosign.pub\""))
		Expect(status).To(Equal(http.StatusBadRequest))
	})
})

var _ = Describe("resolveTaskBundleRef", func() {
	It("should return empty when secureBuild is false", func() {
		req := &buildcontract.BuildRequest{SecureBuild: false}
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

		req := &buildcontract.BuildRequest{
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

		req := &buildcontract.BuildRequest{SecureBuild: true}
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

		req := &buildcontract.BuildRequest{SecureBuild: true}
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

		req := &buildcontract.BuildRequest{SecureBuild: true}
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

		req := &buildcontract.BuildRequest{SecureBuild: true}
		k8sClient := newFakeClient()
		ref, status, err := resolveTaskBundleRef(context.Background(), k8sClient, "ns", req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("OperatorConfig could not be read"))
		Expect(ref).To(BeEmpty())
		Expect(status).To(Equal(http.StatusInternalServerError))
	})
})
