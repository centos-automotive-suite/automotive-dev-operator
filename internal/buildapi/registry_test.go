package buildapi

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

var imageStreamGVK = schema.GroupVersionKind{
	Group:   "image.openshift.io",
	Version: "v1",
	Kind:    "ImageStream",
}

var imageStreamTagGVK = schema.GroupVersionKind{
	Group:   "image.openshift.io",
	Version: "v1",
	Kind:    "ImageStreamTag",
}

func newRegistryTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
	Expect(corev1.AddToScheme(scheme)).To(Succeed())
	return scheme
}

func newRegistryTestClient(scheme *runtime.Scheme, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func newUnstructuredImageStream(namespace, name string) *unstructured.Unstructured {
	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(imageStreamGVK)
	is.SetName(name)
	is.SetNamespace(namespace)
	return is
}

func newUnstructuredImageStreamTag(namespace, stream, tag string) *unstructured.Unstructured {
	ist := &unstructured.Unstructured{}
	ist.SetGroupVersionKind(imageStreamTagGVK)
	ist.SetName(stream + ":" + tag)
	ist.SetNamespace(namespace)
	return ist
}

var _ = Describe("Registry", func() {

	Describe("ensureImageStream", func() {
		It("creates ImageStream when it does not exist", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			created, err := ensureImageStream(context.Background(), k8sClient, "ns", "my-stream")
			Expect(err).NotTo(HaveOccurred())
			Expect(created).To(BeTrue())

			// Verify it exists
			is := &unstructured.Unstructured{}
			is.SetGroupVersionKind(imageStreamGVK)
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-stream", Namespace: "ns"}, is)
			Expect(err).NotTo(HaveOccurred())
			Expect(is.GetLabels()).To(HaveKeyWithValue(labels.ManagedBy, labels.ValueBuildAPI))
			Expect(is.GetLabels()).To(HaveKeyWithValue(labels.Transient, labels.ValueTrue))
		})

		It("returns false when ImageStream already exists", func() {
			scheme := newRegistryTestScheme()
			existing := newUnstructuredImageStream("ns", "existing-stream")
			k8sClient := newRegistryTestClient(scheme, existing)

			created, err := ensureImageStream(context.Background(), k8sClient, "ns", "existing-stream")
			Expect(err).NotTo(HaveOccurred())
			Expect(created).To(BeFalse())
		})
	})

	Describe("deleteImageStream", func() {
		It("deletes an existing ImageStream", func() {
			scheme := newRegistryTestScheme()
			existing := newUnstructuredImageStream("other-ns", "to-delete")
			k8sClient := newRegistryTestClient(scheme, existing)

			err := deleteImageStream(context.Background(), k8sClient, "other-ns", "to-delete")
			Expect(err).NotTo(HaveOccurred())

			// Verify deleted
			is := &unstructured.Unstructured{}
			is.SetGroupVersionKind(imageStreamGVK)
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "to-delete", Namespace: "other-ns"}, is)
			Expect(err).To(HaveOccurred())
		})

		It("returns error when ImageStream does not exist", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			err := deleteImageStream(context.Background(), k8sClient, "ns", "nonexistent")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("deleteImageStreamTag", func() {
		It("deletes an existing ImageStreamTag", func() {
			scheme := newRegistryTestScheme()
			existing := newUnstructuredImageStreamTag("ns", "my-stream", "v1")
			k8sClient := newRegistryTestClient(scheme, existing)

			err := deleteImageStreamTag(context.Background(), k8sClient, "ns", "my-stream", "v1")
			Expect(err).NotTo(HaveOccurred())

			// Verify deleted
			ist := &unstructured.Unstructured{}
			ist.SetGroupVersionKind(imageStreamTagGVK)
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-stream:v1", Namespace: "ns"}, ist)
			Expect(err).To(HaveOccurred())
		})

		It("returns error when ImageStreamTag does not exist", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			err := deleteImageStreamTag(context.Background(), k8sClient, "ns", "my-stream", "v1")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("imageStreamHasTags", func() {
		It("returns true when ImageStream has tags", func() {
			scheme := newRegistryTestScheme()
			is := newUnstructuredImageStream("ns", "tagged-stream")
			// Set status.tags via unstructured
			Expect(unstructured.SetNestedSlice(is.Object, []any{
				map[string]any{"tag": "v1"},
			}, "status", "tags")).To(Succeed())
			k8sClient := newRegistryTestClient(scheme, is)

			hasTags, err := imageStreamHasTags(context.Background(), k8sClient, "ns", "tagged-stream")
			Expect(err).NotTo(HaveOccurred())
			Expect(hasTags).To(BeTrue())
		})

		It("returns false when ImageStream has no tags", func() {
			scheme := newRegistryTestScheme()
			is := newUnstructuredImageStream("ns", "empty-stream")
			k8sClient := newRegistryTestClient(scheme, is)

			hasTags, err := imageStreamHasTags(context.Background(), k8sClient, "ns", "empty-stream")
			Expect(err).NotTo(HaveOccurred())
			Expect(hasTags).To(BeFalse())
		})

		It("returns error when ImageStream does not exist", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			_, err := imageStreamHasTags(context.Background(), k8sClient, "ns", "missing")
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("getExternalRegistryRoute", func() {
		It("returns route from OperatorConfig when set", func() {
			scheme := newRegistryTestScheme()
			opConfig := &automotivev1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "ns"},
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{
						ClusterRegistryRoute: "registry.apps.example.com",
					},
				},
			}
			k8sClient := newRegistryTestClient(scheme, opConfig)

			route, err := getExternalRegistryRoute(context.Background(), k8sClient, "ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(route).To(Equal("registry.apps.example.com"))
		})

		It("returns error when no OperatorConfig and no Route", func() {
			scheme := newRegistryTestScheme()
			k8sClient := newRegistryTestClient(scheme)

			_, err := getExternalRegistryRoute(context.Background(), k8sClient, "ns")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cannot determine external registry route"))
		})
	})

	Describe("generateRegistryImageRef", func() {
		It("formats host/namespace/image:tag", func() {
			ref := generateRegistryImageRef("registry.example.com", "my-ns", "my-image", "v1")
			Expect(ref).To(Equal("registry.example.com/my-ns/my-image:v1"))
		})
	})

	Describe("translateToExternalURL", func() {
		It("replaces internal registry URL with external route host", func() {
			internal := "image-registry.openshift-image-registry.svc:5000/ns/stream:tag"
			result := translateToExternalURL(internal, "registry.apps.example.com")
			Expect(result).To(Equal("registry.apps.example.com/ns/stream:tag"))
		})

		It("returns unchanged URL when internal prefix not present", func() {
			external := "quay.io/org/image:latest"
			result := translateToExternalURL(external, "registry.apps.example.com")
			Expect(result).To(Equal("quay.io/org/image:latest"))
		})
	})

	Describe("resolveTokenLifetime", func() {
		var originalFn func(ctx context.Context, c client.Client, ns string) (*automotivev1alpha1.OperatorConfig, error)

		BeforeEach(func() {
			originalFn = loadOperatorConfigFn
		})

		AfterEach(func() {
			loadOperatorConfigFn = originalFn
		})

		It("returns default when loadOperatorConfigFn errors", func() {
			loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return nil, fmt.Errorf("not found")
			}
			lifetime := resolveTokenLifetime(context.Background(), nil, "ns")
			Expect(lifetime).To(Equal(automotivev1alpha1.DefaultRegistryTokenLifetimeSeconds))
		})

		It("returns default when OSBuilds is nil", func() {
			loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return &automotivev1alpha1.OperatorConfig{}, nil
			}
			lifetime := resolveTokenLifetime(context.Background(), nil, "ns")
			Expect(lifetime).To(Equal(automotivev1alpha1.DefaultRegistryTokenLifetimeSeconds))
		})

		It("returns custom value when set", func() {
			loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return &automotivev1alpha1.OperatorConfig{
					Spec: automotivev1alpha1.OperatorConfigSpec{
						OSBuilds: &automotivev1alpha1.OSBuildsConfig{
							RegistryTokenLifetimeSeconds: 7200,
						},
					},
				}, nil
			}
			lifetime := resolveTokenLifetime(context.Background(), nil, "ns")
			Expect(lifetime).To(Equal(int64(7200)))
		})

		It("returns default when config is nil", func() {
			loadOperatorConfigFn = func(_ context.Context, _ client.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return nil, nil
			}
			lifetime := resolveTokenLifetime(context.Background(), nil, "ns")
			Expect(lifetime).To(Equal(automotivev1alpha1.DefaultRegistryTokenLifetimeSeconds))
		})
	})

})
