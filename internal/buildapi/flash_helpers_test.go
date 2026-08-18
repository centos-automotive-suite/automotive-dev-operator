package buildapi

import (
	"context"
	"fmt"
	"net/http"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
	"github.com/containers/image/v5/types"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("BuildLeaseTags", func() {
	DescribeTable("merges tags correctly",
		func(defaults, buildName, userTags, expected string) {
			Expect(BuildLeaseTags(defaults, buildName, userTags)).To(Equal(expected))
		},
		Entry("all parts present",
			"platform=caib", "my-build", "env=staging,team=platform",
			"platform=caib,build-name=my-build,env=staging,team=platform"),
		Entry("no user tags",
			"platform=caib", "my-build", "",
			"platform=caib,build-name=my-build"),
		Entry("no defaults",
			"", "my-build", "env=staging",
			"build-name=my-build,env=staging"),
		Entry("only build name",
			"", "my-build", "",
			"build-name=my-build"),
		Entry("multiple defaults",
			"platform=caib,cluster=prod", "test-build", "team=eng",
			"platform=caib,cluster=prod,build-name=test-build,team=eng"),
	)
})

var _ = Describe("resolveTargetFromImage", func() {
	var originalFn func(context.Context, string, *types.SystemContext) (map[string]string, error)

	BeforeEach(func() {
		originalFn = readImageAnnotationsFn
	})

	AfterEach(func() {
		readImageAnnotationsFn = originalFn
	})

	It("should return target from image annotations", func() {
		readImageAnnotationsFn = func(_ context.Context, _ string, _ *types.SystemContext) (map[string]string, error) {
			return map[string]string{
				oci.Get().AnnotationKey("target"): "j784s4evm",
			}, nil
		}
		Expect(resolveTargetFromImage(context.Background(), "quay.io/test/image:v1", nil)).To(Equal("j784s4evm"))
	})

	It("should return empty when annotation is missing", func() {
		readImageAnnotationsFn = func(_ context.Context, _ string, _ *types.SystemContext) (map[string]string, error) {
			return map[string]string{}, nil
		}
		Expect(resolveTargetFromImage(context.Background(), "quay.io/test/image:v1", nil)).To(BeEmpty())
	})

	It("should return empty on error", func() {
		readImageAnnotationsFn = func(_ context.Context, _ string, _ *types.SystemContext) (map[string]string, error) {
			return nil, fmt.Errorf("connection refused")
		}
		Expect(resolveTargetFromImage(context.Background(), "quay.io/test/image:v1", nil)).To(BeEmpty())
	})

	It("should pass credentials as SystemContext", func() {
		var receivedSysCtx *types.SystemContext
		readImageAnnotationsFn = func(_ context.Context, _ string, sysCtx *types.SystemContext) (map[string]string, error) {
			receivedSysCtx = sysCtx
			return map[string]string{}, nil
		}
		creds := &RegistryCredentials{
			Enabled:  true,
			AuthType: authTypeUsernamePassword,
			Username: "user",
			Password: "pass",
		}
		resolveTargetFromImage(context.Background(), "quay.io/test/image:v1", creds)
		Expect(receivedSysCtx).NotTo(BeNil())
		Expect(receivedSysCtx.DockerAuthConfig).NotTo(BeNil())
		Expect(receivedSysCtx.DockerAuthConfig.Username).To(Equal("user"))
		Expect(receivedSysCtx.DockerAuthConfig.Password).To(Equal("pass"))
	})

	It("should respect context cancellation", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		readImageAnnotationsFn = func(c context.Context, _ string, _ *types.SystemContext) (map[string]string, error) {
			return nil, c.Err()
		}
		Expect(resolveTargetFromImage(ctx, "quay.io/test/image:v1", nil)).To(BeEmpty())
	})
})

var _ = Describe("pinFlashDigest", func() {
	DescribeTable("pins digest onto a registry URL",
		func(registryURL, digest, expected string) {
			Expect(PinFlashDigest(registryURL, digest)).To(Equal(expected))
		},
		Entry("empty digest", "quay.io/org/img:tag", "", "quay.io/org/img:tag"),
		Entry("empty url", "", "sha256:abc", ""),
		Entry("appends digest", "quay.io/org/img:tag", "sha256:abc", "quay.io/org/img:tag@sha256:abc"),
		Entry("already pinned", "quay.io/org/img@sha256:abc", "sha256:def", "quay.io/org/img@sha256:abc"),
	)
})

var _ = Describe("resolveFlashImageFromCatalog", func() {
	newCatalogClient := func(objs ...ctrlclient.Object) ctrlclient.Client {
		scheme := runtime.NewScheme()
		Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
		return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	}

	It("pins spec digest for an Available catalog image", func() {
		img := &automotivev1alpha1.CatalogImage{
			ObjectMeta: metav1.ObjectMeta{Name: "qa-ebbr", Namespace: "test-ns"},
			Spec: automotivev1alpha1.CatalogImageSpec{
				RegistryURL: "quay.io/bzlotnik/qa:disk-ebbr",
				Digest:      "sha256:abc123",
			},
			Status: automotivev1alpha1.CatalogImageStatus{
				Phase: automotivev1alpha1.CatalogImagePhaseAvailable,
			},
		}
		ref, httpErr := resolveFlashImageFromCatalog(context.Background(), newCatalogClient(img), "test-ns", "qa-ebbr")
		Expect(httpErr).To(BeNil())
		Expect(ref).To(Equal("quay.io/bzlotnik/qa:disk-ebbr@sha256:abc123"))
	})

	It("falls back to resolved digest from registry metadata", func() {
		img := &automotivev1alpha1.CatalogImage{
			ObjectMeta: metav1.ObjectMeta{Name: "qa-ebbr", Namespace: "test-ns"},
			Spec:       automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/bzlotnik/qa:disk-ebbr"},
			Status: automotivev1alpha1.CatalogImageStatus{
				Phase:            automotivev1alpha1.CatalogImagePhaseAvailable,
				RegistryMetadata: &automotivev1alpha1.RegistryMetadata{ResolvedDigest: "sha256:from-status"},
			},
		}
		ref, httpErr := resolveFlashImageFromCatalog(context.Background(), newCatalogClient(img), "test-ns", "qa-ebbr")
		Expect(httpErr).To(BeNil())
		Expect(ref).To(Equal("quay.io/bzlotnik/qa:disk-ebbr@sha256:from-status"))
	})

	It("returns 404 when the catalog image is missing", func() {
		_, httpErr := resolveFlashImageFromCatalog(context.Background(), newCatalogClient(), "test-ns", "missing")
		Expect(httpErr).NotTo(BeNil())
		Expect(httpErr.code).To(Equal(http.StatusNotFound))
	})

	It("rejects catalog images that are not Available", func() {
		img := &automotivev1alpha1.CatalogImage{
			ObjectMeta: metav1.ObjectMeta{Name: "qa-ebbr", Namespace: "test-ns"},
			Spec:       automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/bzlotnik/qa:disk-ebbr"},
			Status:     automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhaseFailed},
		}
		_, httpErr := resolveFlashImageFromCatalog(context.Background(), newCatalogClient(img), "test-ns", "qa-ebbr")
		Expect(httpErr).NotTo(BeNil())
		Expect(httpErr.code).To(Equal(http.StatusBadRequest))
		Expect(httpErr.message).To(ContainSubstring("not Available"))
	})
})
