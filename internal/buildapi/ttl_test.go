package buildapi

import (
	"context"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("resolveAndClampTTL", func() {
	var server *APIServer

	BeforeEach(func() {
		server = newTestServer(GinkgoT(), nil)
	})

	It("passes through empty TTL unchanged", func() {
		result, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(""))
	})

	It("passes through zero TTL when no max configured", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return nil, nil
		}

		result, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "0")
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("0"))
	})

	It("rejects zero TTL when MaxBuildTTL is set", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{
						MaxBuildTTL: "72h",
					},
				},
			}, nil
		}

		_, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "0")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not allowed when MaxBuildTTL is set"))
	})

	It("returns valid TTL as-is when no max configured", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{},
				},
			}, nil
		}

		result, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "48h")
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("48h"))
	})

	It("rejects TTL exceeding MaxBuildTTL", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{
						MaxBuildTTL: "72h",
					},
				},
			}, nil
		}

		_, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "168h")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceeds maximum"))
	})

	It("allows TTL within MaxBuildTTL", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{
						MaxBuildTTL: "72h",
					},
				},
			}, nil
		}

		result, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "48h")
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("48h"))
	})

	It("rejects invalid TTL format", func() {
		_, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "not-a-duration")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid TTL"))
	})

	It("rejects negative TTL", func() {
		_, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "-1h")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must not be negative"))
	})

	It("ignores MaxBuildTTL when set to zero", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					OSBuilds: &automotivev1alpha1.OSBuildsConfig{
						MaxBuildTTL: "0",
					},
				},
			}, nil
		}

		result, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "999h")
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("999h"))
	})

	It("handles missing OperatorConfig gracefully", func() {
		server.deps.loadOperatorConfig = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
			return nil, nil
		}

		result, err := server.resolveAndClampTTL(context.Background(), nil, "test-ns", "48h")
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("48h"))
	})
})
