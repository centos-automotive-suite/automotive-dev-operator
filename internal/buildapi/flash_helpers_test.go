package buildapi

import (
	"context"
	"fmt"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
	"github.com/containers/image/v5/types"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
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
