package test

import (
	"context"
	"strings"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Reproducible OCI repositories", func() {
	It("rejects tag-only references on builds and schedule templates", func() {
		ctx := context.Background()
		spec := api.ImageBuildSpec{SecureBuild: true, Reproducible: true, AIB: &api.AIBSpec{Distro: "autosd", Target: "qemu", OCIRepoImages: []string{"quay.io/org/rpms:v1"}}}
		build := &api.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "repro-oci", Namespace: "default"}, Spec: spec}
		err := k8sClient.Create(ctx, build)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reproducible builds require digest-pinned OCI repository images"))
		schedule := &api.ScheduledImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "repro-oci-schedule", Namespace: "default"}, Spec: api.ScheduledImageBuildSpec{Schedule: "0 0 * * *", ImageBuildTemplate: api.ImageBuildTemplateSpec{Spec: spec}}}
		err = k8sClient.Create(ctx, schedule)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reproducible builds require digest-pinned OCI repository images"))
		build.Spec.AIB.OCIRepoImages[0] += "@sha256:" + strings.Repeat("a", 64)
		Expect(k8sClient.Create(ctx, build)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, build)).To(Succeed()) })
		schedule.Spec.ImageBuildTemplate.Spec = build.Spec
		Expect(k8sClient.Create(ctx, schedule)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, schedule)).To(Succeed()) })
	})
})
