package test

import (
	"context"
	"strings"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Secure builds with OCI repositories", func() {
	It("requires pinned repositories on secure builds and schedule templates", func() {
		ctx := context.Background()
		tag := "quay.io/org/rpms:v1"
		pinned := tag + "@sha256:" + strings.Repeat("a", 64)
		for _, tc := range []struct {
			name, ref            string
			secure, reproducible bool
		}{
			{name: "ordinary-tag", ref: tag},
			{name: "ordinary-digest", ref: pinned},
			{name: "secure-tag", ref: tag, secure: true},
			{name: "secure-digest", ref: pinned, secure: true},
			{name: "repro-tag", ref: tag, secure: true, reproducible: true},
			{name: "repro-digest", ref: pinned, secure: true, reproducible: true},
			{name: "secure-no-repos", secure: true},
			{name: "repro-no-repos", secure: true, reproducible: true},
		} {
			spec := api.ImageBuildSpec{SecureBuild: tc.secure, Reproducible: tc.reproducible, AIB: &api.AIBSpec{Distro: "autosd", Target: "qemu"}}
			if tc.ref != "" {
				spec.AIB.OCIRepoImages = []string{tc.ref}
			}
			build := &api.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: tc.name, Namespace: "default"}, Spec: spec}
			schedule := &api.ScheduledImageBuild{ObjectMeta: metav1.ObjectMeta{Name: tc.name, Namespace: "default"}, Spec: api.ScheduledImageBuildSpec{Schedule: "0 0 * * *", ImageBuildTemplate: api.ImageBuildTemplateSpec{Spec: spec}}}
			for _, obj := range []client.Object{build, schedule} {
				err := k8sClient.Create(ctx, obj)
				if tc.secure && tc.ref == tag {
					Expect(err).To(MatchError(ContainSubstring("secure builds require digest-pinned OCI repository images")))
				} else {
					Expect(err).NotTo(HaveOccurred())
					DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
				}
			}
		}
	})
})
