package test

import (
	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Git source repository admission", func() {
	for _, scheduled := range []bool{false, true} {
		kind := "ImageBuild"
		if scheduled {
			kind = "ScheduledImageBuild"
		}
		DescribeTable(kind,
			func(mutate func(*api.ImageBuildSpec), valid bool) {
				spec := api.ImageBuildSpec{AIB: &api.AIBSpec{
					Distro: "autosd", Target: "qemu",
					GitSource:     &api.GitSource{URL: "https://git.example.com/os.git", ManifestPath: "images/os.aib.yml"},
					OCIRepoImages: []string{"quay.io/example/rpms:v1"},
				}}
				mutate(&spec)
				meta := metav1.ObjectMeta{GenerateName: "git-oci-", Namespace: "default"}
				var object client.Object = &api.ImageBuild{ObjectMeta: meta, Spec: spec}
				if scheduled {
					object = &api.ScheduledImageBuild{ObjectMeta: meta, Spec: api.ScheduledImageBuildSpec{
						Schedule: "0 0 * * *", ImageBuildTemplate: api.ImageBuildTemplateSpec{Spec: spec},
					}}
				}
				err := k8sClient.Create(ctx, object)
				if err == nil {
					DeferCleanup(func() { Expect(k8sClient.Delete(ctx, object)).To(Succeed()) })
				}
				if valid {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(HaveOccurred())
				}
			},
			Entry("allows OCI RPMs with a Git manifest", func(s *api.ImageBuildSpec) {}, true),
			Entry("rejects multiple OCI repositories", func(s *api.ImageBuildSpec) {
				s.AIB.OCIRepoImages = append(s.AIB.OCIRepoImages, "quay.io/example/rpms:v2")
			}, false),
			Entry("rejects inline manifests", func(s *api.ImageBuildSpec) { s.AIB.Manifest = "name: demo" }, false),
			Entry("rejects inline lockfiles", func(s *api.ImageBuildSpec) { s.AIB.Lockfile = `{"version":1}` }, false),
			Entry("rejects disk mode", func(s *api.ImageBuildSpec) { s.AIB.Mode = "disk" }, false),
			Entry("rejects uploads", func(s *api.ImageBuildSpec) { s.AIB.InputFilesServer = true }, false),
			Entry("rejects workspaces", func(s *api.ImageBuildSpec) { s.Workspace = "dev" }, false),
			Entry("rejects cache PVCs", func(s *api.ImageBuildSpec) { s.BuildCachePVC = "cache" }, false),
		)
	}
})
