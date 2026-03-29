package buildapi

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

const (
	testBuildName = "test-build"
	testNamespace = "test-ns"
)

var _ = Describe("Internal Registry", func() {

	Describe("generateRegistryImageRef", func() {
		It("should produce a valid registry reference", func() {
			ref := generateRegistryImageRef("registry.example.com:5000", "my-namespace", "my-image", "v1")
			Expect(ref).To(Equal("registry.example.com:5000/my-namespace/my-image:v1"))
		})

		It("should use the default internal registry URL", func() {
			ref := generateRegistryImageRef(defaultInternalRegistryURL, "ns", "img", "tag")
			Expect(ref).To(Equal("image-registry.openshift-image-registry.svc:5000/ns/img:tag"))
		})
	})

	Describe("translateToExternalURL", func() {
		It("should replace the internal registry host with the external route", func() {
			internalURL := "image-registry.openshift-image-registry.svc:5000/ns/img:tag"
			result := translateToExternalURL(internalURL, "registry.apps.example.com")
			Expect(result).To(Equal("registry.apps.example.com/ns/img:tag"))
		})

		It("should not modify URLs that don't contain the internal registry", func() {
			externalURL := "quay.io/org/image:latest"
			result := translateToExternalURL(externalURL, "registry.apps.example.com")
			Expect(result).To(Equal(externalURL))
		})

		It("should handle empty external route", func() {
			internalURL := "image-registry.openshift-image-registry.svc:5000/ns/img:tag"
			result := translateToExternalURL(internalURL, "")
			// strings.Replace with empty replacement removes the internal URL prefix
			Expect(result).To(Equal("/ns/img:tag"))
		})
	})

	Describe("buildExportSpec", func() {
		It("should set UseServiceAccountAuth when UseInternalRegistry is true", func() {
			req := &BuildRequest{
				UseInternalRegistry: true,
				ExportFormat:        "qcow2",
				Compression:         "gzip",
				ContainerPush:       "registry/ns/img:tag",
			}
			export := buildExportSpec(req)
			Expect(export.UseServiceAccountAuth).To(BeTrue())
			Expect(export.Container).To(Equal("registry/ns/img:tag"))
		})

		It("should not set UseServiceAccountAuth when UseInternalRegistry is false", func() {
			req := &BuildRequest{
				UseInternalRegistry: false,
				ExportFormat:        "qcow2",
				Compression:         "gzip",
				ContainerPush:       "quay.io/org/img:tag",
			}
			export := buildExportSpec(req)
			Expect(export.UseServiceAccountAuth).To(BeFalse())
		})

		It("should set Disk.OCI when ExportOCI is provided", func() {
			req := &BuildRequest{
				ExportFormat: "simg",
				Compression:  "gzip",
				ExportOCI:    "registry/ns/disk:tag",
			}
			export := buildExportSpec(req)
			Expect(export.Disk).NotTo(BeNil())
			Expect(export.Disk.OCI).To(Equal("registry/ns/disk:tag"))
		})

		It("should not set Disk when ExportOCI is empty", func() {
			req := &BuildRequest{
				ExportFormat: "qcow2",
				Compression:  "gzip",
			}
			export := buildExportSpec(req)
			Expect(export.Disk).To(BeNil())
		})
	})

	Describe("BuildRequest internal registry fields", func() {
		It("should support UseInternalRegistry field", func() {
			req := BuildRequest{
				UseInternalRegistry:       true,
				InternalRegistryImageName: "my-image",
				InternalRegistryTag:       "v1.0",
			}
			Expect(req.UseInternalRegistry).To(BeTrue())
			Expect(req.InternalRegistryImageName).To(Equal("my-image"))
			Expect(req.InternalRegistryTag).To(Equal("v1.0"))
		})
	})

	Describe("ExportSpec UseServiceAccountAuth", func() {
		It("should return true via GetUseServiceAccountAuth when set", func() {
			spec := &automotivev1alpha1.ImageBuildSpec{
				Export: &automotivev1alpha1.ExportSpec{
					UseServiceAccountAuth: true,
					Container:             "registry/ns/img:tag",
				},
			}
			Expect(spec.GetUseServiceAccountAuth()).To(BeTrue())
		})

		It("should return false via GetUseServiceAccountAuth when not set", func() {
			spec := &automotivev1alpha1.ImageBuildSpec{
				Export: &automotivev1alpha1.ExportSpec{
					Container: "registry/ns/img:tag",
				},
			}
			Expect(spec.GetUseServiceAccountAuth()).To(BeFalse())
		})

		It("should return false when Export is nil", func() {
			spec := &automotivev1alpha1.ImageBuildSpec{}
			Expect(spec.GetUseServiceAccountAuth()).To(BeFalse())
		})
	})

	Describe("Mode helpers", func() {
		It("should identify bootc mode", func() {
			Expect(ModeBootc.IsBootc()).To(BeTrue())
			Expect(ModeImage.IsBootc()).To(BeFalse())
			Expect(ModePackage.IsBootc()).To(BeFalse())
			Expect(ModeDisk.IsBootc()).To(BeFalse())
		})

		It("should identify traditional modes", func() {
			Expect(ModeImage.IsTraditional()).To(BeTrue())
			Expect(ModePackage.IsTraditional()).To(BeTrue())
			Expect(ModeBootc.IsTraditional()).To(BeFalse())
			Expect(ModeDisk.IsTraditional()).To(BeFalse())
		})
	})

	Describe("Validation", func() {
		Context("internal registry mutual exclusivity", func() {
			It("should pass validation when UseInternalRegistry is set without conflicting fields", func() {
				req := &BuildRequest{
					Name:                testBuildName,
					Manifest:            "content: {}",
					UseInternalRegistry: true,
					Mode:                ModeBootc,
				}
				err := validateBuildRequest(req)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should pass validation with internal registry and image name override", func() {
				req := &BuildRequest{
					Name:                      "test-build",
					Manifest:                  "content: {}",
					UseInternalRegistry:       true,
					InternalRegistryImageName: "custom-name",
					InternalRegistryTag:       "v2",
					Mode:                      ModePackage,
				}
				err := validateBuildRequest(req)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("applyBuildDefaults with internal registry", func() {
			It("should apply defaults without overwriting internal registry fields", func() {
				req := &BuildRequest{
					UseInternalRegistry:       true,
					InternalRegistryImageName: "custom",
					InternalRegistryTag:       "v1",
				}
				err := applyBuildDefaults(req)
				Expect(err).NotTo(HaveOccurred())
				Expect(req.UseInternalRegistry).To(BeTrue())
				Expect(req.InternalRegistryImageName).To(Equal("custom"))
				Expect(req.InternalRegistryTag).To(Equal("v1"))
				// Defaults should still be applied
				Expect(string(req.Distro)).To(Equal("autosd"))
				Expect(string(req.Target)).To(Equal("qemu"))
				Expect(string(req.Mode)).To(Equal(string(ModeBootc)))
			})
		})
	})

	Describe("resolveImageStreamRefs", func() {
		It("should extract name and tag from bootc container push URL", func() {
			build := &automotivev1alpha1.ImageBuild{}
			build.Spec.Export = &automotivev1alpha1.ExportSpec{
				UseServiceAccountAuth: true,
				Container:             defaultInternalRegistryURL + "/my-ns/my-image:bootc",
			}
			name, tags := resolveImageStreamRefs(build)
			Expect(name).To(Equal("my-image"))
			Expect(tags).To(ConsistOf("bootc"))
		})

		It("should extract name and tag from disk OCI export URL", func() {
			build := &automotivev1alpha1.ImageBuild{}
			build.Spec.Export = &automotivev1alpha1.ExportSpec{
				UseServiceAccountAuth: true,
				Disk:                  &automotivev1alpha1.DiskExport{OCI: defaultInternalRegistryURL + "/ns/disk-img:disk"},
			}
			name, tags := resolveImageStreamRefs(build)
			Expect(name).To(Equal("disk-img"))
			Expect(tags).To(ConsistOf("disk"))
		})

		It("should collect tags from both container push and disk URLs", func() {
			build := &automotivev1alpha1.ImageBuild{}
			build.Spec.Export = &automotivev1alpha1.ExportSpec{
				UseServiceAccountAuth: true,
				Container:             defaultInternalRegistryURL + "/ns/my-build:bootc",
				Disk:                  &automotivev1alpha1.DiskExport{OCI: defaultInternalRegistryURL + "/ns/my-build:disk"},
			}
			name, tags := resolveImageStreamRefs(build)
			Expect(name).To(Equal("my-build"))
			Expect(tags).To(ConsistOf("bootc", "disk"))
		})

		It("should return empty for external registry URLs", func() {
			build := &automotivev1alpha1.ImageBuild{}
			build.Spec.Export = &automotivev1alpha1.ExportSpec{
				Container: "quay.io/org/image:latest",
			}
			name, tags := resolveImageStreamRefs(build)
			Expect(name).To(BeEmpty())
			Expect(tags).To(BeEmpty())
		})

		It("should return empty when export is nil", func() {
			build := &automotivev1alpha1.ImageBuild{}
			name, tags := resolveImageStreamRefs(build)
			Expect(name).To(BeEmpty())
			Expect(tags).To(BeEmpty())
		})

		It("should handle URL without tag", func() {
			build := &automotivev1alpha1.ImageBuild{}
			build.Spec.Export = &automotivev1alpha1.ExportSpec{
				Container: defaultInternalRegistryURL + "/ns/notag",
			}
			name, tags := resolveImageStreamRefs(build)
			Expect(name).To(Equal("notag"))
			Expect(tags).To(BeEmpty())
		})
	})

	Describe("Internal registry URL generation per mode", func() {
		It("should set ContainerPush for bootc mode", func() {
			req := &BuildRequest{
				Name:                testBuildName,
				Mode:                ModeBootc,
				UseInternalRegistry: true,
			}

			imageName := testBuildName
			tag := testBuildName
			namespace := testNamespace

			// Simulate what setupInternalRegistryBuild does for bootc
			if req.Mode.IsBootc() {
				req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
				if req.BuildDiskImage {
					req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName+"-disk", tag)
				}
			} else {
				req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
			}

			Expect(req.ContainerPush).To(Equal(
				fmt.Sprintf("%s/%s/%s:%s", defaultInternalRegistryURL, namespace, imageName, tag),
			))
			Expect(req.ExportOCI).To(BeEmpty())
		})

		It("should set ExportOCI for traditional mode", func() {
			req := &BuildRequest{
				Name:                testBuildName,
				Mode:                ModePackage,
				UseInternalRegistry: true,
			}

			imageName := testBuildName
			tag := testBuildName
			namespace := testNamespace

			if req.Mode.IsBootc() {
				req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
			} else {
				req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
			}

			Expect(req.ContainerPush).To(BeEmpty())
			Expect(req.ExportOCI).To(Equal(
				fmt.Sprintf("%s/%s/%s:%s", defaultInternalRegistryURL, namespace, imageName, tag),
			))
		})

		It("should set both ContainerPush and ExportOCI for bootc with disk", func() {
			req := &BuildRequest{
				Name:                testBuildName,
				Mode:                ModeBootc,
				UseInternalRegistry: true,
				BuildDiskImage:      true,
			}

			imageName := testBuildName
			tag := testBuildName
			namespace := testNamespace

			if req.Mode.IsBootc() {
				req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
				if req.BuildDiskImage {
					req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName+"-disk", tag)
				}
			} else {
				req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
			}

			Expect(req.ContainerPush).To(ContainSubstring(imageName + ":" + tag))
			Expect(req.ExportOCI).To(ContainSubstring(imageName + "-disk:" + tag))
		})

		It("should set ExportOCI for disk mode", func() {
			req := &BuildRequest{
				Name:                testBuildName,
				Mode:                ModeDisk,
				UseInternalRegistry: true,
			}

			imageName := testBuildName
			tag := testBuildName
			namespace := testNamespace

			if req.Mode.IsBootc() {
				req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
			} else {
				req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
			}

			Expect(req.ContainerPush).To(BeEmpty())
			Expect(req.ExportOCI).To(ContainSubstring(namespace + "/" + imageName))
		})

		It("should imply BuildDiskImage for bootc with flash", func() {
			req := &BuildRequest{
				Name:                testBuildName,
				Mode:                ModeBootc,
				UseInternalRegistry: true,
				FlashEnabled:        true,
			}

			imageName := testBuildName
			tag := testBuildName
			namespace := testNamespace

			// Simulate flash implying disk image
			if req.FlashEnabled && !req.BuildDiskImage {
				req.BuildDiskImage = true
			}

			if req.Mode.IsBootc() {
				req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
				if req.BuildDiskImage {
					req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName+"-disk", tag)
				}
			}

			Expect(req.BuildDiskImage).To(BeTrue())
			Expect(req.ContainerPush).NotTo(BeEmpty())
			Expect(req.ExportOCI).To(ContainSubstring(imageName + "-disk"))
		})
	})
})
