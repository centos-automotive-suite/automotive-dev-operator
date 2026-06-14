package buildapi

import (
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("validateBuildRequest", func() {
	It("accepts a valid bootc build request", func() {
		req := &BuildRequest{
			Name:     "my-build",
			Manifest: "name: test\n",
			Mode:     ModeBootc,
		}
		Expect(validateBuildRequest(req)).To(Succeed())
	})

	It("rejects empty manifest for non-disk mode", func() {
		req := &BuildRequest{
			Name:     "my-build",
			Manifest: "",
			Mode:     ModeBootc,
		}
		err := validateBuildRequest(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("manifest is required"))
	})

	It("rejects disk mode without container ref", func() {
		req := &BuildRequest{
			Name:     "my-build",
			Manifest: "name: test\n",
			Mode:     ModeDisk,
		}
		err := validateBuildRequest(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("container-ref is required"))
	})

	It("accepts disk mode with valid container ref", func() {
		req := &BuildRequest{
			Name:         "my-build",
			Manifest:     "name: test\n",
			Mode:         ModeDisk,
			ContainerRef: "quay.io/org/image:latest",
		}
		Expect(validateBuildRequest(req)).To(Succeed())
	})

	It("rejects manifest exceeding size limit", func() {
		req := &BuildRequest{
			Name:     "my-build",
			Manifest: strings.Repeat("x", maxManifestSize+1),
			Mode:     ModeBootc,
		}
		err := validateBuildRequest(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("manifest too large"))
	})

	It("rejects reproducible without secureBuild", func() {
		req := &BuildRequest{
			Name:         "my-build",
			Manifest:     "name: test\n",
			Mode:         ModeBootc,
			Reproducible: true,
			SecureBuild:  false,
		}
		err := validateBuildRequest(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reproducible builds require secureBuild"))
	})

	It("accepts reproducible with secureBuild", func() {
		req := &BuildRequest{
			Name:         "my-build",
			Manifest:     "name: test\n",
			Mode:         ModeBootc,
			Reproducible: true,
			SecureBuild:  true,
		}
		Expect(validateBuildRequest(req)).To(Succeed())
	})

	It("rejects container-push ref with shell metacharacters", func() {
		req := &BuildRequest{
			Name:          "my-build",
			Manifest:      "name: test\n",
			Mode:          ModeBootc,
			ContainerPush: "quay.io/org/image;rm -rf /",
		}
		err := validateBuildRequest(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid container-push"))
	})

	It("rejects export-oci ref with shell metacharacters", func() {
		req := &BuildRequest{
			Name:      "my-build",
			Manifest:  "name: test\n",
			Mode:      ModeBootc,
			ExportOCI: "quay.io/org/image$(whoami)",
		}
		err := validateBuildRequest(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid export-oci"))
	})
})

var _ = Describe("applyBuildDefaults", func() {
	It("applies all defaults to empty request", func() {
		req := &BuildRequest{}
		Expect(applyBuildDefaults(req)).To(Succeed())
		Expect(string(req.Distro)).To(Equal("autosd"))
		Expect(string(req.Target)).To(Equal("qemu"))
		Expect(string(req.Architecture)).To(Equal("arm64"))
		Expect(string(req.ExportFormat)).To(Equal(formatImage))
		Expect(string(req.Mode)).To(Equal("bootc"))
		Expect(string(req.Compression)).To(Equal("gzip"))
		Expect(req.ManifestFileName).To(Equal("manifest.aib.yml"))
	})

	It("preserves explicitly set values", func() {
		req := &BuildRequest{
			Distro:       "cs9",
			Target:       "aws",
			Architecture: "amd64",
			Mode:         ModeDisk,
			Compression:  CompressionLZ4,
		}
		Expect(applyBuildDefaults(req)).To(Succeed())
		Expect(string(req.Distro)).To(Equal("cs9"))
		Expect(string(req.Target)).To(Equal("aws"))
		Expect(string(req.Architecture)).To(Equal("amd64"))
		Expect(string(req.Mode)).To(Equal("disk"))
		Expect(string(req.Compression)).To(Equal("lz4"))
	})

	It("normalizes x86_64 to amd64", func() {
		req := &BuildRequest{Architecture: "x86_64"}
		Expect(applyBuildDefaults(req)).To(Succeed())
		Expect(string(req.Architecture)).To(Equal("amd64"))
	})

	It("normalizes aarch64 to arm64", func() {
		req := &BuildRequest{Architecture: "aarch64"}
		Expect(applyBuildDefaults(req)).To(Succeed())
		Expect(string(req.Architecture)).To(Equal("arm64"))
	})

	It("rejects invalid compression", func() {
		req := &BuildRequest{Compression: "brotli"}
		err := applyBuildDefaults(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid compression"))
	})

	It("rejects invalid architecture", func() {
		req := &BuildRequest{Architecture: "mips"}
		err := applyBuildDefaults(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid architecture"))
	})
})

var _ = Describe("validateRestoreSourcesRef", func() {
	It("accepts empty ref", func() {
		req := &BuildRequest{}
		Expect(validateRestoreSourcesRef(req)).To(Succeed())
	})

	It("accepts valid digest-pinned ref", func() {
		req := &BuildRequest{
			RestoreSourcesRef: "quay.io/org/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		Expect(validateRestoreSourcesRef(req)).To(Succeed())
	})

	It("rejects tag-based ref", func() {
		req := &BuildRequest{
			RestoreSourcesRef: "quay.io/org/image:latest",
		}
		err := validateRestoreSourcesRef(req)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must be digest-pinned"))
	})

	It("trims whitespace from ref", func() {
		ref := "  quay.io/org/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  "
		req := &BuildRequest{RestoreSourcesRef: ref}
		Expect(validateRestoreSourcesRef(req)).To(Succeed())
		Expect(req.RestoreSourcesRef).ToNot(HavePrefix(" "))
	})
})

var _ = Describe("validateTargetDefaults", func() {
	It("passes when targets map is nil", func() {
		Expect(validateTargetDefaults(nil)).To(Succeed())
	})

	It("passes when no accepted lists are set", func() {
		targets := map[string]TargetDefaults{
			"qemu": {Architecture: "arm64", DefaultFormat: "raw"},
		}
		Expect(validateTargetDefaults(targets)).To(Succeed())
	})

	It("passes when defaults match accepted values", func() {
		targets := map[string]TargetDefaults{
			"qemu": {
				DefaultFormat:         "raw",
				AcceptedFormats:       []string{"qcow2", "raw"},
				AcceptedArchitectures: []string{"amd64", "arm64"},
			},
			"ebbr": {
				Architecture:          "arm64",
				DefaultFormat:         "simg",
				AcceptedFormats:       []string{"simg"},
				AcceptedArchitectures: []string{"arm64"},
			},
		}
		Expect(validateTargetDefaults(targets)).To(Succeed())
	})

	It("rejects architecture not in target's accepted list", func() {
		targets := map[string]TargetDefaults{
			"bad-board": {
				Architecture:          "mips64",
				AcceptedArchitectures: []string{"amd64", "arm64"},
			},
		}
		err := validateTargetDefaults(targets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("bad-board"))
		Expect(err.Error()).To(ContainSubstring("mips64"))
		Expect(err.Error()).To(ContainSubstring("acceptedArchitectures"))
	})

	It("rejects defaultFormat not in target's accepted list", func() {
		targets := map[string]TargetDefaults{
			"my-target": {
				DefaultFormat:   "vdi",
				AcceptedFormats: []string{"qcow2", "raw", "simg"},
			},
		}
		err := validateTargetDefaults(targets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("my-target"))
		Expect(err.Error()).To(ContainSubstring("vdi"))
	})

	It("skips validation when default field is empty", func() {
		targets := map[string]TargetDefaults{
			"qemu": {
				DefaultFormat:         "raw",
				AcceptedFormats:       []string{"qcow2", "raw"},
				AcceptedArchitectures: []string{"amd64", "arm64"},
			},
		}
		Expect(validateTargetDefaults(targets)).To(Succeed())
	})

	It("skips validation when accepted list is empty", func() {
		targets := map[string]TargetDefaults{
			"qemu": {
				Architecture:          "anything",
				DefaultFormat:         "whatever",
				AcceptedFormats:       []string{},
				AcceptedArchitectures: []string{},
			},
		}
		Expect(validateTargetDefaults(targets)).To(Succeed())
	})

	It("reports errors from multiple targets", func() {
		targets := map[string]TargetDefaults{
			"a": {
				Architecture:          "bad-arch",
				AcceptedArchitectures: []string{"amd64", "arm64"},
			},
			"b": {
				DefaultFormat:   "bad-fmt",
				AcceptedFormats: []string{"qcow2", "raw", "simg"},
			},
		}
		err := validateTargetDefaults(targets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("bad-arch"))
		Expect(err.Error()).To(ContainSubstring("bad-fmt"))
	})
})
