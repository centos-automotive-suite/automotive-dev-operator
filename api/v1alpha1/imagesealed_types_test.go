/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

func TestImageSealedTypes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ImageSealed Types Suite")
}

var _ = Describe("ImageSealedSpec", func() {

	Describe("GetAIBImage", func() {
		It("should return the configured AIB image when set", func() {
			spec := &ImageSealedSpec{AIBImage: "custom/aib:v1"}
			Expect(spec.GetAIBImage()).To(Equal("custom/aib:v1"))
		})

		It("should return default AIB image when not set", func() {
			spec := &ImageSealedSpec{}
			Expect(spec.GetAIBImage()).To(Equal("quay.io/centos-sig-automotive/automotive-image-builder:latest"))
		})

		It("should return default AIB image when empty string", func() {
			spec := &ImageSealedSpec{AIBImage: ""}
			Expect(spec.GetAIBImage()).To(Equal("quay.io/centos-sig-automotive/automotive-image-builder:latest"))
		})
	})

	Describe("GetStages", func() {
		It("should return Stages when set", func() {
			spec := &ImageSealedSpec{
				Operation: "reseal",
				Stages:    []string{"prepare-reseal", "reseal"},
			}
			Expect(spec.GetStages()).To(Equal([]string{"prepare-reseal", "reseal"}))
		})

		It("should return single-element slice from Operation when Stages is empty", func() {
			spec := &ImageSealedSpec{Operation: "prepare-reseal"}
			Expect(spec.GetStages()).To(Equal([]string{"prepare-reseal"}))
		})

		It("should return nil when neither Operation nor Stages is set", func() {
			spec := &ImageSealedSpec{}
			Expect(spec.GetStages()).To(BeNil())
		})

		It("should prefer Stages over Operation", func() {
			spec := &ImageSealedSpec{
				Operation: "reseal",
				Stages:    []string{"extract-for-signing", "inject-signed"},
			}
			stages := spec.GetStages()
			Expect(stages).To(HaveLen(2))
			Expect(stages[0]).To(Equal("extract-for-signing"))
			Expect(stages[1]).To(Equal("inject-signed"))
		})
	})

	Describe("Spec fields", func() {
		It("should store all sealed spec fields", func() {
			spec := ImageSealedSpec{
				Operation:            "inject-signed",
				Stages:               []string{"prepare-reseal", "inject-signed"},
				InputRef:             "quay.io/test/image:seal",
				OutputRef:            "quay.io/test/image:signed",
				SignedRef:            "quay.io/test/artifacts:latest",
				AIBImage:             "custom/aib:v2",
				BuilderImage:         "quay.io/test/builder:latest",
				Architecture:         "arm64",
				StorageClass:         "gp3",
				SecretRef:            "my-registry-auth",
				KeySecretRef:         "my-seal-key",
				KeyPasswordSecretRef: "my-key-password",
				AIBExtraArgs:         []string{"--verbose", "--dry-run"},
			}
			Expect(spec.Operation).To(Equal("inject-signed"))
			Expect(spec.Stages).To(HaveLen(2))
			Expect(spec.InputRef).To(Equal("quay.io/test/image:seal"))
			Expect(spec.OutputRef).To(Equal("quay.io/test/image:signed"))
			Expect(spec.SignedRef).To(Equal("quay.io/test/artifacts:latest"))
			Expect(spec.AIBImage).To(Equal("custom/aib:v2"))
			Expect(spec.BuilderImage).To(Equal("quay.io/test/builder:latest"))
			Expect(spec.Architecture).To(Equal("arm64"))
			Expect(spec.StorageClass).To(Equal("gp3"))
			Expect(spec.SecretRef).To(Equal("my-registry-auth"))
			Expect(spec.KeySecretRef).To(Equal("my-seal-key"))
			Expect(spec.KeyPasswordSecretRef).To(Equal("my-key-password"))
			Expect(spec.AIBExtraArgs).To(Equal([]string{"--verbose", "--dry-run"}))
		})
	})
})
