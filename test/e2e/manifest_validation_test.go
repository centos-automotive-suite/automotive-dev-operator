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

package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

const (
	invalidManifest   = "test/config/invalid-manifest.aib.yml"
	validationTimeout = 2 * time.Minute
)

var _ = Describe("Manifest Validation", Label("manifest-validation"), Ordered, func() {

	BeforeAll(func() {
		ensureOperatorDeployed()
		ensureBuildAPIAccess()
		ensureCaibCredentials()
	})

	It("should reject a manifest with unknown fields", func() {
		ctx, cancel := context.WithTimeout(context.Background(), validationTimeout)
		defer cancel()

		cmd := utils.NewCaibCommand(ctx, caibEnv,
			"image", "build",
			invalidManifest,
			"--name", "e2e-invalid-manifest",
			"--arch", arch,
			"--push", "localhost:5000/test/invalid:latest")
		output, err := utils.RunSafe(cmd)

		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- caib manifest validation ---\n%s\n", string(output))

		Expect(err).To(HaveOccurred(), "expected caib to fail on invalid manifest")
		Expect(string(output)).To(ContainSubstring("manifest validation error"),
			"expected manifest validation error in output")
	})
})
