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
	"fmt"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	"github.com/onsi/gomega/format"

	utils "github.com/centos-automotive-suite/automotive-dev-operator/test/utils"
)

// Run e2e tests using the Ginkgo runner.
func TestE2E(t *testing.T) {
	format.MaxLength = 0
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting automotive-dev-operator suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	testNamespace = resolveNamespace()
	registryHost = os.Getenv("REGISTRY_HOST")
	arch = detectArch()
	openShiftCluster = utils.IsOpenShiftCluster()

	_, _ = fmt.Fprintf(GinkgoWriter, "Test namespace: %s\n", testNamespace)
	_, _ = fmt.Fprintf(GinkgoWriter, "Registry host:  %s\n", registryHost)
	_, _ = fmt.Fprintf(GinkgoWriter, "Architecture:   %s\n", arch)
})

var _ = AfterSuite(func() {
	teardownOperator()
})
