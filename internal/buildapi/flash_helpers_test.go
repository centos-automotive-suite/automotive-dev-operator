package buildapi

import (
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
