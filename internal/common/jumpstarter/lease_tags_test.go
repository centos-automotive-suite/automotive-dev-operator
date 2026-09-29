package jumpstarter

import "testing"

func TestBuildLeaseTags(t *testing.T) {
	cases := []struct{ name, defaults, build, user, want string }{
		{"all parts", "platform=caib", "my-build", "env=staging,team=platform", "platform=caib,build-name=my-build,env=staging,team=platform"},
		{"no user tags", "platform=caib", "my-build", "", "platform=caib,build-name=my-build"},
		{"no defaults", "", "my-build", "env=staging", "build-name=my-build,env=staging"},
		{"only build name", "", "my-build", "", "build-name=my-build"},
		{"multiple defaults", "platform=caib,cluster=prod", "test-build", "team=eng", "platform=caib,cluster=prod,build-name=test-build,team=eng"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildLeaseTags(tc.defaults, tc.build, tc.user); got != tc.want {
				t.Fatalf("BuildLeaseTags() = %q, want %q", got, tc.want)
			}
		})
	}
}
