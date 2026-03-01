package container

import "testing"

func TestSanitizeBuildName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "simple lowercase", input: "my-build", want: "my-build"},
		{name: "uppercase converted", input: "MyBuild", want: "mybuild"},
		{name: "special chars replaced", input: "my_build@v1", want: "my-build-v1"},
		{name: "leading/trailing dashes trimmed", input: "---build---", want: "build"},
		{name: "dots replaced", input: "my.build.name", want: "my-build-name"},
		{name: "long name truncated", input: "this-is-a-very-long-build-name-that-should-be-truncated-because-it-exceeds-the-limit", want: "this-is-a-very-long-build-name-that-should-be-trun"},
		{name: "empty string fallback", input: "", want: "build"},
		{name: "all special chars fallback", input: "!!!@@@###", want: "build"},
		{name: "spaces replaced", input: "my build name", want: "my-build-name"},
		{name: "mixed case and special", input: "My_App.V2", want: "my-app-v2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeBuildName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeBuildName(%q) = %q, want %q", tt.input, got, tt.want)
			}
			// Result must be a valid K8s name
			if got != "build" && !isValidKubernetesName(got) {
				t.Errorf("sanitizeBuildName(%q) = %q is not a valid Kubernetes name", tt.input, got)
			}
		})
	}
}

func TestIsValidKubernetesName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "valid simple", input: "my-build", want: true},
		{name: "valid single char", input: "a", want: true},
		{name: "valid numeric", input: "123", want: true},
		{name: "valid alphanumeric", input: "build-123-abc", want: true},
		{name: "invalid empty", input: "", want: false},
		{name: "invalid uppercase", input: "MyBuild", want: false},
		{name: "invalid leading dash", input: "-build", want: false},
		{name: "invalid trailing dash", input: "build-", want: false},
		{name: "invalid underscore", input: "my_build", want: false},
		{name: "invalid dot", input: "my.build", want: false},
		{name: "invalid spaces", input: "my build", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidKubernetesName(tt.input)
			if got != tt.want {
				t.Errorf("isValidKubernetesName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
