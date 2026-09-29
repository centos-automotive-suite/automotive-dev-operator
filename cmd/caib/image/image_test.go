package image

import (
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	"github.com/spf13/cobra"
)

func TestImageCommandOutputDefaults(t *testing.T) {
	output := &commandopts.Output{}
	cmd := NewImageCmd(Options{
		Connection: &commandopts.Connection{}, Output: output, Callback: &commandopts.Callback{},
		Registry: &commandopts.Registry{}, S3: &commandopts.S3{}, Flash: &commandopts.Flash{},
		Sealed: &commandopts.Sealed{}, Build: &commandopts.Build{},
		GetDefaultArch: func() string { return "amd64" },
	})
	find := func(name string) *cobra.Command {
		t.Helper()
		for _, child := range cmd.Commands() {
			if child.Name() == name {
				return child
			}
		}
		t.Fatalf("missing command %q", name)
		return nil
	}
	for _, tc := range []struct {
		name    string
		timeout int
		wait    bool
		follow  bool
	}{
		{name: "build", timeout: 60, wait: true},
		{name: "resolve", timeout: 30},
		{name: "disk", timeout: 60},
		{name: "build-dev", timeout: 60},
		{name: "flash", timeout: -1, wait: true},
		{name: "prepare-reseal", timeout: 120, follow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output.Timeout = -1
			output.Wait = !tc.wait
			output.FollowLogs = !tc.follow
			if err := cmd.PersistentPreRunE(find(tc.name), nil); err != nil {
				t.Fatal(err)
			}
			if output.Timeout != tc.timeout {
				t.Fatalf("timeout = %d, want %d", output.Timeout, tc.timeout)
			}
			if child := find(tc.name); child.Flags().Lookup("wait") != nil && output.Wait != tc.wait {
				t.Fatalf("wait = %t, want %t", output.Wait, tc.wait)
			}
			if child := find(tc.name); child.Flags().Lookup("follow") != nil && output.FollowLogs != tc.follow {
				t.Fatalf("follow = %t, want %t", output.FollowLogs, tc.follow)
			}
		})
	}
	build := find("build")
	for name, value := range map[string]string{"timeout": "7", "wait": "false", "follow": "true"} {
		if err := build.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.PersistentPreRunE(build, nil); err != nil {
		t.Fatal(err)
	}
	if output.Timeout != 7 || output.Wait || !output.FollowLogs {
		t.Fatalf("explicit output flags were overwritten: %+v", output)
	}
}

func TestShowCommandRejectsMissingBuildName(t *testing.T) {
	called := false
	cmd := newShowCmd(Options{
		RunShow: func(_ *cobra.Command, _ []string) {
			called = true
		},
	})

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected an error when build name argument is missing")
	}
	if called {
		t.Fatalf("expected RunShow not to be called when args are invalid")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg(s), received 0") {
		t.Fatalf("unexpected error for missing build name: %v", err)
	}
}

func TestShowCommandInvokesHandlerWithBuildName(t *testing.T) {
	var gotArgs []string
	cmd := newShowCmd(Options{
		RunShow: func(_ *cobra.Command, args []string) {
			gotArgs = append([]string{}, args...)
		},
	})

	cmd.SetArgs([]string{"my-build"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully: %v", err)
	}
	if len(gotArgs) != 1 || gotArgs[0] != "my-build" {
		t.Fatalf("expected RunShow to receive [my-build], got %v", gotArgs)
	}
}
