package image

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func manifestArgument(example string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("a manifest path is required\nExample: %s\nSee '%s --help' for more options", example, cmd.CommandPath())
		}
		return cobra.ExactArgs(1)(cmd, args)
	}
}

func configureHelp(cmd *cobra.Command) {
	groups := []struct {
		id, title string
		commands  []string
	}{
		{"build", "Build images:", []string{"build", "build-dev", "disk", "resolve"}},
		{"use", "Use build results:", []string{"download", "flash", "token"}},
		{"monitor", "Check builds:", []string{"list", "show", "logs", "inspect"}},
		{"manage", "Manage builds:", []string{"cancel", "delete"}},
		{"sign", "Sign and seal images:", []string{"prepare-reseal", "reseal", "extract-for-signing", "inject-signed"}},
	}
	for _, group := range groups {
		cmd.AddGroup(&cobra.Group{ID: group.id, Title: group.title})
		for _, name := range group.commands {
			for _, child := range cmd.Commands() {
				if child.Name() == name {
					child.GroupID = group.id
				}
			}
		}
	}
	for _, child := range cmd.Commands() {
		switch child.Name() {
		case "build", "build-dev", "disk":
			child.SetUsageFunc(groupedBuildUsage)
		}
	}
}

// Keep pflag's rendering of types, shorthands and defaults; only change the
// order and headings. Unclassified flags remain visible in Other flags.
func groupedBuildUsage(cmd *cobra.Command) error {
	groups := []struct {
		title string
		flags []string
	}{
		{"Build flags", []string{"name", "target", "arch", "distro", "mode", "define", "define-file", "extra-args", "workspace"}},
		{"Output flags", []string{"output", "push", "push-disk", "disk", "format", "compress", "internal-registry", "image-name", "image-tag"}},
		{"Progress flags", []string{"wait", "follow", "timeout"}},
		{"Source and package flags", []string{"git-url", "git-ref", "git-secret", "git-lockfile", "lockfile", "extra-repo", "local-repo", "root-password"}},
		{"Device flags", []string{"flash", "client", "exporter", "lease", "lease-duration", "lease-tag", "flash-cmd"}},
		{"Registry and S3 flags", []string{"registry-auth-file", "s3-bucket", "s3-prefix", "s3-region", "s3-endpoint", "s3-access-key-id", "s3-secret-access-key", "s3-credentials-secret", "s3-insecure"}},
		{"Advanced flags", []string{"aib-image", "builder-image", "builder-cache-policy", "rebuild-builder", "secure", "reproducible", "task-bundle-ref", "restore-sources", "ttl", "external-id", "callback-url", "callback-secret-file"}},
		{"Connection flags", []string{"server", "token"}},
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Usage:\n  %s\n", cmd.UseLine())
	if cmd.HasExample() {
		fmt.Fprintf(&out, "\nExamples:\n%s\n", cmd.Example)
	}
	local := cmd.LocalFlags()
	seen := make(map[string]bool)
	printFlags := func(title string, flags *pflag.FlagSet) {
		if flags.HasAvailableFlags() {
			fmt.Fprintf(&out, "\n%s:\n%s", title, flags.FlagUsages())
		}
	}
	for _, group := range groups {
		flags := pflag.NewFlagSet(group.title, pflag.ContinueOnError)
		for _, name := range group.flags {
			if flag := local.Lookup(name); flag != nil {
				flags.AddFlag(flag)
				seen[name] = true
			}
		}
		printFlags(group.title, flags)
	}
	other := pflag.NewFlagSet("other", pflag.ContinueOnError)
	local.VisitAll(func(flag *pflag.Flag) {
		if !seen[flag.Name] {
			other.AddFlag(flag)
		}
	})
	printFlags("Other flags", other)
	printFlags("Global flags", cmd.InheritedFlags())
	_, err := fmt.Fprint(cmd.OutOrStderr(), out.String())
	return err
}
