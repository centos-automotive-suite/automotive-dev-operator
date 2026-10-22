package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestBuildHelpGroupsKeepEveryFlagVisible(t *testing.T) {
	t.Setenv("CAIB_SERVER", "https://api.example")
	for _, name := range []string{"build", "build-dev", "disk"} {
		t.Run(name, func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"image", name, "--help"})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			help := out.String()
			for _, heading := range []string{"Build flags:", "Output flags:", "Progress flags:", "Device flags:", "Registry and S3 flags:", "Advanced flags:", "Connection flags:", "Global flags:"} {
				if !strings.Contains(help, heading) {
					t.Errorf("missing %q in help", heading)
				}
			}
			counts := map[string]int{}
			for _, match := range regexp.MustCompile(`(?m)^ +(?:-\w, )?--([\w-]+)`).FindAllStringSubmatch(help, -1) {
				counts[match[1]]++
			}
			cmd, _, err := root.Find([]string{"image", name})
			if err != nil {
				t.Fatal(err)
			}
			check := func(flag *pflag.Flag) {
				if !flag.Hidden && flag.Deprecated == "" && counts[flag.Name] != 1 {
					t.Errorf("--%s appears %d times, want once", flag.Name, counts[flag.Name])
				}
			}
			cmd.LocalFlags().VisitAll(check)
			cmd.InheritedFlags().VisitAll(check)
			if name == "build" {
				last := -1
				for _, text := range []string{"# Download a disk image", "# Publish a bootc image", "# Build and flash a board", "Build flags:"} {
					index := strings.Index(help, text)
					if index <= last {
						t.Fatalf("recipe %q is missing or out of order", text)
					}
					last = index
				}
			}
		})
	}
}

func TestMissingManifestGivesConciseExample(t *testing.T) {
	for _, name := range []string{"build", "build-dev", "resolve"} {
		t.Run(name, func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"image", name})
			err := root.Execute()
			if err == nil {
				t.Fatal("missing manifest was accepted")
			}
			for _, want := range []string{"a manifest path is required", "Example: caib image " + name + " manifest.aib.yml", "caib image " + name + " --help"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not include %q", err, want)
				}
			}
			if out.Len() != 0 || strings.Count(err.Error(), "\n") > 3 {
				t.Fatalf("expected one concise error for main to print; output=%q error=%v", out.String(), err)
			}
		})
	}
}

func TestUnknownBuildFlagGivesHelpHint(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetErr(&out)
	root.SetArgs([]string{"image", "build", "--unknown"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "caib image build --help") || out.Len() != 0 {
		t.Fatalf("unexpected flag error: %v, output: %q", err, out.String())
	}
}
