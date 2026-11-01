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
			for _, heading := range []string{"Build Flags:", "Output Flags:", "Progress Flags:", "Device Flags:", "Registry and S3 Flags:", "Advanced Flags:", "Connection Flags:", "Global Flags:"} {
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
				for _, text := range []string{"# Download a disk image", "# Publish a bootc image", "# Build and flash a board", "Build Flags:"} {
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

func TestExtraManifestArgumentsGiveConciseExample(t *testing.T) {
	for _, name := range []string{"build", "build-dev", "resolve"} {
		t.Run(name, func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"image", name, "manifest.aib.yml", "second.aib.yml", "third.aib.yml"})
			err := root.Execute()
			if err == nil {
				t.Fatal("extra manifest arguments were accepted")
			}
			for _, want := range []string{"one manifest path is expected, got 3", "Example: caib image " + name, "caib image " + name + " --help"} {
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

func runHelp(t *testing.T, args ...string) string {
	t.Helper()
	t.Setenv("CAIB_SERVER", "https://api.example")
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append(append([]string{}, args...), "--help"))
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A subcommand left out of configureHelp's groups falls under "Additional
// Commands", so the task groups only stay complete if every command is listed.
func TestImageHelpGroupsEveryCommand(t *testing.T) {
	help := runHelp(t, "image")
	if strings.Contains(help, "Additional Commands:") {
		t.Errorf("ungrouped commands in caib image help:\n%s", help)
	}
	root := newRootCmd()
	imageCmd, _, err := root.Find([]string{"image"})
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range imageCmd.Commands() {
		if !child.IsAvailableCommand() || child.Name() == "help" {
			continue
		}
		listed, err := regexp.MatchString(`(?m)^  `+regexp.QuoteMeta(child.Name())+`\s`, help)
		if err != nil {
			t.Fatal(err)
		}
		if !listed {
			t.Errorf("%s is not listed in any task group; add it to configureHelp", child.Name())
		}
	}
}

// Flags missing from groupedBuildUsage still render, but under "Other Flags".
// Keeping that section free of real flags means a new flag cannot land in the
// catch-all unnoticed.
func TestBuildHelpClassifiesEveryFlag(t *testing.T) {
	for _, name := range []string{"build", "build-dev", "disk"} {
		t.Run(name, func(t *testing.T) {
			help := runHelp(t, "image", name)
			start := strings.Index(help, "Other Flags:")
			end := strings.Index(help, "Global Flags:")
			if start < 0 || end < start {
				t.Fatalf("missing Other Flags or Global Flags section in help:\n%s", help)
			}
			other := help[start:end]
			if !strings.Contains(other, "--help") {
				t.Fatalf("expected --help in the Other Flags section:\n%s", other)
			}
			for _, match := range regexp.MustCompile(`--([\w-]+)`).FindAllStringSubmatch(other, -1) {
				if match[1] != "help" {
					t.Errorf("--%s is not in a flag group; add it to groupedBuildUsage", match[1])
				}
			}
		})
	}
}

// Every argument validator gets the --help pointer, not just the manifest
// commands, and it must appear once so the hint is not duplicated.
func TestArgumentErrorsPointToHelp(t *testing.T) {
	for _, args := range [][]string{
		{"image", "show"},
		{"workspace", "shell"},
		{"image", "build", "manifest.aib.yml", "second.aib.yml"},
		{"image", "build"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(args)
			err := root.Execute()
			if err == nil {
				t.Fatal("expected an argument error")
			}
			if want := "See 'caib " + strings.Join(args[:2], " ") + " --help' for usage"; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not include %q", err, want)
			}
			if got := strings.Count(err.Error(), "--help"); got != 1 {
				t.Errorf("error %q mentions --help %d times, want once", err, got)
			}
			if strings.Contains(err.Error(), "Usage:") || out.Len() != 0 {
				t.Fatalf("expected no usage dump; output=%q error=%v", out.String(), err)
			}
		})
	}
}

// SilenceErrors drops the "Run 'caib --help' for usage." line Cobra prints after
// an unknown command, so execute puts the pointer back.
func TestUnknownCommandPointsToHelp(t *testing.T) {
	for _, args := range [][]string{{"bogus"}, {"imag"}} {
		t.Run(args[0], func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(args)
			err := execute(root)
			if err == nil {
				t.Fatal("expected an unknown command error")
			}
			for _, want := range []string{`unknown command "` + args[0] + `" for "caib"`, "See 'caib --help' for usage"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not include %q", err, want)
				}
			}
			if args[0] == "imag" && !strings.Contains(err.Error(), "Did you mean this?") {
				t.Errorf("error %q lost its suggestion", err)
			}
			if out.Len() != 0 {
				t.Fatalf("expected no output; got %q", out.String())
			}
		})
	}
}
