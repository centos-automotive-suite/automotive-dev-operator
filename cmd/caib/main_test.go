package main

import (
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/spf13/cobra"
)

func TestOutputFormatFlagRegistered(t *testing.T) {
	rootCmd := newRootCmd()
	flag := rootCmd.PersistentFlags().Lookup("output-format")
	if flag == nil {
		t.Fatal("expected --output-format persistent flag on root command")
	}
	if flag.DefValue != "table" {
		t.Errorf("expected default value 'table', got %q", flag.DefValue)
	}
}

func TestNotificationFlagsRegistered(t *testing.T) {
	rootCmd := newRootCmd()
	for _, path := range [][]string{{"image", "build"}, {"image", "disk"}, {"image", "build-dev"}, {"image", "flash"}} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatalf("find %v: %v", path, err)
		}
		for _, name := range []string{"external-id", "callback-url", "callback-secret-file"} {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("%v missing --%s", path, name)
			}
		}
		callbackURL := cmd.Flags().Lookup("callback-url")
		if callbackURL != nil && !strings.Contains(callbackURL.Usage, "webhookNotifications.allowHTTP") {
			t.Errorf("%v --callback-url help does not describe the HTTP exception: %q", path, callbackURL.Usage)
		}
	}
}

func TestOutputFormatFlagPropagates(t *testing.T) {
	rootCmd := newRootCmd()

	// Simulate: caib image list --output-format json
	// Find the image subcommand, then list under it
	imageCmd, _, err := rootCmd.Find([]string{"image", "list"})
	if err != nil {
		t.Fatalf("could not find image list command: %v", err)
	}

	flag := imageCmd.Root().PersistentFlags().Lookup("output-format")
	if flag == nil {
		t.Fatal("expected --output-format to be visible from image list command")
	}
}

func TestOutputFormatFlagSetFromArgs(t *testing.T) {
	originalFormat := outputFormat
	t.Cleanup(func() { outputFormat = originalFormat })

	rootCmd := newRootCmd()

	// Parse --output-format json at root level
	rootCmd.SetArgs([]string{"--output-format", "json", "--help"})
	_ = rootCmd.Execute()

	if outputFormat != "json" {
		t.Errorf("expected outputFormat to be 'json' after parsing, got %q", outputFormat)
	}
}

func TestValidOutputFormats(t *testing.T) {
	// This tests the validOutputFormats map keys directly.
	// Note: PersistentPreRunE applies strings.ToLower before the lookup,
	// so CLI users can pass e.g. "--output-format TABLE" and it will be
	// accepted as "table". This test only validates the canonical map entries.
	for _, f := range []string{"table", "json", "yaml", "yml"} {
		if !validOutputFormats[f] {
			t.Errorf("expected %q to be a valid output format", f)
		}
	}
	for _, f := range []string{"csv", "xml", "", "TABLE"} {
		if validOutputFormats[f] {
			t.Errorf("expected %q to NOT be a valid output format", f)
		}
	}
}

func TestQuietFlagRegistered(t *testing.T) {
	rootCmd := newRootCmd()
	flag := rootCmd.PersistentFlags().Lookup("quiet")
	if flag == nil {
		t.Fatal("expected --quiet persistent flag on root command")
	}
	if flag.Shorthand != "q" {
		t.Errorf("expected shorthand 'q', got %q", flag.Shorthand)
	}
	if flag.DefValue != "false" {
		t.Errorf("expected default value 'false', got %q", flag.DefValue)
	}
}

func TestQuietFlagActivatesClilog(t *testing.T) {
	clilog.SetQuiet(false)
	t.Cleanup(func() { clilog.SetQuiet(false) })

	rootCmd := newRootCmd()
	noop := &cobra.Command{Use: "noop", RunE: func(_ *cobra.Command, _ []string) error { return nil }}
	rootCmd.AddCommand(noop)
	rootCmd.SetArgs([]string{"-q", "noop"})
	_ = rootCmd.Execute()

	if !clilog.IsQuiet() {
		t.Error("expected clilog.IsQuiet() == true after -q flag parsed")
	}
}

func TestQuietFlagWorksOnImageSubcommand(t *testing.T) {
	clilog.SetQuiet(false)
	t.Cleanup(func() { clilog.SetQuiet(false) })

	rootCmd := newRootCmd()
	// Add a noop under image to test that cobra.OnInitialize fires
	// even when image's PersistentPreRunE overrides root's
	imageCmd, _, _ := rootCmd.Find([]string{"image"})
	noop := &cobra.Command{Use: "noop", RunE: func(_ *cobra.Command, _ []string) error { return nil }}
	imageCmd.AddCommand(noop)
	rootCmd.SetArgs([]string{"image", "noop", "-q"})
	_ = rootCmd.Execute()

	if !clilog.IsQuiet() {
		t.Error("expected clilog.IsQuiet() == true for 'image noop -q' (child PersistentPreRunE must not override quiet)")
	}
}

func TestLockfileFlag(t *testing.T) {
	for _, subcommand := range []string{"build", "build-dev"} {
		t.Run(subcommand, func(t *testing.T) {
			root := newRootCmd()
			cmd, _, err := root.Find([]string{"image", subcommand})
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.ParseFlags([]string{"--lockfile", "path with spaces/input.lock"}); err != nil {
				t.Fatal(err)
			}
			got, err := cmd.Flags().GetString("lockfile")
			if err != nil || got != "path with spaces/input.lock" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}
