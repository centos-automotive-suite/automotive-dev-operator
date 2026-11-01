// Package main provides the caib CLI tool for interacting with the automotive image build system.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/spf13/cobra"
)

const (
	archAMD64 = "amd64"
	archARM64 = "arm64"
)

var version string

func main() {
	if err := execute(newRootCmd()); err != nil {
		fmt.Fprintln(os.Stderr, caibcommon.FormatError(err))
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 && exitErr.ExitCode() < 256 {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

// execute runs the command tree and restores the pointer to --help that
// SilenceErrors suppresses for unknown commands. Cobra builds that error while
// looking up the command, before any Args validator runs, so addArgsHint cannot
// reach it.
func execute(rootCmd *cobra.Command) error {
	cmd, err := rootCmd.ExecuteC()
	if err != nil && strings.HasPrefix(err.Error(), "unknown command ") {
		return fmt.Errorf("%w\nSee '%s --help' for usage", err, cmd.CommandPath())
	}
	return err
}
