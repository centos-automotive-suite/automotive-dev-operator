// Package main provides the caib CLI tool for interacting with the automotive image build system.
package main

import (
	"errors"
	"fmt"
	"os"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
)

const (
	archAMD64 = "amd64"
	archARM64 = "arm64"
)

var version string

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, caibcommon.FormatError(err))
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 && exitErr.ExitCode() < 256 {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
