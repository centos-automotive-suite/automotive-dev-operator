// Package main provides the caib CLI tool for interacting with the automotive image build system.
package main

import (
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
		os.Exit(1)
	}
}
