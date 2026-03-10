// Package main provides the caib CLI tool for interacting with the automotive image build system.
package main

import (
	"fmt"
	"os"
)

const (
	archAMD64 = "amd64"
	archARM64 = "arm64"
)

var (
	serverURL              string
	manifest               string
	buildName              string
	showOutputFormat       string
	distro                 string
	target                 string
	architecture           string
	exportFormat           string
	mode                   string
	automotiveImageBuilder string
	storageClass           string
	outputDir              string
	timeout                int
	waitForBuild           bool
	customDefs             []string
	aibExtraArgs           []string
	followLogs             bool
	version                string
	compressionAlgo        string
	authToken              string

	containerPush    string
	buildDiskImage   bool
	diskFormat       string
	exportOCI        string
	builderImage     string
	registryAuthFile string

	containerRef   string
	rebuildBuilder bool

	// Flash options
	flashAfterBuild   bool
	jumpstarterClient string
	flashName         string
	exporterSelector  string
	leaseDuration     string
	flashCmdOverride  string

	// Internal registry options
	useInternalRegistry       bool
	internalRegistryImageName string
	internalRegistryTag       string

	// TLS options
	insecureSkipTLS bool

	// Sealed operation options
	sealedBuilderImage      string
	sealedArchitecture      string
	sealedKeySecret         string
	sealedKeyPasswordSecret string
	sealedKeyFile           string
	sealedKeyPassword       string
	sealedInputRef          string
	sealedOutputRef         string
	sealedSignedRef         string
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
