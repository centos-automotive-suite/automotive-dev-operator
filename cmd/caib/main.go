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

var (
	serverURL              string
	manifest               string
	buildName              string
	outputFormat           string
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
	defineFiles            []string
	aibExtraArgs           []string
	extraRepos             []string
	workspaceName          string
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
	leaseName         string
	flashCmdOverride  string

	// Internal registry options
	useInternalRegistry       bool
	internalRegistryImageName string
	internalRegistryTag       string

	// Secure build
	secureBuild bool

	// Reproducible build
	reproducibleBuild bool
	taskBundleRef     string
	restoreSourcesRef string

	// Build TTL
	buildTTL string

	// Output options
	quiet bool

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
		fmt.Fprintln(os.Stderr, caibcommon.FormatError(err))
		os.Exit(1)
	}
}
