package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
)

// getDefaultArch returns the current system architecture in caib format.
func getDefaultArch() string {
	switch runtime.GOARCH {
	case archAMD64:
		return archAMD64
	case archARM64:
		return archARM64
	default:
		fmt.Fprintf(os.Stderr, "Warning: unrecognized host architecture %q, using raw GOARCH value\n", runtime.GOARCH)
		return runtime.GOARCH
	}
}

// envBool parses a boolean from environment variable.
func envBool(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

func handleError(err error) {
	fmt.Fprintln(os.Stderr, caibcommon.FormatError(err))
	os.Exit(1)
}
