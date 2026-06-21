/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package container

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
)

// handleError prints an error and exits
func handleError(err error) {
	fmt.Fprintln(os.Stderr, caibcommon.FormatError(err))
	os.Exit(1)
}

// sanitizeBuildName sanitizes a build name
func sanitizeBuildName(name string) string {
	// Replace invalid characters with dashes, lowercase, and truncate
	name = strings.ToLower(name)
	re := regexp.MustCompile(`[^a-z0-9-]`)
	sanitized := re.ReplaceAllString(name, "-")
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}
	sanitized = strings.Trim(sanitized, "-")
	if sanitized == "" {
		sanitized = "build"
	}
	return sanitized
}

// validateBuildName validates a build name
func validateBuildName(name string) {
	if name == "" {
		handleError(fmt.Errorf("build name cannot be empty"))
	}
	if len(name) > 63 {
		handleError(fmt.Errorf("build name cannot be longer than 63 characters"))
	}
	if !isValidKubernetesName(name) {
		handleError(fmt.Errorf("build name must be a valid Kubernetes resource name"))
	}
}

// isValidKubernetesName checks if a string is a valid Kubernetes resource name
func isValidKubernetesName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	re := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	return re.MatchString(name)
}
