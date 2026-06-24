package caibcommon

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	multiHyphenRe       = regexp.MustCompile(`-{2,}`)
	validManifestSuffix = []string{".aib.yml", ".mpp.yml"}
)

const maxBuildNameLen = 63

// SanitizeBuildName converts a string into a valid RFC1123-style name.
func SanitizeBuildName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	result := multiHyphenRe.ReplaceAllString(b.String(), "-")
	return strings.Trim(result, "-")
}

// ValidateBuildName checks user-provided build name validity.
func ValidateBuildName(name string) error {
	sanitized := SanitizeBuildName(name)
	if sanitized == "" {
		return fmt.Errorf("build name %q contains only invalid characters", name)
	}
	if len(sanitized) > maxBuildNameLen {
		return fmt.Errorf(
			"sanitized build name %q is too long: got %d, max %d",
			sanitized,
			len(sanitized),
			maxBuildNameLen,
		)
	}
	return nil
}

// ValidateReproducibleRequiresSecure returns an error when reproducible builds
// are requested without secure build mode.
func ValidateReproducibleRequiresSecure(reproducible, secureBuild bool) error {
	if reproducible && !secureBuild {
		return fmt.Errorf("--reproducible requires --secure for task bundle pinning")
	}
	return nil
}

// ValidateLeaseTags checks that each tag is in key=value format with no commas.
func ValidateLeaseTags(tags []string) error {
	for _, tag := range tags {
		if strings.Contains(tag, ",") {
			return fmt.Errorf("lease tag %q must not contain commas", tag)
		}
		if !strings.Contains(tag, "=") {
			return fmt.Errorf("lease tag %q must be in key=value format", tag)
		}
		key := tag[:strings.Index(tag, "=")]
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("lease tag %q has empty key", tag)
		}
	}
	return nil
}

// ValidateAndJoinLeaseTags validates tags and returns a comma-separated string.
func ValidateAndJoinLeaseTags(tags *[]string) (string, error) {
	if tags == nil || len(*tags) == 0 {
		return "", nil
	}
	if err := ValidateLeaseTags(*tags); err != nil {
		return "", err
	}
	return strings.Join(*tags, ","), nil
}

// ValidateManifestSuffix validates the manifest file extension.
func ValidateManifestSuffix(filename string) error {
	for _, suffix := range validManifestSuffix {
		if strings.HasSuffix(filename, suffix) {
			return nil
		}
	}
	return fmt.Errorf("manifest file %q must have one of the following extensions: %s",
		filepath.Base(filename), strings.Join(validManifestSuffix, ", "))
}
