package jumpstarter

import "strings"

// BuildLeaseTags merges defaults, the build name, and user tags in that order.
func BuildLeaseTags(operatorConfigDefaults, buildName, userTags string) string {
	parts := make([]string, 0, 3)
	if operatorConfigDefaults != "" {
		parts = append(parts, operatorConfigDefaults)
	}
	parts = append(parts, "build-name="+buildName)
	if userTags != "" {
		parts = append(parts, userTags)
	}
	return strings.Join(parts, ",")
}
