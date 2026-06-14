package tasks

import (
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
)

func TestNoHardcodedOCIStringsInScripts(t *testing.T) {
	spec := oci.Get()
	generatedBlock := spec.ShellVars()

	scripts := map[string]string{
		"PushArtifactScript":    PushArtifactScript,
		"BuildImageScript":      BuildImageScript,
		"SealedOperationScript": SealedOperationScript,
	}

	forbiddenMediaTypes := []string{
		"application/vnd.automotive.disk.",
		"application/vnd.automotive.manifest.",
		"application/vnd.automotive.sources.",
		"application/vnd.osbuild.manifest.",
	}

	allKeys := spec.AllManifestAnnotationKeys()
	forbiddenAnnotationKeys := make([]string, 0, len(allKeys)+len(spec.Annotations.Layer.Custom))
	for _, ak := range allKeys {
		forbiddenAnnotationKeys = append(forbiddenAnnotationKeys, `"`+spec.AnnotationKey(ak.Key)+`"`)
	}
	for _, ak := range spec.Annotations.Layer.Custom {
		forbiddenAnnotationKeys = append(forbiddenAnnotationKeys, `"`+spec.AnnotationKey(ak.Key)+`"`)
	}

	for name, script := range scripts {
		stripped := stripGeneratedBlock(script, generatedBlock)

		for _, pattern := range forbiddenMediaTypes {
			if strings.Contains(stripped, pattern) {
				t.Errorf("%s contains hardcoded OCI media type %q — use OCI_* shell variables from spec.json instead",
					name, pattern)
			}
		}

		for _, key := range forbiddenAnnotationKeys {
			if strings.Contains(stripped, key) {
				t.Errorf("%s contains hardcoded annotation key %s — use $OCI_ANN_* shell variables from spec.json instead",
					name, key)
			}
		}
	}
}

func stripGeneratedBlock(script, block string) string {
	idx := strings.Index(script, block)
	if idx < 0 {
		return script
	}
	return script[:idx] + script[idx+len(block):]
}
