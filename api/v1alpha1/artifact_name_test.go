package v1alpha1

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// The CRD pattern marker must be a literal, so guard it against drifting from
// the constant the Build API validates with.
func TestArtifactNameCRDPatternMatchesConstant(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(getCRDPath(), "automotive.sdv.cloud.redhat.com_imagebuilds.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Properties struct {
									Export struct {
										Properties struct {
											ArtifactName struct {
												Pattern   string `yaml:"pattern"`
												MaxLength int    `yaml:"maxLength"`
											} `yaml:"artifactName"`
										} `yaml:"properties"`
									} `yaml:"export"`
								} `yaml:"properties"`
							} `yaml:"spec"`
						} `yaml:"properties"`
					} `yaml:"openAPIV3Schema"`
				} `yaml:"schema"`
			} `yaml:"versions"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	if len(crd.Spec.Versions) == 0 {
		t.Fatal("CRD has no versions")
	}
	field := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Properties.Export.Properties.ArtifactName
	if field.Pattern != ArtifactNamePattern || field.MaxLength != ArtifactNameMaxLength {
		t.Fatalf("CRD artifactName pattern=%q maxLength=%d, want %q and %d", field.Pattern, field.MaxLength, ArtifactNamePattern, ArtifactNameMaxLength)
	}
}
