package tasks

import (
	_ "embed"
)

//go:embed scripts/find_manifest.sh
var FindManifestScript string

//go:embed scripts/build_image.sh
var BuildImageScript string

//go:embed scripts/push_artifact.sh
var PushArtifactScript string

//go:embed scripts/build_builder.sh
var BuildBuilderScript string

//go:embed scripts/reseal_image.sh
var ResealImageScript string
