// Package tasks provides embedded shell scripts for Tekton pipeline tasks.
package tasks

import (
	_ "embed"
)

//go:embed scripts/find_manifest.sh

// FindManifestScript contains the embedded shell script for finding build manifests.
var FindManifestScript string

//go:embed scripts/build_image.sh

// BuildImageScript contains the embedded shell script for building images.
var BuildImageScript string

//go:embed scripts/push_artifact.sh

// PushArtifactScript contains the embedded shell script for pushing artifacts.
var PushArtifactScript string

//go:embed scripts/build_builder.sh

// BuildBuilderScript contains the embedded shell script for building the builder image.
var BuildBuilderScript string

//go:embed scripts/flash_image.sh

// FlashImageScript contains the embedded shell script for flashing images via Jumpstarter.
var FlashImageScript string

//go:embed scripts/reseal_image.sh

// ResealImageScript contains the embedded shell script for resealing bootc container images.
var ResealImageScript string
