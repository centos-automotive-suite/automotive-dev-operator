// Package tasks provides embedded shell scripts for Tekton pipeline tasks.
package tasks

import (
	_ "embed"
)

//go:embed scripts/common.sh
var commonScript string

//go:embed scripts/find_manifest.sh

// FindManifestScript contains the embedded shell script for finding build manifests.
var FindManifestScript string

//go:embed scripts/build_image.sh
var buildImageScript string

// BuildImageScript contains the embedded shell script for building images.
// It is the concatenation of common.sh and build_image.sh.
var BuildImageScript = ""

//go:embed scripts/push_artifact.sh
var pushArtifactScript string

// PushArtifactScript contains the embedded shell script for pushing artifacts.
var PushArtifactScript = ""

//go:embed scripts/build_builder.sh
var buildBuilderScript string

// BuildBuilderScript contains the embedded shell script for building the builder image.
var BuildBuilderScript = ""

//go:embed scripts/flash_image.sh
var flashImageScript string

// FlashImageScript contains the embedded shell script for flashing images via Jumpstarter.
var FlashImageScript = ""

func init() {
	BuildImageScript = commonScript + "\n" + buildImageScript
	BuildBuilderScript = commonScript + "\n" + buildBuilderScript
	PushArtifactScript = commonScript + "\n" + pushArtifactScript
	FlashImageScript = commonScript + "\n" + flashImageScript
	SealedOperationScript = commonScript + "\n" + sealedOperationScript
}

//go:embed scripts/sealed_operation.sh
var sealedOperationScript string

// SealedOperationScript contains the embedded script for AIB sealed operations.
// It is the concatenation of common.sh and sealed_operation.sh.
var SealedOperationScript string
