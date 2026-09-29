package buildapi

import "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"

import api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"

func storedArtifacts(build *api.ImageBuild) []buildcontract.ArtifactStatus {
	var artifacts []buildcontract.ArtifactStatus
	if build.Status.TerminalResult != nil {
		artifacts = build.Status.TerminalResult.Artifacts
	} else {
		artifacts = build.Status.Artifacts
	}
	if !build.Spec.GetResolveOnly() {
		return artifacts
	}
	projected := append([]buildcontract.ArtifactStatus(nil), artifacts...)
	for i := range projected {
		if projected[i].Kind == string(buildcontract.ModeDisk) {
			projected[i].Kind = "lockfile"
		}
	}
	return projected
}

func storedFlash(build *api.ImageBuild) *buildcontract.FlashOutcomeStatus {
	if build.Status.TerminalResult != nil {
		return build.Status.TerminalResult.Flash
	}
	return build.Status.Flash
}

func storedArtifactURLs(build *api.ImageBuild) (container, disk string) {
	for _, artifact := range storedArtifacts(build) {
		switch artifact.Kind {
		case "container":
			container = artifact.URL
		case string(buildcontract.ModeDisk), "lockfile":
			disk = artifact.URL
		}
	}
	return
}

func classifyBuildArtifactURLs(build *api.ImageBuild, container, disk string) (string, string, string) {
	if build.Spec.GetResolveOnly() {
		return container, "", disk
	}
	return container, disk, ""
}
