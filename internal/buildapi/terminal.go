package buildapi

import api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"

func storedArtifacts(build *api.ImageBuild) []ArtifactStatus {
	if build.Status.TerminalResult != nil {
		return build.Status.TerminalResult.Artifacts
	}
	return build.Status.Artifacts
}

func storedFlash(build *api.ImageBuild) *FlashOutcomeStatus {
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
		case string(ModeDisk):
			disk = artifact.URL
		}
	}
	return
}
