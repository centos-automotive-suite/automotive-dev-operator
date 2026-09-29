package buildapi

import "errors"

const workspaceFSRoot = "/workspace"
const maxWorkspaceHydrateBytes = 220 * 1024

var ErrWorkspaceHydratePlanTooLarge = errors.New("workspace hydrate plan exceeds annotation size limit")

const (
	hydrateKindPath = "path"
	hydrateKindGlob = "glob"
)
