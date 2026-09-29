package buildcontract

// BuildProgress is the response for GET /v1/builds/{name}/progress
type BuildProgress struct {
	Phase string     `json:"phase"`
	Step  *BuildStep `json:"step,omitempty"`
}

// BuildStep represents a progress checkpoint emitted by the build script.
type BuildStep struct {
	Stage string `json:"stage"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}
