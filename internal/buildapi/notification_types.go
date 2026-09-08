package buildapi

import (
	"encoding/json"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

// BuildCallback requests a signed terminal event for a build or flash operation.
type BuildCallback struct {
	URL string `json:"url"`
	// Secret is standard base64 encoding of 32 to 4096 cryptographically random bytes.
	Secret string `json:"secret"`
}

func (BuildCallback) String() string     { return "[redacted callback]" }
func (c BuildCallback) GoString() string { return c.String() }

type ArtifactStatus = automotivev1alpha1.ArtifactStatus
type FlashOutcomeStatus = automotivev1alpha1.FlashOutcomeStatus
type NotificationStatus = automotivev1alpha1.NotificationStatus

// MarshalJSON prevents the write-only callback from leaking through a build template response.
func (r BuildTemplateResponse) MarshalJSON() ([]byte, error) {
	type templateResponse BuildTemplateResponse
	return json.Marshal(struct {
		templateResponse
		Callback *BuildCallback `json:"callback,omitempty"`
	}{templateResponse: templateResponse(r)})
}
