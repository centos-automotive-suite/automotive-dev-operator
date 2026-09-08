package buildapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
	"github.com/gin-gonic/gin"
)

func validCallback() *BuildCallback {
	return &BuildCallback{
		URL:    "https://receiver.example.com/hooks/builds",
		Secret: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))),
	}
}

func TestNotificationMetadataValidation(t *testing.T) {
	tests := []struct {
		name       string
		externalID string
		callback   *BuildCallback
		valid      bool
	}{
		{name: "none", valid: true},
		{name: "valid", externalID: "pipeline-42", callback: validCallback(), valid: true},
		{name: "external id too long", externalID: strings.Repeat("x", MaxExternalIDBytes+1)},
		{name: "external id control character", externalID: "pipeline\n42"},
		{name: "HTTP callback", callback: &BuildCallback{URL: "http://receiver.example.com/hook", Secret: validCallback().Secret}, valid: true},
		{name: "callback credentials", callback: &BuildCallback{URL: "https://user:pass@receiver.example.com/hook", Secret: validCallback().Secret}},
		{name: "callback fragment", callback: &BuildCallback{URL: "https://receiver.example.com/hook#token", Secret: validCallback().Secret}},
		{name: "short secret", callback: &BuildCallback{URL: "https://receiver.example.com/hook", Secret: base64.StdEncoding.EncodeToString([]byte("short"))}},
		{name: "malformed secret", callback: &BuildCallback{URL: "https://receiver.example.com/hook", Secret: "not-base64"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateOperationMetadata(tc.externalID, tc.callback); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestCallbackPolicy(t *testing.T) {
	httpsCallback := validCallback()
	httpCallback := &BuildCallback{URL: "http://receiver.example.com/hook", Secret: httpsCallback.Secret}
	invalidCallback := &BuildCallback{URL: "https://invalid host/hook", Secret: httpsCallback.Secret}
	enabled := &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{
		FeatureGates: map[string]bool{string(featuregates.WebhookNotifications): true},
	}}
	allowHTTP := enabled.DeepCopy()
	allowHTTP.Spec.WebhookNotifications = &automotivev1alpha1.WebhookNotificationsConfig{AllowHTTP: true}

	for _, tc := range []struct {
		name     string
		config   *automotivev1alpha1.OperatorConfig
		callback *BuildCallback
		valid    bool
	}{
		{name: "no callback", callback: nil, valid: true},
		{name: "missing config", callback: httpsCallback},
		{name: "disabled", config: &automotivev1alpha1.OperatorConfig{}, callback: httpsCallback},
		{name: "invalid URL", config: enabled, callback: invalidCallback},
		{name: "enabled HTTPS", config: enabled, callback: httpsCallback, valid: true},
		{name: "HTTP denied by default", config: enabled, callback: httpCallback},
		{name: "HTTP explicitly allowed", config: allowHTTP, callback: httpCallback, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateCallbackPolicy(tc.config, tc.callback); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestOperationRequestEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"valid", `{"name":"test","externalId":"job-1"}`, http.StatusOK},
		{"oversize trailing bytes", `{"name":"test"}` + strings.Repeat(" ", MaxOperationRequestBytes), http.StatusRequestEntityTooLarge},
		{"trailing JSON", `{"name":"test"} {"name":"other"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")
			var request BuildRequest
			accepted := bindOperationRequest(c, &request)
			if accepted != (tc.status == http.StatusOK) || w.Code != tc.status {
				t.Fatalf("accepted=%v status=%d body=%s", accepted, w.Code, w.Body.String())
			}
		})
	}
}

func TestCallbackFormattingAndJSONRedaction(t *testing.T) {
	request := BuildRequest{Name: "build", Manifest: "name: image", ExternalID: "pipeline-42", Callback: validCallback()}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, request)
		for _, secret := range []string{"receiver.example.com", validCallback().Secret} {
			if strings.Contains(formatted, secret) {
				t.Errorf("format %s leaked callback data", format)
			}
		}
	}
	template := BuildTemplateResponse{BuildRequest: request}
	data, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "callback") || strings.Contains(string(data), validCallback().Secret) {
		t.Fatalf("template response leaked callback: %s", data)
	}
}
