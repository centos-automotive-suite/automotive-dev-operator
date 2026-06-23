package buildcmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapi "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func strPtr(s string) *string { return &s }

func TestBuildResultJSONMarshal(t *testing.T) {
	result := BuildResult{
		Name:                    "my-build-abc12",
		Phase:                   "Completed",
		Message:                 "Build completed",
		ContainerImage:          "registry.example.com/img:v1",
		DiskImage:               "registry.example.com/disk:v1",
		LeaseID:                 "lease-123",
		RegistryCredentialsFile: "/tmp/creds.json",
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var roundtrip map[string]any
	if err := json.Unmarshal(out, &roundtrip); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	checks := map[string]string{
		"name":                    "my-build-abc12",
		"phase":                   "Completed",
		"message":                 "Build completed",
		"containerImage":          "registry.example.com/img:v1",
		"diskImage":               "registry.example.com/disk:v1",
		"leaseId":                 "lease-123",
		"registryCredentialsFile": "/tmp/creds.json",
	}
	for key, want := range checks {
		got, ok := roundtrip[key]
		if !ok {
			t.Errorf("missing key %q in JSON output", key)
			continue
		}
		if got != want {
			t.Errorf("key %q = %v, want %v", key, got, want)
		}
	}
}

func TestBuildResultOmitEmpty(t *testing.T) {
	result := BuildResult{
		Name:  "my-build",
		Phase: "Pending",
	}

	out, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	var roundtrip map[string]any
	if err := json.Unmarshal(out, &roundtrip); err != nil {
		t.Fatal(err)
	}

	omitKeys := []string{"message", "containerImage", "diskImage", "leaseId", "registryCredentialsFile", "registryUsername", "registryToken"}
	for _, key := range omitKeys {
		if _, ok := roundtrip[key]; ok {
			t.Errorf("expected omitempty to exclude empty field %q", key)
		}
	}

	if roundtrip["name"] != "my-build" {
		t.Errorf("name = %v, want my-build", roundtrip["name"])
	}
	if roundtrip["phase"] != "Pending" {
		t.Errorf("phase = %v, want Pending", roundtrip["phase"])
	}
}

func TestIsStructuredOutput(t *testing.T) {
	tests := []struct {
		name   string
		format *string
		want   bool
	}{
		{"nil", nil, false},
		{"table", strPtr("table"), false},
		{"json", strPtr("json"), true},
		{"yaml", strPtr("yaml"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{opts: Options{OutputFormat: tt.format}}
			if got := h.isStructuredOutput(); got != tt.want {
				t.Errorf("isStructuredOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyWaitFollowDefaultsStructuredOutput(t *testing.T) {
	format := "json"
	wait := false
	follow := true

	h := &Handler{opts: Options{
		OutputFormat: &format,
		WaitForBuild: &wait,
		FollowLogs:   &follow,
	}}

	cmd := &cobra.Command{}
	cmd.Flags().Bool("wait", false, "")
	cmd.Flags().Bool("follow", false, "")

	clilog.SetQuiet(false)
	h.applyWaitFollowDefaults(cmd, true)

	if !clilog.IsQuiet() {
		t.Error("structured output should enable quiet mode")
	}
	if *h.opts.WaitForBuild != true {
		t.Error("wait should default to true when flag not changed")
	}
	if *h.opts.FollowLogs != false {
		t.Error("follow should default to false")
	}

	clilog.SetQuiet(false)
}

func TestBuildResultTokenFallback(t *testing.T) {
	result := BuildResult{
		Name:             "my-build",
		Phase:            "Completed",
		RegistryToken:    "tok-abc123",
		RegistryUsername: "serviceaccount",
	}

	out, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	var roundtrip map[string]any
	if err := json.Unmarshal(out, &roundtrip); err != nil {
		t.Fatal(err)
	}

	if roundtrip["registryToken"] != "tok-abc123" {
		t.Errorf("registryToken = %v, want tok-abc123", roundtrip["registryToken"])
	}
	if roundtrip["registryUsername"] != "serviceaccount" {
		t.Errorf("registryUsername = %v, want serviceaccount", roundtrip["registryUsername"])
	}
	if _, ok := roundtrip["registryCredentialsFile"]; ok {
		t.Error("expected registryCredentialsFile to be omitted when empty")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestDisplayBuildResultsTextTokenFallback(t *testing.T) {
	useInternal := true
	outputDir := ""
	h := &Handler{opts: Options{
		UseInternalRegistry: &useInternal,
		OutputDir:           &outputDir,
	}}

	st := &buildapi.BuildResponse{
		Name:          "test-build",
		Phase:         "Completed",
		RegistryToken: "secret-token-xyz",
	}

	out := captureStdout(t, func() {
		h.displayBuildResultsText(st, "")
	})

	if !strings.Contains(out, "secret-token-xyz") {
		t.Errorf("text fallback should print token when credsFile empty, got:\n%s", out)
	}
	if !strings.Contains(out, "serviceaccount") {
		t.Errorf("text fallback should print username, got:\n%s", out)
	}
}

func TestDisplayBuildResultsTextCredsFileSuccess(t *testing.T) {
	useInternal := true
	outputDir := ""
	h := &Handler{opts: Options{
		UseInternalRegistry: &useInternal,
		OutputDir:           &outputDir,
	}}

	st := &buildapi.BuildResponse{
		Name:          "test-build",
		Phase:         "Completed",
		RegistryToken: "secret-token-xyz",
	}

	out := captureStdout(t, func() {
		h.displayBuildResultsText(st, "/tmp/creds.json")
	})

	if !strings.Contains(out, "/tmp/creds.json") {
		t.Errorf("should show creds file path, got:\n%s", out)
	}
	if strings.Contains(out, "secret-token-xyz") {
		t.Errorf("should NOT print raw token when creds file succeeded, got:\n%s", out)
	}
}

func TestBuildResultYAMLKeysMatchJSON(t *testing.T) {
	result := BuildResult{
		Name:                    "b",
		Phase:                   "Completed",
		Message:                 "done",
		ContainerImage:          "img",
		DiskImage:               "disk",
		LeaseID:                 "lease",
		RegistryCredentialsFile: "/tmp/c",
		RegistryUsername:        "user",
		RegistryToken:           "tok",
	}

	jsonOut, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var jsonMap map[string]any
	if err := json.Unmarshal(jsonOut, &jsonMap); err != nil {
		t.Fatal(err)
	}

	yamlOut, err := yaml.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var yamlMap map[string]any
	if err := yaml.Unmarshal(yamlOut, &yamlMap); err != nil {
		t.Fatal(err)
	}

	for key := range jsonMap {
		if _, ok := yamlMap[key]; !ok {
			t.Errorf("JSON key %q missing from YAML output (got YAML keys: %v)", key, yamlMap)
		}
	}
	for key := range yamlMap {
		if _, ok := jsonMap[key]; !ok {
			t.Errorf("YAML key %q missing from JSON output", key)
		}
	}
}

func TestBuildResultRenderFormatted(t *testing.T) {
	result := BuildResult{
		Name:  "test-build",
		Phase: "Completed",
	}

	var gotErr error
	handleErr := func(err error) { gotErr = err }

	caibcommon.RenderFormatted("json", result, nil, handleErr)
	if gotErr != nil {
		t.Fatalf("RenderFormatted(json) error: %v", gotErr)
	}

	caibcommon.RenderFormatted("yaml", result, nil, handleErr)
	if gotErr != nil {
		t.Fatalf("RenderFormatted(yaml) error: %v", gotErr)
	}
}
