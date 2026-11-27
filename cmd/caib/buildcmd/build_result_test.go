package buildcmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestDisplayBuildResultsCredentialsRequireArtifact(t *testing.T) {
	for _, tc := range []struct {
		name, phase, container, disk, lockfile string
	}{
		{name: "failed", phase: "Failed"},
		{name: "cancelled", phase: "Cancelled"},
		{name: "pending", phase: "Pending"},
		{name: "completed without image", phase: "Completed"},
		{name: "container", phase: "Completed", container: "registry.example/image:latest"},
		{name: "disk", phase: "Completed", disk: "registry.example/disk:latest"},
		{name: "flash failed", phase: "Failed", disk: "registry.example/disk:latest"},
		{name: "lockfile", phase: "Completed", lockfile: "registry.example/lockfile:latest"},
	} {
		for _, format := range []string{"table", "json", "yaml"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				tmp := t.TempDir()
				t.Setenv("TMPDIR", tmp)
				clilog.SetQuiet(false)
				t.Cleanup(func() { clilog.SetQuiet(false) })
				server := fakeBuildServer(t, []buildcontract.BuildResponse{{
					Name: "build", Phase: tc.phase, ContainerImage: tc.container,
					DiskImage: tc.disk, LockfileArtifact: tc.lockfile, RegistryToken: "test-registry-token",
				}})
				t.Cleanup(server.Close)
				api, err := buildapiclient.New(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				h := NewHandler(Options{
					Output:      &commandopts.Output{Format: format},
					Registry:    &commandopts.Registry{UseInternalRegistry: true},
					HandleError: func(err error) { t.Errorf("unexpected error: %v", err) },
				})
				out := captureStdout(t, func() { h.displayBuildResults(t.Context(), api, "build") })
				files, err := filepath.Glob(filepath.Join(tmp, "caib-registry-creds-*.json"))
				if err != nil {
					t.Fatal(err)
				}
				wantCredentials := tc.container != "" || tc.disk != "" || tc.lockfile != ""
				wantFiles := 0
				if wantCredentials {
					wantFiles = 1
				}
				if len(files) != wantFiles {
					t.Fatalf("created %d credential files, want %d", len(files), wantFiles)
				}
				if wantCredentials {
					data, err := os.ReadFile(files[0])
					if err != nil {
						t.Fatal(err)
					}
					var credentials map[string]string
					if err := json.Unmarshal(data, &credentials); err != nil {
						t.Fatal(err)
					}
					if credentials["username"] != "serviceaccount" || credentials["token"] != "test-registry-token" {
						t.Fatal("credential file does not contain the expected credentials")
					}
				}
				if format == "table" {
					if strings.Contains(out, "Registry credentials") != wantCredentials {
						t.Fatalf("unexpected credential output: %q", out)
					}
				} else {
					var result BuildResult
					decode := json.Unmarshal
					if format == "yaml" {
						decode = yaml.Unmarshal
					}
					if err := decode([]byte(out), &result); err != nil {
						t.Fatal(err)
					}
					if (result.RegistryToken != "") != wantCredentials ||
						(result.RegistryUsername != "") != wantCredentials ||
						(result.RegistryCredentialsFile != "") != wantCredentials {
						t.Fatalf("unexpected credential fields: %#v", result)
					}
					if result.Phase != tc.phase {
						t.Fatalf("phase = %q, want %q", result.Phase, tc.phase)
					}
				}
			})
		}
	}
}

func TestBuildResultJSONMarshal(t *testing.T) {
	result := BuildResult{
		ExternalID:              "pipeline-42",
		Notification:            &buildcontract.NotificationStatus{State: "Failed", Attempts: 2, LastError: "receiver rejected request"},
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
		"externalId":              "pipeline-42",
		"name":                    "my-build-abc12",
		"phase":                   "Completed",
		"message":                 "Build completed",
		"containerImage":          "registry.example.com/img:v1",
		"diskImage":               "registry.example.com/disk:v1",
		"leaseId":                 "lease-123",
		"registryCredentialsFile": "/tmp/creds.json",
	}
	if notification, ok := roundtrip["notification"].(map[string]any); !ok || notification["state"] != "Failed" || notification["attempts"] != float64(2) {
		t.Fatalf("unexpected notification output: %#v", roundtrip["notification"])
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

	omitKeys := []string{"externalId", "notification", "message", "containerImage", "diskImage", "leaseId", "registryCredentialsFile", "registryUsername", "registryToken"}
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
		format string
		want   bool
	}{
		{"empty", "", false},
		{"table", "table", false},
		{"json", "json", true},
		{"yaml", "yaml", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{opts: Options{Output: &commandopts.Output{Format: tt.format}}}
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

	h := &Handler{opts: Options{Output: &commandopts.Output{Format: format, Wait: wait, FollowLogs: follow}}}

	cmd := &cobra.Command{}
	cmd.Flags().Bool("wait", false, "")
	cmd.Flags().Bool("follow", false, "")

	clilog.SetQuiet(false)
	h.applyWaitFollowDefaults(cmd, true)

	if !clilog.IsQuiet() {
		t.Error("structured output should enable quiet mode")
	}
	if h.opts.Output.Wait != true {
		t.Error("wait should default to true when flag not changed")
	}
	if h.opts.Output.FollowLogs != false {
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
	h := &Handler{opts: Options{Output: &commandopts.Output{Dir: outputDir}, Registry: &commandopts.Registry{UseInternalRegistry: useInternal}}}

	st := &buildcontract.BuildResponse{
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
	h := &Handler{opts: Options{Output: &commandopts.Output{Dir: outputDir}, Registry: &commandopts.Registry{UseInternalRegistry: useInternal}}}

	st := &buildcontract.BuildResponse{
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

func TestDisplayBuildResultsTextQuietSuppressesOutput(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	useInternal := false
	outputDir := ""
	containerPush := "registry.example.com/img:v1"
	exportOCI := "registry.example.com/disk:v1"
	h := &Handler{opts: Options{Output: &commandopts.Output{Dir: outputDir}, Registry: &commandopts.Registry{UseInternalRegistry: useInternal, ContainerPush: containerPush, ExportOCI: exportOCI}}}

	st := &buildcontract.BuildResponse{
		Name:           "test-build",
		Phase:          "Completed",
		ContainerImage: "registry.example.com/img:v1",
		DiskImage:      "registry.example.com/disk:v1",
	}

	out := captureStdout(t, func() {
		h.displayBuildResultsText(st, "")
	})

	if out != "" {
		t.Errorf("quiet mode should suppress all text output, got: %q", out)
	}
}

func TestDisplayBuildResultsTextInternalRegistryQuiet(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	useInternal := true
	outputDir := ""
	h := &Handler{opts: Options{Output: &commandopts.Output{Dir: outputDir}, Registry: &commandopts.Registry{UseInternalRegistry: useInternal}}}

	st := &buildcontract.BuildResponse{
		Name:           "test-build",
		Phase:          "Completed",
		ContainerImage: "image-registry.example.com/img:v1",
		DiskImage:      "image-registry.example.com/disk:v1",
		RegistryToken:  "secret-token",
	}

	out := captureStdout(t, func() {
		h.displayBuildResultsText(st, "")
	})

	if out != "" {
		t.Errorf("quiet mode should suppress all text output, got: %q", out)
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

var testArtifacts = []buildcontract.ArtifactStatus{
	{Kind: "container", URL: "quay.io/org/img:tag", Digest: "sha256:" + strings.Repeat("a", 64)},
	{Kind: "s3", URL: "s3://bucket/disk.raw.xz"},
}

func TestBuildResultArtifactsStructured(t *testing.T) {
	result := BuildResult{Name: "b", Phase: "Completed", Artifacts: testArtifacts}

	jsonOut, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	yamlOut, err := yaml.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	for name, unmarshal := range map[string]func() (map[string]any, error){
		"json": func() (map[string]any, error) { var m map[string]any; return m, json.Unmarshal(jsonOut, &m) },
		"yaml": func() (map[string]any, error) { var m map[string]any; return m, yaml.Unmarshal(yamlOut, &m) },
	} {
		m, err := unmarshal()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		arts, ok := m["artifacts"].([]any)
		if !ok || len(arts) != 2 {
			t.Fatalf("%s: artifacts = %v, want 2 entries", name, m["artifacts"])
		}
		first, _ := arts[0].(map[string]any)
		if first["kind"] != "container" || first["url"] != "quay.io/org/img:tag" || first["digest"] != testArtifacts[0].Digest {
			t.Errorf("%s: first artifact = %v", name, first)
		}
		second, _ := arts[1].(map[string]any)
		if _, ok := second["digest"]; ok {
			t.Errorf("%s: empty digest should be omitted, got %v", name, second)
		}
	}

	empty, err := json.Marshal(BuildResult{Name: "b", Phase: "Completed"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "artifacts") {
		t.Errorf("artifacts should be omitted when empty, got %s", empty)
	}
}

func TestDisplayBuildResultsTextPrintsArtifacts(t *testing.T) {
	for _, internal := range []bool{false} {
		h := &Handler{opts: Options{Output: &commandopts.Output{}, Registry: &commandopts.Registry{
			UseInternalRegistry: internal,
			ContainerPush:       "flag-value-should-not-print",
		}}}
		st := &buildcontract.BuildResponse{
			Name:           "test-build",
			Phase:          "Completed",
			ContainerImage: "quay.io/org/img:tag",
			Artifacts:      testArtifacts,
		}

		out := captureStdout(t, func() {
			h.displayBuildResultsText(st, "")
		})

		for _, want := range []string{"quay.io/org/img:tag", testArtifacts[0].Digest, "s3://bucket/disk.raw.xz", "container", "s3"} {
			if !strings.Contains(out, want) {
				t.Errorf("internal=%v: output missing %q, got:\n%s", internal, want, out)
			}
		}
		if strings.Count(out, "quay.io/org/img:tag") != 1 {
			t.Errorf("internal=%v: container URL should print once, got:\n%s", internal, out)
		}
		if strings.Contains(out, "flag-value-should-not-print") {
			t.Errorf("internal=%v: should print server artifacts, not flag value, got:\n%s", internal, out)
		}
	}
}

// Internal-registry artifacts carry cluster-local URLs, so the externally
// translated image lines must still print alongside them.
func TestDisplayBuildResultsTextInternalRegistryKeepsExternalURL(t *testing.T) {
	h := &Handler{opts: Options{Output: &commandopts.Output{}, Registry: &commandopts.Registry{
		UseInternalRegistry: true,
	}}}
	st := &buildcontract.BuildResponse{
		Name:           "test-build",
		Phase:          "Completed",
		ContainerImage: "default-route.apps.example.com/ns/img:tag",
		DiskImage:      "default-route.apps.example.com/ns/disk:tag",
		Artifacts: []buildcontract.ArtifactStatus{
			{Kind: "container", URL: "image-registry.openshift-image-registry.svc:5000/ns/img:tag"},
		},
	}

	out := captureStdout(t, func() {
		h.displayBuildResultsText(st, "")
	})

	for _, want := range []string{
		"image-registry.openshift-image-registry.svc:5000/ns/img:tag",
		"Container image: default-route.apps.example.com/ns/img:tag",
		"Disk image: default-route.apps.example.com/ns/disk:tag",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got:\n%s", want, out)
		}
	}
}
