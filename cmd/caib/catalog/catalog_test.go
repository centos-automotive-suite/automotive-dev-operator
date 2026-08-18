package catalog

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/spf13/cobra"
)

func TestGetOutputFormat_ReadsFromRoot(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("output-format", "table", "output format")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	// Default
	if got := getOutputFormat(child); got != outputFormatTable {
		t.Errorf("expected default %q, got %q", outputFormatTable, got)
	}

	// Set to json
	if err := root.PersistentFlags().Set("output-format", outputFormatJSON); err != nil {
		t.Fatal(err)
	}
	if got := getOutputFormat(child); got != outputFormatJSON {
		t.Errorf("expected %q, got %q", outputFormatJSON, got)
	}

	// Set to yaml
	if err := root.PersistentFlags().Set("output-format", outputFormatYAML); err != nil {
		t.Fatal(err)
	}
	if got := getOutputFormat(child); got != outputFormatYAML {
		t.Errorf("expected %q, got %q", outputFormatYAML, got)
	}
}

func TestGetOutputFormat_FallbackWithoutFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "standalone"}
	if got := getOutputFormat(cmd); got != outputFormatTable {
		t.Errorf("expected fallback %q, got %q", outputFormatTable, got)
	}
}

func resetListFlagVars() {
	listArchitecture = ""
	listDistro = ""
	listTarget = ""
	listPhase = ""
	listTags = ""
	listSort = listSortCreated
	listLatest = false
	listAll = false
	listLimit = 20
}

func TestListQueryParams_LatestFlag(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantLatest string
		wantPhase  string
	}{
		{name: "default omits latest so the API keeps its true default", args: nil, wantLatest: ""},
		{name: "explicit --latest sends true", args: []string{"--latest"}, wantLatest: "true"},
		{name: "explicit --latest=false is sent, not dropped", args: []string{"--latest=false"}, wantLatest: "false"},
		{name: "--all disables latest heads", args: []string{"--all"}, wantLatest: "false", wantPhase: "all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetListFlagVars()
			cmd := newListCmd()
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			params, err := listQueryParams(cmd)
			if err != nil {
				t.Fatal(err)
			}
			if got := params.Get("latest"); got != tt.wantLatest {
				t.Errorf("latest=%q, want %q (raw query %q)", got, tt.wantLatest, params.Encode())
			}
			if tt.wantLatest == "" && params.Has("latest") {
				t.Errorf("latest should be omitted, got query %q", params.Encode())
			}
			if tt.wantPhase != "" && params.Get("phase") != tt.wantPhase {
				t.Errorf("phase=%q, want %q", params.Get("phase"), tt.wantPhase)
			}
		})
	}
}

func TestCatalogAgeTimestamp(t *testing.T) {
	if got := catalogAgeTimestamp("created", "published"); got != "published" {
		t.Errorf("catalogAgeTimestamp() = %q, want published", got)
	}
	if got := catalogAgeTimestamp("created", ""); got != "created" {
		t.Errorf("catalogAgeTimestamp() = %q, want created", got)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{1536 * 1024, "1.5 MiB"},
		{2 * 1024 * 1024 * 1024, "2.0 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
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

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func withServerURL(t *testing.T, url string) {
	t.Helper()
	old := serverURL
	serverURL = url
	t.Cleanup(func() { serverURL = old })
}

func TestRemovePromptAutoDeclineInQuietMode(t *testing.T) {
	withServerURL(t, "http://localhost:0")
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	removeForce = false
	defer func() { removeForce = false }()

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("output-format", "table", "output format")
	cmd := &cobra.Command{Use: "remove"}
	root.AddCommand(cmd)

	stdout := captureStdout(t, func() {
		err := runRemove(cmd, []string{"test-image"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if strings.Contains(stdout, "Are you sure") {
		t.Error("prompt should not appear on stdout in quiet mode")
	}
}

func TestRemovePromptAutoDeclineInJSONMode(t *testing.T) {
	withServerURL(t, "http://localhost:0")
	clilog.SetQuiet(false)

	removeForce = false
	defer func() { removeForce = false }()

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("output-format", "table", "output format")
	_ = root.PersistentFlags().Set("output-format", "json")
	cmd := &cobra.Command{Use: "remove"}
	root.AddCommand(cmd)

	stdout := captureStdout(t, func() {
		err := runRemove(cmd, []string{"test-image"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if strings.Contains(stdout, "Are you sure") {
		t.Error("prompt should not appear on stdout in json mode")
	}
	if strings.Contains(stdout, "Cancelled") {
		t.Error("cancellation notice should not appear on stdout in json mode, it would corrupt structured output")
	}
}

func TestRemovePromptWritesToStderr(t *testing.T) {
	withServerURL(t, "http://localhost:0")
	clilog.SetQuiet(false)

	removeForce = false
	defer func() { removeForce = false }()

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("output-format", "table", "output format")
	cmd := &cobra.Command{Use: "remove"}
	root.AddCommand(cmd)

	// Provide "n\n" on stdin to decline
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	_, _ = w.Write([]byte("n\n"))
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	var stderrBuf bytes.Buffer
	oldStderr := os.Stderr
	stderrR, stderrW, _ := os.Pipe()
	os.Stderr = stderrW

	stdout := captureStdout(t, func() {
		_ = runRemove(cmd, []string{"test-image"})
	})

	_ = stderrW.Close()
	os.Stderr = oldStderr
	_, _ = io.Copy(&stderrBuf, stderrR)

	if strings.Contains(stdout, "Are you sure") {
		t.Error("prompt should not appear on stdout")
	}
	if !strings.Contains(stderrBuf.String(), "Are you sure") {
		t.Error("prompt should appear on stderr")
	}
}
