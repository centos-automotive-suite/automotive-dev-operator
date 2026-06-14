package buildcmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

func newTestOpts() Options {
	opts := newTestDiskOpts()
	var (
		workspace        string
		extraRepos       []string
		flashCmd         string
		exporterSelector string
	)
	opts.Workspace = &workspace
	opts.ExtraRepos = &extraRepos
	opts.FlashCmd = &flashCmd
	opts.ExporterSelector = &exporterSelector
	return opts
}

// fakeBuildServer creates an httptest.Server that responds to /v1/builds/<name>
// with the given BuildResponse sequence. Each call to GetBuild returns the next
// response; once exhausted it repeats the last one. Progress endpoint returns 404.
func fakeBuildServer(t *testing.T, responses []buildapitypes.BuildResponse) *httptest.Server {
	t.Helper()
	callIdx := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/progress") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		idx := callIdx
		if idx < len(responses)-1 {
			callIdx++
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(responses[idx]); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
}

func TestWaitForBuildCompletion_BuildFailedNoDiskImage(t *testing.T) {
	responses := []buildapitypes.BuildResponse{
		{
			Name:    "test-build",
			Phase:   "Failed",
			Message: `"step-build-image" exited with code 1`,
		},
	}
	srv := fakeBuildServer(t, responses)
	defer srv.Close()

	opts := newTestOpts()
	*opts.ServerURL = srv.URL
	timeout := 1
	opts.Timeout = &timeout

	var capturedErr error
	opts.HandleError = func(err error) { capturedErr = err }
	h := NewHandler(opts)

	api, err := buildapiclient.New(srv.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Capture stdout to verify no flash instructions printed
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	waitErr := h.waitForBuildCompletion(t.Context(), api, "test-build")

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	if waitErr == nil {
		t.Fatal("expected error from waitForBuildCompletion")
	}

	output := string(out)
	if strings.Contains(output, "Flash failed") {
		t.Errorf("should not show flash instructions when build itself failed, got: %s", output)
	}
	if strings.Contains(output, "flash manually") {
		t.Errorf("should not show manual flash guidance when build failed, got: %s", output)
	}
	if capturedErr == nil {
		t.Fatal("expected HandleError to be called")
	}
	if !strings.Contains(capturedErr.Error(), "step-build-image") {
		t.Errorf("error should contain build failure message, got: %v", capturedErr)
	}
}

func TestWaitForBuildCompletion_BuildFailedWithDiskImage_NotFlashFailure(t *testing.T) {
	// Edge case: server returns DiskImage on a build failure (shouldn't happen
	// with server fix, but tests client-side defense-in-depth).
	responses := []buildapitypes.BuildResponse{
		{
			Name:      "test-build",
			Phase:     "Failed",
			Message:   `"step-build-image" exited with code 1`,
			DiskImage: "registry.example.com/img:disk",
		},
	}
	srv := fakeBuildServer(t, responses)
	defer srv.Close()

	opts := newTestOpts()
	*opts.ServerURL = srv.URL
	*opts.FlashAfterBuild = true
	timeout := 1
	opts.Timeout = &timeout

	var capturedErr error
	opts.HandleError = func(err error) { capturedErr = err }
	h := NewHandler(opts)

	api, err := buildapiclient.New(srv.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	waitErr := h.waitForBuildCompletion(t.Context(), api, "test-build")

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	if waitErr == nil {
		t.Fatal("expected error from waitForBuildCompletion")
	}

	output := string(out)
	// Even though DiskImage is set and FlashAfterBuild is true, the message
	// does not indicate a flash failure, so no flash instructions should appear.
	if strings.Contains(output, "Flash failed") {
		t.Errorf("should not show flash instructions for build failure (not flash failure), got: %s", output)
	}
	if capturedErr == nil {
		t.Fatal("expected HandleError to be called")
	}
}

func TestWaitForBuildCompletion_FlashFailure_ShowsFlashInstructions(t *testing.T) {
	responses := []buildapitypes.BuildResponse{
		{
			Name:      "test-build",
			Phase:     "Failed",
			Message:   "Flash to device failed: timeout waiting for device",
			DiskImage: "registry.example.com/ns/test-build:disk",
			Jumpstarter: &buildapitypes.JumpstarterInfo{
				Available:        true,
				ExporterSelector: "board-type=renesas-rcar-s4,enabled=true",
				FlashCmd:         "j storage flash oci://registry.example.com/ns/test-build:disk",
			},
		},
	}
	srv := fakeBuildServer(t, responses)
	defer srv.Close()

	opts := newTestOpts()
	*opts.ServerURL = srv.URL
	*opts.FlashAfterBuild = true
	timeout := 1
	opts.Timeout = &timeout

	var capturedErr error
	opts.HandleError = func(err error) { capturedErr = err }
	h := NewHandler(opts)

	api, err := buildapiclient.New(srv.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	waitErr := h.waitForBuildCompletion(t.Context(), api, "test-build")

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	if waitErr == nil {
		t.Fatal("expected error from waitForBuildCompletion")
	}

	output := string(out)
	if !strings.Contains(output, "Flash failed") {
		t.Errorf("expected flash failure message, got: %s", output)
	}
	if !strings.Contains(output, "flash manually") {
		t.Errorf("expected manual flash guidance, got: %s", output)
	}
	if !strings.Contains(output, "j storage flash") {
		t.Errorf("expected flash command in output, got: %s", output)
	}
	if capturedErr == nil {
		t.Fatal("expected HandleError to be called")
	}
	if !strings.Contains(capturedErr.Error(), "Flash to device failed") {
		t.Errorf("error should contain flash failure message, got: %v", capturedErr)
	}
}

func TestWaitForBuildCompletion_FlashFailure_NoJumpstarter(t *testing.T) {
	// Flash failure detected but no Jumpstarter info — should still call
	// handleFlashError (which calls handleError) but not print flash instructions.
	responses := []buildapitypes.BuildResponse{
		{
			Name:      "test-build",
			Phase:     "Failed",
			Message:   "Flash to device failed: connection refused",
			DiskImage: "registry.example.com/ns/test-build:disk",
		},
	}
	srv := fakeBuildServer(t, responses)
	defer srv.Close()

	opts := newTestOpts()
	*opts.ServerURL = srv.URL
	*opts.FlashAfterBuild = true
	timeout := 1
	opts.Timeout = &timeout

	var capturedErr error
	opts.HandleError = func(err error) { capturedErr = err }
	h := NewHandler(opts)

	api, err := buildapiclient.New(srv.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	waitErr := h.waitForBuildCompletion(t.Context(), api, "test-build")

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	if waitErr == nil {
		t.Fatal("expected error from waitForBuildCompletion")
	}

	output := string(out)
	// No Jumpstarter info, so no "flash manually" instructions should appear
	if strings.Contains(output, "flash manually") {
		t.Errorf("should not show flash instructions without Jumpstarter info, got: %s", output)
	}
	if capturedErr == nil {
		t.Fatal("expected HandleError to be called")
	}
	if !strings.Contains(capturedErr.Error(), "Flash to device failed") {
		t.Errorf("error should contain flash failure message, got: %v", capturedErr)
	}
}
