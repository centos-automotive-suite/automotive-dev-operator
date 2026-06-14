package ui

import (
	"os"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

// captureStdout redirects os.Stdout to a pipe, runs fn, then returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w

	fn()

	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestComplete_RendersFullBar(t *testing.T) {
	// Use a non-TTY progress bar (isTTY=false) so output goes through renderPlain
	pb := &ProgressBar{isTTY: false}

	// Simulate partial progress that was rendered mid-build
	pb.Render("Building", &buildapitypes.BuildStep{
		Stage: "Building image",
		Done:  4,
		Total: 8,
	})

	// Call Complete — this should render a final fully-filled state
	out := captureStdout(t, func() {
		pb.Complete()
	})

	if !strings.Contains(out, "8/8") {
		t.Errorf("Complete() should render full progress (8/8), got: %q", out)
	}
	if !strings.Contains(out, "Complete") {
		t.Errorf("Complete() should show 'Complete' stage, got: %q", out)
	}
}

func TestComplete_UsesHighStepTotal(t *testing.T) {
	pb := &ProgressBar{isTTY: false}

	// Simulate a build with 6 total steps
	pb.Render("Building", &buildapitypes.BuildStep{
		Stage: "Pushing",
		Done:  3,
		Total: 6,
	})

	out := captureStdout(t, func() {
		pb.Complete()
	})

	if !strings.Contains(out, "6/6") {
		t.Errorf("Complete() should use the tracked total (6/6), got: %q", out)
	}
}

func TestComplete_NoopWhenNothingRendered(t *testing.T) {
	pb := &ProgressBar{isTTY: false}

	out := captureStdout(t, func() {
		pb.Complete()
	})

	if out != "" {
		t.Errorf("Complete() with no prior render should produce no output, got: %q", out)
	}
}

func TestRender_QuietModeSuppressesOutput(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	pb := &ProgressBar{isTTY: false}
	out := captureStdout(t, func() {
		pb.Render("Building", &buildapitypes.BuildStep{
			Stage: "Building image",
			Done:  4,
			Total: 8,
		})
	})

	if out != "" {
		t.Errorf("Render() in quiet mode should produce no output, got: %q", out)
	}
}

func TestComplete_QuietModeSuppressesOutput(t *testing.T) {
	clilog.SetQuiet(false)
	pb := &ProgressBar{isTTY: false}
	pb.Render("Building", &buildapitypes.BuildStep{
		Stage: "Building image",
		Done:  4,
		Total: 8,
	})

	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	out := captureStdout(t, func() {
		pb.Complete()
	})

	if out != "" {
		t.Errorf("Complete() in quiet mode should produce no output, got: %q", out)
	}
}

func TestClear_QuietModeSuppressesOutput(t *testing.T) {
	clilog.SetQuiet(false)
	pb := &ProgressBar{isTTY: true}
	pb.Render("Building", &buildapitypes.BuildStep{
		Stage: "Building image",
		Done:  4,
		Total: 8,
	})

	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	out := captureStdout(t, func() {
		pb.Clear()
	})

	if out != "" {
		t.Errorf("Clear() in quiet mode should produce no output, got: %q", out)
	}
}
