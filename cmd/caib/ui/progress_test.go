package ui

import (
	"os"
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

func TestComplete_RendersCompleted(t *testing.T) {
	// Use a non-TTY progress bar (isTTY=false) so output goes through renderPlain
	pb := &ProgressBar{isTTY: false}

	// Simulate partial progress that was rendered mid-build
	pb.Render("Building", &buildapitypes.BuildStep{
		Stage: "Building image",
		Done:  4,
		Total: 8,
	})

	out := captureStdout(t, func() {
		pb.Complete()
	})

	if out != "Completed\n" {
		t.Errorf("Complete() should render completion, got: %q", out)
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

	if out != "Completed\n" || pb.highStep.Done != 6 || pb.highStep.Total != 6 {
		t.Errorf("Complete() should use the tracked total and render completion, got: %q step=%+v", out, pb.highStep)
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

func TestRenderRetainsLastCheckpoint(t *testing.T) {
	for _, tt := range []struct {
		name string
		step *buildapitypes.BuildStep
	}{
		{"older checkpoint", &buildapitypes.BuildStep{Stage: "Preparing build", Done: 1, Total: 5}},
		{"missing checkpoint", nil},
		{"invalid checkpoint", &buildapitypes.BuildStep{Stage: "Preparing build", Done: 0, Total: 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pb := &ProgressBar{}
			captureStdout(t, func() {
				pb.Render("Building", &buildapitypes.BuildStep{Stage: "Building image", Done: 2, Total: 5})
			})
			out := captureStdout(t, func() { pb.Render("Building", tt.step) })
			if out != "" || pb.highStep.Stage != "Building image" || pb.highStep.Done != 2 {
				t.Fatalf("checkpoint regressed: output=%q step=%+v", out, pb.highStep)
			}
		})
	}
}

func TestRenderTTYDoesNotRewriteUnchangedLine(t *testing.T) {
	pb := &ProgressBar{isTTY: true}
	step := &buildapitypes.BuildStep{Stage: "Building image", Done: 2, Total: 5}
	captureStdout(t, func() { pb.Render("Building", step) })
	if out := captureStdout(t, func() { pb.Render("Building", step) }); out != "" {
		t.Fatalf("unchanged line was written again: %q", out)
	}
}

func TestRenderClampsInvalidCountsWithoutMutatingInput(t *testing.T) {
	for _, done := range []int{-1, 9} {
		pb := &ProgressBar{isTTY: true}
		step := &buildapitypes.BuildStep{Stage: "Building image", Done: done, Total: 5}
		captureStdout(t, func() { pb.Render("Building", step) })
		if pb.highStep.Done < 0 || pb.highStep.Done > 5 || step.Done != done {
			t.Fatalf("invalid clamping: rendered=%+v input=%+v", pb.highStep, step)
		}
	}
}

func TestCompleteWithoutCheckpointDoesNotInventCounts(t *testing.T) {
	pb := &ProgressBar{}
	captureStdout(t, func() { pb.Render("Building", nil) })
	if out := captureStdout(t, pb.Complete); out != "Completed\n" {
		t.Fatalf("completion = %q, want a plain completion message", out)
	}
}

func TestRenderCompletionAcceptsCorrectedTotal(t *testing.T) {
	pb := &ProgressBar{}
	captureStdout(t, func() {
		pb.Render("Building", &buildapitypes.BuildStep{Stage: "Building image", Done: 2, Total: 6})
	})
	out := captureStdout(t, func() {
		pb.Render("Completed", &buildapitypes.BuildStep{Stage: "Complete", Done: 4, Total: 4})
	})
	if out != "Completed\n" || pb.highStep.Done != 4 || pb.highStep.Total != 4 {
		t.Fatalf("completion retained the old estimate: %q step=%+v", out, pb.highStep)
	}
}
