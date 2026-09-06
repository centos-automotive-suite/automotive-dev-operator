package flashcmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapi "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

func TestFinishFlashRendersTerminalFailureBeforeHandlingError(t *testing.T) {
	format := "json"
	var capturedErr error
	h := NewHandler(Options{
		OutputFormat: &format,
		HandleError:  func(err error) { capturedErr = err },
	})
	resp := &buildapi.FlashResponse{
		Name:    "flash-test",
		Phase:   phaseFailed,
		Message: "device rejected image",
		Notification: &buildapi.NotificationStatus{
			State:     automotivev1alpha1.DeliveryFailed,
			Attempts:  2,
			LastError: "receiver unavailable",
		},
	}
	operationErr := errors.New("flash failed: device rejected image")

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h.finishFlash(resp, operationErr)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	var rendered buildapi.FlashResponse
	if err := json.Unmarshal(out, &rendered); err != nil {
		t.Fatalf("invalid structured output %q: %v", out, err)
	}
	if rendered.Phase != phaseFailed || rendered.Notification == nil ||
		rendered.Notification.State != automotivev1alpha1.DeliveryFailed {
		t.Fatalf("terminal response was not preserved: %+v", rendered)
	}
	if !errors.Is(capturedErr, operationErr) {
		t.Fatalf("HandleError received %v, want %v", capturedErr, operationErr)
	}
}
