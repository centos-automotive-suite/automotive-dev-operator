package buildcmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

// A build that ends before reaching Uploading stops the upload wait.
func TestHandleFileUploadsStopsOnTerminalPhase(t *testing.T) {
	for _, phase := range []string{phaseFailed, phaseCancelled, "Expired", phaseCompleted} {
		t.Run(phase, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(src, nil, 0600); err != nil {
				t.Fatal(err)
			}
			server := fakeBuildServer(t, []buildcontract.BuildResponse{{Name: "build", Phase: phase, Message: "done"}})
			t.Cleanup(server.Close)
			api, err := buildapiclient.New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			h := NewHandler(Options{})
			err = h.handleFileUploads(ctx, api, "build", []map[string]string{{"source_path": src, "dest": "file"}})
			if err == nil || !strings.Contains(err.Error(), strings.ToLower(phase)+" while waiting for upload server") {
				t.Fatalf("err = %v, want build %s error", err, strings.ToLower(phase))
			}
		})
	}
}
