package buildcmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

// deadlineTransport records whether each upload request it sends has a
// deadline.
type deadlineTransport struct {
	deadlines chan bool
}

func (d deadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/uploads") {
		_, ok := req.Context().Deadline()
		d.deadlines <- ok
	}
	return http.DefaultTransport.RoundTrip(req)
}

// An upload takes as long as its files take to send, so nothing but the
// caller's context limits it.
func TestHandleFileUploadsDoesNotLimitTheTransfer(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(buildcontract.BuildResponse{Name: "build", Phase: phaseUploading})
	}))
	t.Cleanup(server.Close)
	transport := deadlineTransport{deadlines: make(chan bool, 1)}
	api, err := buildapiclient.New(server.URL, buildapiclient.WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Options{})
	if err := h.handleFileUploads(t.Context(), api, "build", []map[string]string{{"source_path": src, "dest": "file"}}); err != nil {
		t.Fatal(err)
	}
	if <-transport.deadlines {
		t.Error("the upload has a deadline, which a large upload or a slow link would pass")
	}
}

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
