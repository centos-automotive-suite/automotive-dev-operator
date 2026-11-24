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
	"sync/atomic"
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

// Only a regular file uploads, and opening anything else, a FIFO say, could
// block the upload for good, so the CLI refuses one before it starts.
func TestHandleFileUploadsTakesOnlyRegularFiles(t *testing.T) {
	server := fakeBuildServer(t, []buildcontract.BuildResponse{{Name: "build", Phase: phaseFailed, Message: "done"}})
	t.Cleanup(server.Close)
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	err = NewHandler(Options{}).handleFileUploads(t.Context(), api, "build", []map[string]string{{"source_path": dir, "dest": "file"}})
	if err == nil || !strings.Contains(err.Error(), dir+" is not a regular file") {
		t.Fatalf("err = %v, want the directory refused", err)
	}
}

// uploadAttemptServer reports the build as Uploading and answers each upload
// attempt with reply, which is passed the attempt's number, starting at 1.
func uploadAttemptServer(t *testing.T, reply func(attempt int32, w http.ResponseWriter)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(buildcontract.BuildResponse{Name: "build", Phase: phaseUploading})
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		reply(attempts.Add(1), w)
	}))
	t.Cleanup(server.Close)
	return server, &attempts
}

// Only a 503, the upload pod not being ready yet, is retried.
func TestHandleFileUploadsRetriesServiceUnavailable(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, attempts := uploadAttemptServer(t, func(attempt int32, w http.ResponseWriter) {
		if attempt == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"upload pod not ready"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = NewHandler(Options{}).handleFileUploads(t.Context(), api, "build", []map[string]string{{"source_path": src, "dest": "file"}})
	if err != nil || attempts.Load() != 2 {
		t.Fatalf("attempts = %d, err = %v; want a retry that succeeds", attempts.Load(), err)
	}
}

// The status decides a retry, not the message. A 400 that repeats the retried
// message is the client's error, and retrying it would repeat it until the
// ten-minute deadline.
func TestHandleFileUploadsDoesNotRetryByMessage(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server, attempts := uploadAttemptServer(t, func(attempt int32, w http.ResponseWriter) {
		if attempt > 1 {
			// Only a retry on the message gets here, so stop the loop.
			cancel()
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"upload pod not ready"}`))
	})
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = NewHandler(Options{}).handleFileUploads(ctx, api, "build", []map[string]string{{"source_path": src, "dest": "file"}})
	if err == nil || attempts.Load() != 1 {
		t.Fatalf("attempts = %d, err = %v; want one attempt and its error", attempts.Load(), err)
	}
}
