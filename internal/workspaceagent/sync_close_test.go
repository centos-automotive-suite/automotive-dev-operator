package workspaceagent

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Closing waits for the upload in progress, then refuses every later upload,
// so nothing commits once the Build API has completed the build.
func TestSyncUploadCloseWaitsForAnUploadAndRefusesLater(t *testing.T) {
	a := newTestAgent(t)
	a.procDir, a.ptsDir = t.TempDir(), t.TempDir()
	a.TakeBuildUploads()
	first := archive(t, entry(tarFile("first.txt", "first", 0o644)))
	reader, writer := io.Pipe()
	firstDone := make(chan error, 1)
	go func() {
		_, err := a.SyncUpload(SyncUploadRequest{}, reader)
		firstDone <- err
	}()
	// Send the header and part of the content, so the first upload is mid-file.
	if _, err := writer.Write(first[:512+2]); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- a.CloseUploads() }()
	select {
	case <-closed:
		t.Fatal("close returned while an upload was in progress")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := writer.Write(first[512+2:]); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("the upload in progress: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}

	_, err := a.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("late.txt", "late", 0o644)))))
	var agentErr *Error
	if !errors.As(err, &agentErr) || agentErr.Code != http.StatusGone {
		t.Fatalf("upload after close: %v, want 410", err)
	}
	if _, err := os.Stat(filepath.Join(a.workdir, "late.txt")); !os.IsNotExist(err) {
		t.Errorf("an upload after close wrote its file: %v", err)
	}
}

// A restarted agent keeps refusing the uploads that were closed before it
// restarted, as when its container is restarted during a build.
func TestSyncUploadCloseSurvivesRestart(t *testing.T) {
	root, workdir := filepath.Join(t.TempDir(), "runs"), t.TempDir()
	before, err := New(root, workdir, workdir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := before.CloseUploads(); err != nil {
		t.Fatal(err)
	}
	after, err := New(root, workdir, workdir, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	_, err = after.SyncUpload(SyncUploadRequest{}, bytes.NewReader(archive(t, entry(tarFile("late.txt", "late", 0o644)))))
	var agentErr *Error
	if !errors.As(err, &agentErr) || agentErr.Code != http.StatusGone {
		t.Fatalf("upload after restart: %v, want 410", err)
	}
}

// The Build API closes uploads through POST /sync/close, and repeating it is
// harmless.
func TestSyncCloseRoute(t *testing.T) {
	a := newTestAgent(t)
	server := httptest.NewServer(a.Handler("secret", nil))
	t.Cleanup(server.Close)
	for range 2 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/sync/close", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("POST /sync/close = %d, want 204", resp.StatusCode)
		}
	}
}
