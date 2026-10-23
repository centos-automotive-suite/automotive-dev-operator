package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestWorkspaceExecStream(t *testing.T) {
	const output = "output without a final newline\x00\n[exec failed: ordinary output]\n"
	for _, tc := range []struct {
		status string
		code   int
		failed bool
	}{
		{status: "0"},
		{status: "42", code: 42, failed: true},
		{status: "137", code: 137, failed: true},
		{status: "", failed: true},
		{status: "garbage", failed: true},
		{status: "-1", failed: true},
		{status: "256", failed: true},
	} {
		t.Run("status="+tc.status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("TE") != "trailers" {
					t.Error("client did not advertise trailer support")
				}
				w.Header().Set("Trailer", buildcontract.WorkspaceExecExitCodeTrailer)
				_, _ = io.WriteString(w, output)
				w.(http.Flusher).Flush()
				w.Header().Set(buildcontract.WorkspaceExecExitCodeTrailer, tc.status)
			}))
			defer server.Close()
			api, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := api.ExecWorkspace(context.Background(), "test", buildcontract.WorkspaceExecRequest{Command: "true"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = body.Close() }()
			got, err := io.ReadAll(body)
			if string(got) != output || (err != nil) != tc.failed {
				t.Fatalf("ReadAll = %q, %v; want original output, failed=%v", got, err, tc.failed)
			}
			var exitErr *WorkspaceExecError
			if tc.code != 0 && (!errors.As(err, &exitErr) || exitErr.ExitCode() != tc.code) {
				t.Fatalf("error = %v; want exit code %d", err, tc.code)
			}
		})
	}
}

func TestWorkspaceExecInterruptedStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
		_ = rw.Flush()
	}))
	defer server.Close()
	api, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := api.ExecWorkspace(context.Background(), "test", buildcontract.WorkspaceExecRequest{Command: "true"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	got, err := io.ReadAll(body)
	if string(got) != "hello" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadAll = %q, %v; want hello, unexpected EOF", got, err)
	}
}
