package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestFollowWorkspaceRunResumesPartialReadsAndDrainsTerminalLogs(t *testing.T) {
	data := []byte{'a', 0, 0xf0, 0x9f, 0x98, 0x80, '\n', 'z'}
	var offsets []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("run request lost authorization")
		}
		if strings.HasSuffix(r.URL.Path, "/logs") {
			offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
			offsets = append(offsets, offset)
			if len(offsets) == 1 {
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				_, _ = w.Write(data[:3]) // Truncated response, including half a UTF-8 character.
				return
			}
			if offset != 3 {
				t.Errorf("wrong resume offset: %d", offset)
			}
			_, _ = w.Write(data[offset:])
			return
		}
		// The run is already finished when the first connection fails, but the
		// CLI must fetch the remaining bytes before returning the exit status.
		_, _ = fmt.Fprintf(w, `{"id":"run","status":"Failed","exitCode":37,"logBytes":%d}`, len(data))
	}))
	defer server.Close()
	api, err := buildapiclient.New(server.URL, buildapiclient.WithAuthToken("test-token"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	var offset int64
	code, err := followWorkspaceRun(ctx, func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", "run", &offset, &output, io.Discard, time.Millisecond)
	if err != nil || code != 37 || !bytes.Equal(output.Bytes(), data) || offset != int64(len(data)) || len(offsets) != 2 {
		t.Fatalf("follow: code=%d err=%v output=%q offset=%d attempts=%v", code, err, output.Bytes(), offset, offsets)
	}
}

func TestRunCreationRetriesAreBoundedAndPermanentErrorsVisible(t *testing.T) {
	for _, tc := range []struct {
		status, attempts int
	}{
		{http.StatusBadGateway, maxRunAttempts},
		{http.StatusUnprocessableEntity, 1},
		{http.StatusNotImplemented, 1},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				var request buildcontract.WorkspaceRunRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.ID != "stable-id" || request.TimeoutSeconds != 90 {
					t.Errorf("creation changed across retries: %+v, %v", request, err)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":"python3 is unavailable in the workspace image"}`)
			}))
			defer server.Close()
			api, err := buildapiclient.New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = startWorkspaceRun(context.Background(), func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", buildcontract.WorkspaceRunRequest{ID: "stable-id", Command: "make", TimeoutSeconds: 90}, time.Millisecond)
			if err == nil || !strings.Contains(err.Error(), "python3") || int(attempts.Load()) != tc.attempts {
				t.Fatalf("retry/result: err=%v attempts=%d", err, attempts.Load())
			}
			if tc.attempts > 1 && !strings.Contains(err.Error(), "giving up after 6 attempts") {
				t.Fatalf("missing bounded-retry diagnostic: %v", err)
			}
		})
	}
}

func TestRunRetriesBackOffAndRespectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var starts []time.Time
	err := retryRunRequest(ctx, 5*time.Millisecond, func() error {
		starts = append(starts, time.Now())
		if len(starts) == 4 {
			cancel()
		}
		return io.ErrUnexpectedEOF
	})
	if !errors.Is(err, context.Canceled) || len(starts) != 4 {
		t.Fatalf("retry cancellation: %v, %d calls", err, len(starts))
	}
	for i := 1; i < len(starts); i++ {
		if delay := starts[i].Sub(starts[i-1]); delay < (5 * time.Millisecond << (i - 1)) {
			t.Fatalf("retry %d did not back off: %s", i, delay)
		}
	}
}

func TestRunCreationReportsOldServerWithoutFallingBack(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		ambiguous, upgrade      bool
	}{
		{name: "missing route", body: "404 page not found", contentType: "text/plain", upgrade: true},
		{name: "workspace not found", body: `{"error":"workspace not found"}`, contentType: "application/json"},
		{name: "JSON without content type", body: `{"error":"workspace not found"}`},
		{name: "ambiguous launch then old server", body: "404 page not found", ambiguous: true, upgrade: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var creates, executions atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/workspaces/dev/runs" {
					executions.Add(1)
					t.Errorf("unexpected execution fallback: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
					return
				}
				if creates.Add(1) == 1 && tc.ambiguous {
					w.WriteHeader(502)
					return
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(404)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			api, err := buildapiclient.New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = startWorkspaceRun(context.Background(), func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", buildcontract.WorkspaceRunRequest{ID: "id", Command: "make"}, time.Millisecond)
			if err == nil || executions.Load() != 0 || strings.Contains(err.Error(), "upgrade the operator") != tc.upgrade || !strings.Contains(err.Error(), tc.body) {
				t.Fatalf("old server diagnostic: err=%v executions=%d", err, executions.Load())
			}
			wantCreates := int32(1)
			if tc.ambiguous {
				wantCreates++
			}
			if creates.Load() != wantCreates {
				t.Fatalf("unexpected retries: %d", creates.Load())
			}
		})
	}
}

func TestFollowRunUsesTruncatedOffsetAndPrintsTimeoutMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs") {
			w.Header().Set("X-Log-Offset", "1000")
			_, _ = io.WriteString(w, "last error\n")
			return
		}
		_, _ = io.WriteString(w, `{"status":"TimedOut","exitCode":124,"logBytes":1011,"logStartOffset":1000,"logTruncated":true,"message":"Run timed out after 7200 seconds"}`)
	}))
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	var offset int64
	code, err := followWorkspaceRun(context.Background(), func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", "run", &offset, &output, &diagnostics, time.Millisecond)
	if err != nil || code != 124 || offset != 1011 || output.String() != "last error\n" || !strings.Contains(diagnostics.String(), "skipped 1000 bytes") || !strings.Contains(diagnostics.String(), "Run timed out after 7200 seconds") {
		t.Fatalf("tail/timeout: %d %v offset=%d output=%q diagnostics=%q", code, err, offset, output.String(), diagnostics.String())
	}
}

func TestFollowRunGivesUpWhenOnlyLogsFail(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs") {
			requests.Add(1)
			w.WriteHeader(502)
			return
		}
		_, _ = io.WriteString(w, `{"status":"Running","logBytes":0}`)
	}))
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var offset int64
	_, err = followWorkspaceRun(context.Background(), func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", "run", &offset, io.Discard, io.Discard, time.Millisecond)
	if err == nil || requests.Load() != maxRunAttempts {
		t.Fatalf("log retry limit: %v, %d requests", err, requests.Load())
	}
}

func TestFollowRunUsesServerStreamCapWithoutExhaustingRetries(t *testing.T) {
	var streams atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs") {
			streams.Add(1)
			w.Header().Set("X-Log-Stream-Seconds", "0.01")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			return
		}
		if streams.Load() > maxRunAttempts {
			_, _ = io.WriteString(w, `{"status":"Succeeded","exitCode":0,"logBytes":0}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"Running","logBytes":0}`)
	}))
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var offset int64
	code, err := followWorkspaceRun(ctx, func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", "run", &offset, io.Discard, io.Discard, time.Millisecond)
	if err != nil || code != 0 || streams.Load() != maxRunAttempts+1 {
		t.Fatalf("normal stream rotations consumed retries: code=%d err=%v streams=%d", code, err, streams.Load())
	}
}

func TestFollowRunReturnsResultAfterLogBudgetEviction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs") {
			w.Header().Set("X-Log-Offset", "2000")
			return
		}
		_, _ = io.WriteString(w, `{"status":"Failed","exitCode":3,"logBytes":2000,"logStartOffset":2000,"logsEvicted":true}`)
	}))
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var offset int64
	var output, diagnostics bytes.Buffer
	code, err := followWorkspaceRun(context.Background(), func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", "run", &offset, &output, &diagnostics, time.Millisecond)
	if err != nil || code != 3 || offset != 2000 || output.Len() != 0 || !strings.Contains(diagnostics.String(), "evicted") {
		t.Fatalf("evicted log lost command result: code=%d err=%v offset=%d output=%q diagnostics=%q", code, err, offset, output.String(), diagnostics.String())
	}
}

func TestFollowWorkspaceRunReportsUnavailableExitCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/logs") {
			_, _ = io.WriteString(w, `{"id":"run","status":"Interrupted","message":"pod stopped","logBytes":0}`)
		}
	}))
	defer server.Close()
	api, err := buildapiclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var offset int64
	_, err = followWorkspaceRun(context.Background(), func(fn func(*buildapiclient.Client) error) error { return fn(api) }, "dev", "run", &offset, io.Discard, io.Discard, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "exit code unavailable") {
		t.Fatalf("interruption was treated as success: %v", err)
	}
}

func TestWorkspaceExecExitCode(t *testing.T) {
	if os.Getenv("CAIB_RUN_EXIT_HELPER") == "1" {
		cmd := NewWorkspaceCmd(nil)
		cmd.SetArgs([]string{"exec", "dev", "--timeout", "90s", "--server", os.Getenv("CAIB_RUN_TEST_SERVER"), "--token", "test-token", "--", "sh", "-c", "exit 42"})
		if err := cmd.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		return
	}
	var id string
	creates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			var request buildcontract.WorkspaceRunRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			creates++
			if request.ID == "" || (id != "" && id != request.ID) || request.Command != "'sh' '-c' 'exit 42'" || request.TimeoutSeconds != 90 {
				t.Errorf("invalid or changed create request: %+v", request)
			}
			id = request.ID
			if creates == 1 {
				// The server accepted the command but its response was lost.
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprintf(w, `{"id":%q,"status":"Running"}`, id)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			_, _ = io.WriteString(w, "command output\n")
		default:
			_, _ = fmt.Fprintf(w, `{"id":%q,"status":"Failed","exitCode":42,"logBytes":15,"message":"recorded failure detail"}`, id)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkspaceExecExitCode$")
	cmd.Env = append(os.Environ(), "CAIB_RUN_EXIT_HELPER=1", "CAIB_RUN_TEST_SERVER="+server.URL)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 || string(output) != "command output\n" || creates != 2 || !strings.Contains(stderr.String(), "recorded failure detail") {
		t.Fatalf("CLI exit: %v, stdout=%q stderr=%q creates=%d", err, output, stderr.String(), creates)
	}
}

func TestWorkspaceExecInterruptPrintsResumeAndCancel(t *testing.T) {
	if os.Getenv("CAIB_RUN_INTERRUPT_HELPER") == "1" {
		cmd := NewWorkspaceCmd(nil)
		cmd.SetArgs([]string{"exec", "dev", "--run", "still-running", "--server", os.Getenv("CAIB_RUN_TEST_SERVER"), "--token", "test-token"})
		if err := cmd.Execute(); err != nil {
			os.Exit(99)
		}
		return
	}
	following := make(chan struct{})
	var cancellations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cancel") {
			cancellations.Add(1)
		}
		if strings.HasSuffix(r.URL.Path, "/logs") {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(following)
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, `{"status":"Running","logBytes":0}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkspaceExecInterruptPrintsResumeAndCancel$")
	cmd.Env = append(os.Environ(), "CAIB_RUN_INTERRUPT_HELPER=1", "CAIB_RUN_TEST_SERVER="+server.URL)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-following:
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("CLI did not begin following")
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 130 || cancellations.Load() != 0 || !strings.Contains(stderr.String(), "caib workspace exec dev --run still-running --offset 0") || !strings.Contains(stderr.String(), "caib workspace run cancel dev still-running") {
		t.Fatalf("interrupt: %v, cancellations=%d stderr=%q", err, cancellations.Load(), stderr.String())
	}
}
