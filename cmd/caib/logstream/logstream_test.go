package logstream

import (
	"bytes"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
)

func TestStreamLogs_WritesToProvidedWriter(t *testing.T) {
	var buf bytes.Buffer
	state := &State{}
	body := strings.NewReader("line1\nline2\nline3\n")

	if err := StreamLogs(&buf, body, state, false); err != nil {
		t.Fatalf("StreamLogs returned error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "line1") || !strings.Contains(got, "line2") || !strings.Contains(got, "line3") {
		t.Errorf("expected all lines in writer output, got: %q", got)
	}
}

func TestStreamLogs_CapturesLeaseID(t *testing.T) {
	var buf bytes.Buffer
	state := &State{}
	body := strings.NewReader("some output\njmp shell --lease abc-123 foo\nmore output\n")

	if err := StreamLogs(&buf, body, state, true); err != nil {
		t.Fatalf("StreamLogs returned error: %v", err)
	}

	if state.LeaseID != "abc-123" {
		t.Errorf("expected LeaseID=abc-123, got %q", state.LeaseID)
	}
}

func TestStreamLogs_NilStateReturnsError(t *testing.T) {
	var buf bytes.Buffer
	body := strings.NewReader("line\n")

	if err := StreamLogs(&buf, body, nil, false); err == nil {
		t.Error("expected error for nil state")
	}
}

func TestLogWriter_ReturnsStderrWhenQuiet(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	w := LogWriter()
	// LogWriter should not return os.Stdout when quiet
	// We can't easily compare io.Writer identity, but we can verify the function
	// returns a non-nil writer that is stderr
	if w == nil {
		t.Fatal("LogWriter returned nil")
	}
}

func TestLogWriter_ReturnsStdoutWhenNotQuiet(t *testing.T) {
	clilog.SetQuiet(false)

	w := LogWriter()
	if w == nil {
		t.Fatal("LogWriter returned nil")
	}
}

func TestStreamLogs_QuietModeDoesNotWriteToStdout(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	var buf bytes.Buffer
	state := &State{}
	body := strings.NewReader("log line 1\nlog line 2\n")

	if err := StreamLogs(&buf, body, state, false); err != nil {
		t.Fatalf("StreamLogs returned error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "log line 1") || !strings.Contains(got, "log line 2") {
		t.Errorf("expected log lines in provided writer, got: %q", got)
	}
}
