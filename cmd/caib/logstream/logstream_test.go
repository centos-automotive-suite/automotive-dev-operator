package logstream

import (
	"bytes"
	"os"
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
	if w != os.Stderr {
		t.Errorf("expected os.Stderr in quiet mode, got %v", w)
	}
}

func TestLogWriter_ReturnsStdoutWhenNotQuiet(t *testing.T) {
	clilog.SetQuiet(false)

	w := LogWriter()
	if w != os.Stdout {
		t.Errorf("expected os.Stdout in normal mode, got %v", w)
	}
}

func TestStreamLogs_LineHandler(t *testing.T) {
	var buf bytes.Buffer
	state := &State{}
	var seen []string
	state.LineHandler = func(line string) {
		seen = append(seen, line)
	}
	body := strings.NewReader("alpha\nbeta\n")

	if err := StreamLogs(&buf, body, state, false); err != nil {
		t.Fatalf("StreamLogs returned error: %v", err)
	}

	if len(seen) != 2 || seen[0] != "alpha" || seen[1] != "beta" {
		t.Errorf("LineHandler got %v, want [alpha beta]", seen)
	}
}
