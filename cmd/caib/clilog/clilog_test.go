package clilog

import (
	"bytes"
	"os"
	"testing"
)

func TestSetQuietAndIsQuiet(t *testing.T) {
	SetQuiet(false)
	if IsQuiet() {
		t.Error("expected IsQuiet() to be false")
	}
	SetQuiet(true)
	if !IsQuiet() {
		t.Error("expected IsQuiet() to be true")
	}
	SetQuiet(false)
}

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestInfofOutputWhenNotQuiet(t *testing.T) {
	SetQuiet(false)
	out := captureStdout(func() {
		Infof("hello %s\n", "world")
	})
	if out != "hello world\n" {
		t.Errorf("expected 'hello world\\n', got %q", out)
	}
}

func TestInfofSuppressedWhenQuiet(t *testing.T) {
	SetQuiet(true)
	defer SetQuiet(false)
	out := captureStdout(func() {
		Infof("should not appear")
	})
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestInfolnOutputWhenNotQuiet(t *testing.T) {
	SetQuiet(false)
	out := captureStdout(func() {
		Infoln("hello", "world")
	})
	if out != "hello world\n" {
		t.Errorf("expected 'hello world\\n', got %q", out)
	}
}

func TestInfolnSuppressedWhenQuiet(t *testing.T) {
	SetQuiet(true)
	defer SetQuiet(false)
	out := captureStdout(func() {
		Infoln("should not appear")
	})
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func captureStderr(fn func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestStatusfOutputWhenNotQuiet(t *testing.T) {
	SetQuiet(false)
	out := captureStderr(func() {
		Statusf("connecting to %s\n", "server")
	})
	if out != "connecting to server\n" {
		t.Errorf("expected 'connecting to server\\n', got %q", out)
	}
}

func TestStatusfSuppressedWhenQuiet(t *testing.T) {
	SetQuiet(true)
	defer SetQuiet(false)
	out := captureStderr(func() {
		Statusf("should not appear")
	})
	if out != "" {
		t.Errorf("expected empty stderr, got %q", out)
	}
}

func TestStatuslnOutputWhenNotQuiet(t *testing.T) {
	SetQuiet(false)
	out := captureStderr(func() {
		Statusln("auth", "complete")
	})
	if out != "auth complete\n" {
		t.Errorf("expected 'auth complete\\n', got %q", out)
	}
}

func TestStatuslnSuppressedWhenQuiet(t *testing.T) {
	SetQuiet(true)
	defer SetQuiet(false)
	out := captureStderr(func() {
		Statusln("should not appear")
	})
	if out != "" {
		t.Errorf("expected empty stderr, got %q", out)
	}
}

func TestStatusfWritesToStderrNotStdout(t *testing.T) {
	SetQuiet(false)
	stdout := captureStdout(func() {
		Statusf("stderr only\n")
	})
	if stdout != "" {
		t.Errorf("Statusf should not write to stdout, got %q", stdout)
	}
}
