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
