package caibcommon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBuildCallbackPreservesRawSecret(t *testing.T) {
	secret := []byte("\n012345678901234567890123456789\n")
	path := filepath.Join(t.TempDir(), "callback.key")
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	callback, err := LoadBuildCallback("https://receiver.example.com/hook", path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(callback.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(secret) {
		t.Fatalf("secret bytes changed: got %q want %q", decoded, secret)
	}
}

func TestLoadBuildCallbackValidation(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "callback.key")
	if err := os.WriteFile(validPath, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, url, path string
	}{
		{name: "URL only", url: "https://receiver.example.com/hook"},
		{name: "secret only", path: validPath},
		{name: "short secret", url: "https://receiver.example.com/hook", path: filepath.Join(t.TempDir(), "short.key")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "short secret" {
				if err := os.WriteFile(tc.path, []byte("short"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadBuildCallback(tc.url, tc.path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	callback, err := LoadBuildCallback("", "")
	if err != nil || callback != nil {
		t.Fatalf("empty callback returned callback=%+v err=%v", callback, err)
	}
}
