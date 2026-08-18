package caibcommon

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
)

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

func TestPullOCIArtifactQuietSuppressesStdout(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	out := captureStdout(func() {
		// Call will fail (invalid ref) but the point is that no fmt.Printf
		// output should appear on stdout before the error.
		_ = PullOCIArtifact("invalid://ref", t.TempDir(), "", "", false)
	})

	if out != "" {
		t.Errorf("quiet mode should suppress all stdout output, got: %q", out)
	}
}

func TestPullOCIArtifactNonQuietPrintsToStdout(t *testing.T) {
	clilog.SetQuiet(false)

	out := captureStdout(func() {
		_ = PullOCIArtifact("invalid://ref", t.TempDir(), "", "", false)
	})

	if out == "" {
		t.Error("non-quiet mode should produce stdout output")
	}
}

func TestPullOCIArtifactNonQuietNoProgressOnStderr(t *testing.T) {
	clilog.SetQuiet(false)

	stderr := captureStderr(func() {
		_ = PullOCIArtifact("invalid://ref", t.TempDir(), "", "", false)
	})

	// Progress/info output must not bleed to stderr; only genuine warnings may appear.
	if strings.Contains(stderr, "Downloading") || strings.Contains(stderr, "Pulling") || strings.Contains(stderr, "Extracting") {
		t.Errorf("non-quiet mode should not send informational output to stderr, got: %q", stderr)
	}
}

func TestExtractOCIArtifactBlobQuietSuppressesStdout(t *testing.T) {
	clilog.SetQuiet(true)
	defer clilog.SetQuiet(false)

	out := captureStdout(func() {
		// Will fail (no index.json) but should produce no stdout output.
		_ = extractOCIArtifactBlob(t.TempDir(), t.TempDir())
	})

	if out != "" {
		t.Errorf("quiet mode should suppress extractOCIArtifactBlob stdout output, got: %q", out)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		layerIndex  int
		want        string
		wantWarning string
	}{
		{"empty string uses fallback", "", 0, "layer-0.bin", ""},
		{"valid filename unchanged", "image.qcow2", 2, "image.qcow2", ""},
		{"null byte uses fallback", "bad\x00name", 1, "layer-1.bin", "null bytes"},
		{"absolute path uses fallback", "/etc/passwd", 3, "layer-3.bin", "absolute path"},
		{"dotdot uses fallback", "../escape", 4, "layer-4.bin", "contains '..'"},
		{"path separator uses basename", "sub/dir/file.img", 5, "file.img", "path separators"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			stderr := captureStderr(func() {
				got = sanitizeFilename(tt.filename, tt.layerIndex)
			})

			if got != tt.want {
				t.Errorf("sanitizeFilename(%q, %d) = %q, want %q", tt.filename, tt.layerIndex, got, tt.want)
			}
			if tt.wantWarning != "" {
				if !strings.Contains(stderr, tt.wantWarning) {
					t.Errorf("expected stderr to contain %q, got: %q", tt.wantWarning, stderr)
				}
			} else if stderr != "" {
				t.Errorf("expected no stderr output, got: %q", stderr)
			}
		})
	}
}
