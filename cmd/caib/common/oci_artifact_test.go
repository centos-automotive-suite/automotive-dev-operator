package caibcommon

import (
	"bytes"
	"os"
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
