package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProgressCheckpointsAreDeliveredInOrder(t *testing.T) {
	dir := t.TempDir()
	script := `
cat() { printf 'test'; }
curl() {
  case "$*" in
    *'Preparing build'*) sleep 0.2; printf 'preparing\n' >> "$PROGRESS_TEST_LOG" ;;
    *'Building image'*) printf 'building\n' >> "$PROGRESS_TEST_LOG" ;;
    *'Finalizing build'*) printf 'finalizing\n' >> "$PROGRESS_TEST_LOG" ;;
  esac
}
emit_progress "Preparing build" 1 4
emit_progress "Building image" 2 4
emit_progress "Finalizing build" 4 4
`
	logPath := filepath.Join(dir, "checkpoints")
	runProgressScript(t, script, "PROGRESS_TEST_LOG="+logPath)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preparing\nbuilding\nfinalizing\n" {
		t.Fatalf("updates arrived out of order: %q", data)
	}
}

func TestProgressFailureWarnsAndAllowsBuildToContinue(t *testing.T) {
	out := runProgressScript(t, `
cat() { printf 'test'; }
curl() { return 22; }
emit_progress "Building image" 2 4
printf 'build continues\n'
`)
	if !strings.Contains(out, "could not report build progress: Building image") || !strings.Contains(out, "build continues") {
		t.Fatalf("missing failure warning or build continuation: %q", out)
	}
}

func runProgressScript(t *testing.T, body string, env ...string) string {
	t.Helper()
	preamble, _, ok := strings.Cut(commonScript, "\nwrite_result()")
	if !ok {
		t.Fatal("progress helper missing from common script")
	}
	cmd := exec.Command("bash", "-c", preamble+"\n"+body)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("progress script failed: %v\n%s", err, out)
	}
	return string(out)
}
