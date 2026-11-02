package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurableScriptRetainsStrictModeAndEOF(t *testing.T) {
	for _, script := range []string{
		"exit 37\necho must-not-run\n",
		"false\necho must-not-run\n",
		"false | true\necho must-not-run\n",
		"cat >/dev/null\nfalse\necho must-not-run\n",
		"unset CAIB_TEST_UNSET_VARIABLE\necho \"${CAIB_TEST_UNSET_VARIABLE}\"\necho must-not-run\n",
		"printf 'script-ok\\n'\n",
	} {
		t.Run(strings.SplitN(script, "\n", 2)[0], func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "build script.sh")
			if err := os.WriteFile(filename, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := newExecCmd()
			if err := cmd.Flags().Set("script", filename); err != nil {
				t.Fatal(err)
			}
			command, err := workspaceRunCommand(cmd, nil)
			if err != nil {
				t.Fatal(err)
			}
			process := exec.Command("/bin/sh", "-c", command)
			output, err := process.CombinedOutput()
			success := strings.HasPrefix(script, "printf")
			if (err == nil) != success || strings.Contains(string(output), "must-not-run") || (success && string(output) != "script-ok\n") {
				t.Fatalf("script strict mode: err=%v output=%q", err, output)
			}
			if strings.HasPrefix(script, "exit 37") && process.ProcessState.ExitCode() != 37 {
				t.Fatalf("script exit status: %d", process.ProcessState.ExitCode())
			}
		})
	}
}

func TestDurableScriptRejectsOversizedEncodedCommands(t *testing.T) {
	for _, script := range []string{
		strings.Repeat("x", 65536),
		strings.Repeat("'", 20000), // Quoting expands a script smaller than 64 KiB.
		strings.Repeat("é", 40000), // The limit counts bytes, not characters.
	} {
		filename := filepath.Join(t.TempDir(), "large.sh")
		if err := os.WriteFile(filename, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := newExecCmd()
		if err := cmd.Flags().Set("script", filename); err != nil {
			t.Fatal(err)
		}
		command, err := workspaceRunCommand(cmd, nil)
		if err == nil || command != "" || !strings.Contains(err.Error(), "65536-byte run command limit after quoting") || !strings.Contains(err.Error(), "sync the script to the workspace and run it from there") {
			t.Fatalf("oversized script: command bytes=%d err=%v", len(command), err)
		}
	}
	for _, size := range []int{65534, 65535} {
		command, err := workspaceRunCommand(newExecCmd(), []string{strings.Repeat("x", size)})
		if size == 65534 && (err != nil || len(command) != 65536) {
			t.Fatalf("command at byte limit rejected: bytes=%d err=%v", len(command), err)
		}
		if size == 65535 && (err == nil || !strings.Contains(err.Error(), "65536-byte run command limit")) {
			t.Fatalf("command over byte limit accepted: bytes=%d err=%v", len(command), err)
		}
	}
}
