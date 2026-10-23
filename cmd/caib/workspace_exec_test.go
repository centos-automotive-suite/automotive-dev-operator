package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestWorkspaceExecHelperProcess(t *testing.T) {
	if os.Getenv("CAIB_EXEC_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"caib"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

func TestWorkspaceExecCLI(t *testing.T) {
	const script = "make dist-srpm\nrpmbuild -bb kernel.spec\n"
	scriptPath := filepath.Join(t.TempDir(), "build script.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	literalArgs := []string{"a b", "quote'and\"double", "", "$(exit 99)", "; exit 99", "*", "line\nbreak", "back\\slash"}
	for _, tc := range []struct {
		name   string
		args   []string
		status string
		code   int
		quiet  bool
	}{
		{name: "success", args: []string{"--", "true"}, status: "0"},
		{name: "remote failure", args: []string{"--", "false"}, status: "37", code: 37},
		{name: "signal", args: []string{"--", "false"}, status: "137", code: 137},
		{name: "missing status", args: []string{"--", "true"}, code: 1},
		{name: "quiet failure", args: []string{"-q", "--", "false"}, status: "37", code: 37, quiet: true},
		{name: "literal arguments", args: append([]string{"--", "printf", "%s\\0"}, literalArgs...), status: "0"},
		{name: "explicit shell", args: []string{"--", "sh", "-c", "printf '%s' \"remote shell\""}, status: "0"},
		{name: "script upload", args: []string{"--script", scriptPath}, status: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan buildcontract.WorkspaceExecRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/workspaces/test-ws/exec" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				var req buildcontract.WorkspaceExecRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requests <- req
				w.Header().Set("Trailer", buildcontract.WorkspaceExecExitCodeTrailer)
				_, _ = io.WriteString(w, "remote output\n")
				w.(http.Flusher).Flush()
				w.Header().Set(buildcontract.WorkspaceExecExitCodeTrailer, tc.status)
			}))
			defer server.Close()

			stdout, stderr, code := runWorkspaceExecCLI(t, server.URL, tc.args...)
			if code != tc.code {
				t.Fatalf("CLI exit = %d, want %d; stderr: %s", code, tc.code, stderr)
			}
			if !tc.quiet && stdout != "remote output\n" || tc.quiet && stdout != "" {
				t.Errorf("unexpected stdout: %q", stdout)
			}
			select {
			case req := <-requests:
				switch tc.name {
				case "script upload":
					if req.Script != script || req.Command != "" {
						t.Errorf("script upload = %+v", req)
					}
				case "literal arguments", "explicit shell":
					got, err := exec.Command("sh", "-c", req.Command).Output()
					if err != nil {
						t.Fatal(err)
					}
					want := "remote shell"
					if tc.name == "literal arguments" {
						want = strings.Join(literalArgs, "\x00") + "\x00"
					}
					if string(got) != want {
						t.Errorf("remote argv output = %q, want %q", got, want)
					}
				}
			default:
				t.Fatal("no exec request received")
			}
		})
	}
}

func TestWorkspaceExecCLIValidation(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--script", "missing.sh", "--", "echo", "ignored"},
		{"--script", filepath.Join(t.TempDir(), "missing.sh")},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, stderr, code := runWorkspaceExecCLI(t, "http://127.0.0.1:1", args...)
			if code != 1 || stderr == "" {
				t.Fatalf("CLI exit = %d, stderr = %q", code, stderr)
			}
		})
	}
}

func runWorkspaceExecCLI(t *testing.T, server string, args ...string) (string, string, int) {
	t.Helper()
	argv := make([]string, 0, 9+len(args))
	argv = append(argv, "-test.run=^TestWorkspaceExecHelperProcess$", "--", "workspace", "exec", "test-ws", "--server", server, "--token", "test-token")
	argv = append(argv, args...)
	command := exec.Command(os.Args[0], argv...)
	command.Env = append(os.Environ(), "CAIB_EXEC_TEST_HELPER=1")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), command.ProcessState.ExitCode()
}
