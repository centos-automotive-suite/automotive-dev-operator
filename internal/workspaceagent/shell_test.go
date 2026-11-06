package workspaceagent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func dialShell(t *testing.T, a *Agent) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(a.Handler("secret", nil))
	t.Cleanup(server.Close)
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/shell",
		http.Header{"Authorization": {"Bearer secret"}})
	if err != nil {
		t.Fatalf("dial shell: %v (%v)", err, resp)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readShell collects output until the shell closes the connection, and
// returns it with the close.
func readShell(t *testing.T, conn *websocket.Conn) (string, *websocket.CloseError) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var output bytes.Buffer
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			closeErr, ok := err.(*websocket.CloseError)
			if !ok {
				t.Fatalf("shell read: %v\n%s", err, output.String())
			}
			return output.String(), closeErr
		}
		output.Write(data)
	}
}

func TestShellRunsInATerminalOfTheClientsSizeAndReportsItsExitCode(t *testing.T) {
	a := newTestAgent(t)
	conn := dialShell(t, a)
	size, _ := json.Marshal(buildcontract.WorkspaceShellSize{Cols: 123, Rows: 45})
	if err := conn.WriteMessage(websocket.TextMessage, size); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("stty size; tty; pwd; exit 3\n")); err != nil {
		t.Fatal(err)
	}
	output, closed := readShell(t, conn)
	for _, want := range []string{"45 123", "/dev/pts/", a.workdir} {
		if !strings.Contains(output, want) {
			t.Errorf("output lacks %q:\n%s", want, output)
		}
	}
	if closed.Code != websocket.CloseNormalClosure || closed.Text != "3" {
		t.Errorf("close = %d %q, want a normal close with exit code 3", closed.Code, closed.Text)
	}
}

func TestShellEndsWhenTheClientGoesAway(t *testing.T) {
	a := newTestAgent(t)
	conn := dialShell(t, a)
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("echo pid=$$\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var output bytes.Buffer
	pid := 0
	for pid == 0 {
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("shell read: %v\n%s", err, output.String())
		}
		output.Write(data)
		// The terminal echoes the command line too; wait for the answer.
		if m := regexp.MustCompile(`pid=(\d+)\r?\n`).FindStringSubmatch(output.String()); m != nil {
			pid, _ = strconv.Atoi(m[1])
		}
	}
	_ = conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the shell outlived its connection")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestShellRequiresTheToken(t *testing.T) {
	server := httptest.NewServer(newTestAgent(t).Handler("secret", nil))
	defer server.Close()
	_, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/shell", nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("shell without a token: %v %v", err, resp)
	}
}

// After the shell exits, a client that stops reading must not keep the agent
// writing to it forever: here a background job floods the terminal and the
// client never reads.
func TestShellGivesUpOnAClientThatStopsReading(t *testing.T) {
	handler := newTestAgent(t).Handler("secret", nil)
	returned := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		close(returned)
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/shell",
		http.Header{"Authorization": {"Bearer secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("yes & exit 2\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("the shell handler is still writing to a client that does not read")
	}
}
