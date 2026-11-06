package workspace

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

// dialShellServer connects to a websocket server that serve answers.
func dialShellServer(t *testing.T, serve func(*websocket.Conn)) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		serve(conn)
	}))
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func closeWith(conn *websocket.Conn, text string) {
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, text))
}

// The session sends the terminal's size as text before any keystrokes, sends
// keystrokes as binary, prints what the shell prints, and ends with the
// shell's exit code.
func TestShellSessionRelaysTheTerminalAndReturnsTheExitCode(t *testing.T) {
	type message struct {
		kind int
		data string
	}
	size := func(cols, rows uint16) string {
		data, _ := json.Marshal(buildcontract.WorkspaceShellSize{Cols: cols, Rows: rows})
		return string(data)
	}
	resizes := make(chan buildcontract.WorkspaceShellSize, 1)
	resizes <- buildcontract.WorkspaceShellSize{Cols: 80, Rows: 24}
	got := make(chan message, 3)
	conn := dialShellServer(t, func(conn *websocket.Conn) {
		for i := range 3 {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				t.Error(err)
				return
			}
			got <- message{kind, string(data)}
			if i == 1 {
				// A later resize follows the keystrokes.
				resizes <- buildcontract.WorkspaceShellSize{Cols: 100, Rows: 30}
			}
		}
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("hello\r\n"))
		closeWith(conn, "7")
	})
	// The user typed before the session started.
	stdin := newBlockingPipe()
	_, _ = stdin.Write([]byte("exit 7\r"))

	var stdout bytes.Buffer
	code, err := shellSession(conn, stdin, &stdout, resizes)
	if err != nil || code != 7 {
		t.Fatalf("session = %d, %v; want exit code 7", code, err)
	}
	if stdout.String() != "hello\r\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
	for i, want := range []message{{websocket.TextMessage, size(80, 24)}, {websocket.BinaryMessage, "exit 7\r"}, {websocket.TextMessage, size(100, 30)}} {
		if m := <-got; m != want {
			t.Errorf("message %d = %+v, want %+v", i, m, want)
		}
	}
}

func TestShellSessionFailsWhenTheShellEndsWithoutAnExitCode(t *testing.T) {
	conn := dialShellServer(t, func(conn *websocket.Conn) { closeWith(conn, "") })
	if code, err := shellSession(conn, newBlockingPipe(), &bytes.Buffer{}, nil); err == nil {
		t.Fatalf("session = %d, want an error", code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("terminal gone") }

func TestShellSessionFailsWhenItCannotPrint(t *testing.T) {
	conn := dialShellServer(t, func(conn *websocket.Conn) {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("output"))
		closeWith(conn, "0")
	})
	if code, err := shellSession(conn, newBlockingPipe(), failingWriter{}, nil); err == nil {
		t.Fatalf("session = %d, want the write error", code)
	}
}

// newBlockingPipe stands in for a terminal: reads block until input arrives
// and never see EOF while the session runs.
func newBlockingPipe() *blockingPipe {
	return &blockingPipe{data: make(chan []byte, 4)}
}

type blockingPipe struct{ data chan []byte }

func (b *blockingPipe) Read(p []byte) (int, error) { return copy(p, <-b.data), nil }

func (b *blockingPipe) Write(p []byte) (int, error) {
	b.data <- append([]byte(nil), p...)
	return len(p), nil
}
