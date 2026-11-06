package workspace

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

// The session sends the terminal's size as text and keystrokes as binary,
// prints what the shell prints, and ends with the shell's exit code.
func TestShellSessionRelaysTheTerminalAndReturnsTheExitCode(t *testing.T) {
	type message struct {
		kind int
		data string
	}
	got := make(chan []message, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		var messages []message
		for len(messages) < 3 {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				t.Error(err)
				break
			}
			messages = append(messages, message{kind, string(data)})
		}
		got <- messages
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("hello\r\n"))
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "7"))
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}

	resizes := make(chan buildcontract.WorkspaceShellSize, 2)
	resizes <- buildcontract.WorkspaceShellSize{Cols: 80, Rows: 24}
	resizes <- buildcontract.WorkspaceShellSize{Cols: 100, Rows: 30}
	stdinR, stdinW := newBlockingPipe()
	go func() {
		// Type only after both sizes went out, so the order is fixed.
		time.Sleep(200 * time.Millisecond)
		_, _ = stdinW.Write([]byte("exit 7\r"))
	}()
	var stdout bytes.Buffer
	code, err := shellSession(conn, stdinR, &stdout, resizes)
	if err != nil || code != 7 {
		t.Fatalf("session = %d, %v; want exit code 7", code, err)
	}
	if stdout.String() != "hello\r\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
	size := func(cols, rows uint16) string {
		data, _ := json.Marshal(buildcontract.WorkspaceShellSize{Cols: cols, Rows: rows})
		return string(data)
	}
	want := []message{{websocket.TextMessage, size(80, 24)}, {websocket.TextMessage, size(100, 30)}, {websocket.BinaryMessage, "exit 7\r"}}
	if messages := <-got; len(messages) != 3 || messages[0] != want[0] || messages[1] != want[1] || messages[2] != want[2] {
		t.Errorf("messages = %+v, want %+v", messages, want)
	}
}

// newBlockingPipe stands in for a terminal: reads block until input arrives
// and never see EOF while the session runs.
func newBlockingPipe() (*blockingReader, *blockingReader) {
	r := &blockingReader{data: make(chan []byte, 4)}
	return r, r
}

type blockingReader struct{ data chan []byte }

func (b *blockingReader) Read(p []byte) (int, error) { return copy(p, <-b.data), nil }

func (b *blockingReader) Write(p []byte) (int, error) {
	b.data <- append([]byte(nil), p...)
	return len(p), nil
}
