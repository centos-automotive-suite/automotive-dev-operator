//go:build linux

package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestWorkspaceShellRunsInTheAgent(t *testing.T) {
	agent, _ := startRunAgent(t, t.TempDir())
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := api.ShellWorkspace(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	size, _ := json.Marshal(buildcontract.WorkspaceShellSize{Cols: 123, Rows: 45})
	if err := conn.WriteMessage(websocket.TextMessage, size); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("stty size; exit 4\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var output bytes.Buffer
	for {
		_, data, err := conn.ReadMessage()
		var closed *websocket.CloseError
		if errors.As(err, &closed) {
			if closed.Code != websocket.CloseNormalClosure || closed.Text != "4" {
				t.Errorf("close = %d %q, want a normal close with exit code 4", closed.Code, closed.Text)
			}
			break
		}
		if err != nil {
			t.Fatalf("shell read: %v\n%s", err, output.String())
		}
		output.Write(data)
	}
	if !strings.Contains(output.String(), "45 123") {
		t.Errorf("the shell did not get the terminal size:\n%s", output.String())
	}
}

func TestWorkspaceShellOfAStoppedWorkspaceIsAConflict(t *testing.T) {
	agent, agentRequests := startRunAgent(t, t.TempDir())
	_, router := runTestServer(t, agent.URL, "alice", true)
	api := newRunClient(t, router)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := api.ShellWorkspace(ctx, "dev")
	var response buildapiclient.HTTPError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusConflict {
		t.Fatalf("shell of a stopped workspace: %v", err)
	}
	if n := agentRequests.Load(); n != 0 {
		t.Errorf("the agent got %d requests", n)
	}
}

// Typing while the shell exits must not cost the client the exit code: the
// relay may fail to pass on the keystrokes, but it still relays the close.
func TestWorkspaceShellReportsTheExitCodeWhileTheClientTypes(t *testing.T) {
	agent, _ := startRunAgent(t, t.TempDir())
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
	for attempt := range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := api.ShellWorkspace(ctx, "dev")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte("exit 5\n")); err != nil {
			t.Fatal(err)
		}
		typing := make(chan struct{})
		go func() {
			defer close(typing)
			for conn.WriteMessage(websocket.BinaryMessage, []byte("x")) == nil {
			}
		}()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			_, _, err := conn.ReadMessage()
			if err == nil {
				continue
			}
			var closed *websocket.CloseError
			if !errors.As(err, &closed) || closed.Code != websocket.CloseNormalClosure || closed.Text != "5" {
				t.Fatalf("attempt %d: shell ended with %v, want a normal close with exit code 5", attempt, err)
			}
			break
		}
		_ = conn.Close()
		<-typing
	}
}

// The build API reads each message whole, so it refuses one larger than the
// agent accepts instead of buffering it.
func TestWorkspaceShellRefusesOversizedMessages(t *testing.T) {
	largest := make(chan int, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		n := 0
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				break
			}
			n = max(n, len(data))
		}
		largest <- n
	}))
	defer agent.Close()
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := api.ShellWorkspace(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Just over the limit, so the whole message fits in the socket buffers
	// before the build API refuses it.
	if err := conn.WriteMessage(websocket.BinaryMessage, make([]byte, buildcontract.MaxWorkspaceShellMessageBytes+1)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	var closed *websocket.CloseError
	if !errors.As(err, &closed) || closed.Code != websocket.CloseMessageTooBig {
		t.Errorf("oversized message: %v, want a close for a message too big", err)
	}
	_ = conn.Close()
	select {
	case n := <-largest:
		if n > buildcontract.MaxWorkspaceShellMessageBytes {
			t.Errorf("the agent got a %d-byte message", n)
		}
	case <-time.After(5 * time.Second):
		t.Error("the relay to the agent stayed open")
	}
}

// Reading the agent's close makes the relay answer it, after which relaying
// keystrokes to the agent fails at once. The relay must still pass the close
// on to the client.
func TestWorkspaceShellRelaysTheCloseWhenInputFailsFirst(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "5"))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer agent.Close()
	_, router := runTestServer(t, agent.URL, "alice", false)
	api := newRunClient(t, router)
	for attempt := range 50 {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := api.ShellWorkspace(ctx, "dev")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		typing := make(chan struct{})
		go func() {
			defer close(typing)
			for conn.WriteMessage(websocket.BinaryMessage, []byte("x")) == nil {
			}
		}()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _, err = conn.ReadMessage()
		var closed *websocket.CloseError
		if !errors.As(err, &closed) || closed.Code != websocket.CloseNormalClosure || closed.Text != "5" {
			t.Fatalf("attempt %d: shell ended with %v, want a normal close with exit code 5", attempt, err)
		}
		_ = conn.Close()
		<-typing
	}
}
