//go:build linux

package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
