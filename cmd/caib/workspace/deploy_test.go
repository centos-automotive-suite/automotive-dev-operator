package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestWorkspaceDeployFollowsItsRunAndExitsWithItsCode(t *testing.T) {
	if os.Getenv("CAIB_DEPLOY_EXIT_HELPER") == "1" {
		cmd := NewWorkspaceCmd(nil)
		cmd.SetArgs([]string{"deploy", "dev", "--artifact", "/workspace/src/app:/usr/bin/app", "--server", os.Getenv("CAIB_RUN_TEST_SERVER"), "--token", "test-token"})
		if err := cmd.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		return
	}
	var id string
	creates := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			var request buildcontract.WorkspaceDeployRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			creates++
			want := []buildcontract.ArtifactMapping{{Src: "/workspace/src/app", Dest: "/usr/bin/app"}}
			if r.URL.Path != "/v1/workspaces/dev/deploy" || request.ID == "" || (id != "" && id != request.ID) || !slices.Equal(request.Artifacts, want) {
				t.Errorf("invalid or changed deploy request to %s: %+v", r.URL.Path, request)
			}
			id = request.ID
			if creates == 1 {
				// The server started the deploy but its response was lost.
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprintf(w, `{"id":%q,"status":"Running"}`, id)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			_, _ = io.WriteString(w, "rsync output\n")
		default:
			_, _ = fmt.Fprintf(w, `{"id":%q,"status":"Failed","exitCode":23,"logBytes":13}`, id)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkspaceDeployFollowsItsRunAndExitsWithItsCode$")
	cmd.Env = append(os.Environ(), "CAIB_DEPLOY_EXIT_HELPER=1", "CAIB_RUN_TEST_SERVER="+server.URL)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 || string(output) != "Deploying /workspace/src/app -> /usr/bin/app\nrsync output\n" || creates != 2 {
		t.Fatalf("CLI exit: %v, stdout=%q stderr=%q creates=%d", err, output, stderr.String(), creates)
	}
	if !strings.Contains(stderr.String(), "caib workspace exec dev --run "+id) {
		t.Errorf("stderr lacks how to reattach:\n%s", stderr.String())
	}
}
