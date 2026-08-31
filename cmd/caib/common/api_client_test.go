package caibcommon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

func TestExecuteWithReauthPreservesForbiddenResponse(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1/workspaces" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"image is not in the allowed images list"}`))
	}))
	defer server.Close()

	token := "valid-token"
	err := ExecuteWithReauth(server.URL, &token, false, func(client *buildapiclient.Client) error {
		_, createErr := client.CreateWorkspace(context.Background(), buildapitypes.WorkspaceRequest{Name: "test"})
		return createErr
	})

	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") || !strings.Contains(err.Error(), "image is not in the allowed images list") {
		t.Fatalf("expected original forbidden response, got %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one request without reauthentication, got %d", got)
	}
}
