package buildapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Anyone may read a build, but only its requester may change what goes into it.

func TestUploadFilesRejectsOtherUsersBuild(t *testing.T) {
	fix := setupUploadTest(t, newTestImageBuild(), newTestUploadPod())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = buildMultipartRequest(t, []multipartPart{{"app.conf", "key=value"}})
	c.Set("requester", "mallory")
	fix.server.uploadFiles(c, "test-build")

	if w.Code != http.StatusForbidden {
		t.Fatalf("response: %d %s, want 403", w.Code, w.Body)
	}
	if len(fix.uploaded) != 0 {
		t.Fatalf("files reached another user's upload pod: %v", fix.uploaded)
	}
}

func TestUploadContainerBuildContextRequiresOwner(t *testing.T) {
	for _, tc := range []struct {
		requester string
		want      int
	}{
		// The owner gets past the check and waits for the build pod.
		{requester: "alice", want: http.StatusServiceUnavailable},
		{requester: "mallory", want: http.StatusForbidden},
	} {
		t.Run(tc.requester, func(t *testing.T) {
			cb := &api.ContainerBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cb", Namespace: "test-ns",
					Annotations: map[string]string{labels.RequestedBy: "alice"},
				},
				Status: api.ContainerBuildStatus{Phase: phaseUploading, BuildRunName: "cb-run"},
			}
			k8s := newFakeClient(cb)
			server := newTestServer(t, func(deps *apiDependencies) {
				deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
			})
			response := postAs(t, tc.requester, "/v1/container-builds/cb/upload", "", func(c *gin.Context) {
				server.uploadContainerBuildContext(c, "cb")
			})
			if response.Code != tc.want {
				t.Fatalf("response: %d %s, want %d", response.Code, response.Body, tc.want)
			}
		})
	}
}
