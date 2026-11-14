package buildapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/gin-gonic/gin"
	imagev1 "github.com/openshift/api/image/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// Builds, container builds and reseals push into an ImageStream named by the
// request, and deleting or expiring a build deletes tags from it, so a request
// may only name a stream its requester owns.

func ownedStream(name, owner string) *imagev1.ImageStream {
	stream := &imagev1.ImageStream{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test-ns"}}
	if owner != "" {
		stream.Annotations = map[string]string{labels.RequestedBy: owner}
	}
	return stream
}

func TestInternalRegistryBuildRequiresStreamOwner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream *imagev1.ImageStream
		want   int // zero when the request should be accepted
	}{
		{name: "new stream"},
		{name: "requester's stream", stream: ownedStream("shared", "alice")},
		{name: "another user's stream", stream: ownedStream("shared", "bob"), want: http.StatusForbidden},
		{name: "unannotated stream", stream: ownedStream("shared", ""), want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{&api.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "test-ns"},
				Spec:       api.OperatorConfigSpec{OSBuilds: &api.OSBuildsConfig{ClusterRegistryRoute: "registry.example.com"}},
			}}
			if tc.stream != nil {
				objs = append(objs, tc.stream)
			}
			k8s := newSealedTestClient(t, interceptor.Funcs{}, objs...)
			server := newTestServer(t, func(deps *apiDependencies) {
				deps.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) { return &rest.Config{}, nil }
				deps.loadOperatorConfig = func(context.Context, client.Client, string) (*api.OperatorConfig, error) {
					return nil, k8serrors.NewNotFound(api.GroupVersion.WithResource("operatorconfigs").GroupResource(), "config")
				}
				deps.createInternalRegistrySecret = func(context.Context, *rest.Config, string, string, int64) (string, error) {
					return "demo-push-auth", nil
				}
			})
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/builds", nil)
			c.Set("requester", "alice")
			req := buildcontract.BuildRequest{Name: "demo-abcde", UseInternalRegistry: true, InternalRegistryImageName: "shared"}

			_, err := server.setupInternalRegistryBuild(t.Context(), c, k8s, "test-ns", &req)
			if tc.want != 0 {
				if err == nil || response.Code != tc.want {
					t.Fatalf("err=%v response: %d %s, want %d", err, response.Code, response.Body, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected: %v %d %s", err, response.Code, response.Body)
			}
			stream := &imagev1.ImageStream{}
			if err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "shared"}, stream); err != nil {
				t.Fatal(err)
			}
			if owner := stream.Annotations[labels.RequestedBy]; owner != "alice" {
				t.Fatalf("stream owner = %q, want alice", owner)
			}
		})
	}
}

func TestContainerBuildRequiresStreamOwner(t *testing.T) {
	k8s := newSealedTestClient(t, interceptor.Funcs{}, ownedStream("shared", "bob"))
	secretCreated := false
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) { return &rest.Config{}, nil }
		deps.createInternalRegistrySecret = func(context.Context, *rest.Config, string, string, int64) (string, error) {
			secretCreated = true
			return "shared-push-auth", nil
		}
	})
	response := postAs(t, "alice", "/v1/container-builds", `{"name":"shared","useInternalRegistry":true}`, server.createContainerBuild)
	if response.Code != http.StatusForbidden {
		t.Fatalf("response: %d %s, want 403", response.Code, response.Body)
	}
	if secretCreated {
		t.Fatal("push Secret created for a request that names another user's stream")
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "shared"}, &api.ContainerBuild{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("ContainerBuild created for another user's stream: %v", err)
	}
}

func TestResealRequiresOutputStreamOwner(t *testing.T) {
	k8s := newSealedTestClient(t, interceptor.Funcs{}, ownedStream("resealed", "bob"))
	body := `{"name":"reseal-demo","inputRef":"quay.io/example/input:v1",` +
		`"outputRef":"` + defaultInternalRegistryURL + `/test-ns/resealed:v1"}`
	if response := postResealAs(t, k8s, "alice", body); response.Code != http.StatusForbidden {
		t.Fatalf("response: %d %s, want 403", response.Code, response.Body)
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "reseal-demo"}, &api.ImageReseal{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("ImageReseal created for another user's stream: %v", err)
	}
}

// A build's stream can be deleted and recreated by another user while the
// build exists, so deleting the build only removes tags from a stream its
// requester still owns.
func TestDeleteBuildOnlyRemovesTagsFromOwnStream(t *testing.T) {
	for _, tc := range []struct {
		streamOwner string
		wantDeleted bool
	}{
		{streamOwner: "alice", wantDeleted: true},
		{streamOwner: "bob"},
	} {
		t.Run(tc.streamOwner, func(t *testing.T) {
			build := &api.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name: "demo", Namespace: "test-ns",
					Annotations: map[string]string{labels.RequestedBy: "alice"},
				},
				Spec: api.ImageBuildSpec{Export: &api.ExportSpec{
					UseServiceAccountAuth: true,
					Disk:                  &api.DiskExport{OCI: defaultInternalRegistryURL + "/test-ns/shared:disk"},
				}},
			}
			tag := &imagev1.ImageStreamTag{ObjectMeta: metav1.ObjectMeta{Name: "shared:disk", Namespace: "test-ns"}}
			k8s := newSealedTestClient(t, interceptor.Funcs{}, build, ownedStream("shared", tc.streamOwner), tag)
			server := newTestServer(t, func(deps *apiDependencies) {
				deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
			})
			response := postAs(t, "alice", "/v1/builds/demo", "", func(c *gin.Context) { server.deleteBuild(c, "demo") })
			if response.Code != http.StatusOK {
				t.Fatalf("response: %d %s", response.Code, response.Body)
			}
			tagErr := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "shared:disk"}, &imagev1.ImageStreamTag{})
			streamErr := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "shared"}, &imagev1.ImageStream{})
			if tc.wantDeleted {
				if !k8serrors.IsNotFound(tagErr) || !k8serrors.IsNotFound(streamErr) {
					t.Fatalf("own tag or emptied stream kept: tag err=%v, stream err=%v", tagErr, streamErr)
				}
				return
			}
			if tagErr != nil || streamErr != nil {
				t.Fatalf("another user's tag or stream deleted: tag err=%v, stream err=%v", tagErr, streamErr)
			}
		})
	}
}
