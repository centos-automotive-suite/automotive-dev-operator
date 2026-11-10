package buildapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// The API reads Secrets as its own ServiceAccount, so a Secret a request names
// must have been created for that requester. Otherwise any user could hand a
// job they control another user's Secret, or the operator's own, such as the
// API's token-signing key.

func ownedSecret(name, owner string) *corev1.Secret {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test-ns"}}
	if owner != "" {
		secret.Annotations = map[string]string{labels.RequestedBy: owner}
	}
	return secret
}

func TestResealKeySecretRefsBoundToRequester(t *testing.T) {
	for _, field := range []string{"keySecretRef", "keyPasswordSecretRef"} {
		for _, tc := range []struct {
			name, owner string
			want        int
		}{
			{name: "requester's secret", owner: "alice", want: http.StatusAccepted},
			{name: "another user's secret", owner: "bob", want: http.StatusForbidden},
			{name: "unannotated secret", want: http.StatusForbidden},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				k8s := newFakeClient(ownedSecret("seal-key", "alice"), ownedSecret("target", tc.owner))
				refs := `"keySecretRef":"seal-key",`
				if field == "keySecretRef" {
					refs = `"keySecretRef":"target",`
				} else {
					refs += `"keyPasswordSecretRef":"target",`
				}
				body := `{"name":"reseal-demo","inputRef":"quay.io/example/input:v1",` + refs +
					`"outputRef":"quay.io/example/output:v1"}`
				response := postResealAs(t, k8s, "alice", body)
				if response.Code != tc.want {
					t.Fatalf("response: %d %s, want %d", response.Code, response.Body, tc.want)
				}
				err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "reseal-demo"}, &api.ImageReseal{})
				if created := err == nil; created != (tc.want == http.StatusAccepted) {
					t.Fatalf("ImageReseal created=%t (err=%v), want %t", created, err, !created)
				}
			})
		}
	}
}

func TestResealMissingKeySecretRejected(t *testing.T) {
	body := `{"name":"reseal-demo","inputRef":"quay.io/example/input:v1","keySecretRef":"missing",` +
		`"outputRef":"quay.io/example/output:v1"}`
	if response := postResealAs(t, newFakeClient(), "alice", body); response.Code != http.StatusForbidden {
		t.Fatalf("response: %d %s, want 403", response.Code, response.Body)
	}
}

func TestS3CredentialsSecretBoundToRequester(t *testing.T) {
	for _, tc := range []struct {
		name, owner string
		ok          bool
	}{
		{name: "requester's secret", owner: "alice", ok: true},
		{name: "another user's secret", owner: "bob"},
		{name: "unannotated secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k8s := newFakeClient(ownedSecret("s3-creds", tc.owner))
			req := &buildcontract.BuildRequest{S3Bucket: "bucket", S3CredentialsSecretName: "s3-creds"}
			httpErr := checkS3Credentials(context.Background(), k8s, req, "test-ns", "alice")
			if (httpErr == nil) != tc.ok {
				t.Fatalf("checkS3Credentials() = %+v, want ok=%t", httpErr, tc.ok)
			}
			if !tc.ok && httpErr.code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", httpErr.code)
			}
		})
	}
}

// A rejected S3 Secret must stop the build before its registry and flash
// Secrets are created, or they are left behind.
func TestBuildS3SecretRejectedBeforeOtherSecrets(t *testing.T) {
	k8s := newFakeClient(ownedSecret("s3-creds", "bob"))
	body := `{"name":"demo","manifest":"name: test","s3Bucket":"bucket","s3CredentialsSecretName":"s3-creds",` +
		`"registryCredentials":{"enabled":true,"authType":"username-password","registryUrl":"quay.io","username":"u","password":"p"},` +
		`"exportOci":"quay.io/example/demo:v1","flashEnabled":true,"flashClientConfig":"YQ=="}`
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.loadOperatorConfig = func(context.Context, client.Client, string) (*api.OperatorConfig, error) {
			return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "operatorconfigs"}, "config")
		}
	})
	if response := postAs(t, "alice", "/v1/builds", body, server.createBuild); response.Code != http.StatusForbidden {
		t.Fatalf("response: %d %s, want 403", response.Code, response.Body)
	}
	secrets := &corev1.SecretList{}
	if err := k8s.List(t.Context(), secrets, client.InNamespace("test-ns")); err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets.Items {
		if secret.Name != "s3-creds" {
			t.Errorf("Secret %s left behind by a rejected build", secret.Name)
		}
	}
}

// A workspace named after another user's flashing build must not pick up that
// build's Jumpstarter client Secret (<name>-jumpstarter-client).
func TestWorkspaceDoesNotAdoptExistingClientSecret(t *testing.T) {
	victim := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-jumpstarter-client", Namespace: "test-ns"},
		Data:       map[string][]byte{"client.yaml": []byte("victim")},
	}
	k8s := newFakeClient(victim)
	body := `{"name":"demo","clientConfig":"` + "YXR0YWNrZXI=" + `"}` // "attacker"
	response := postWorkspaceAs(t, k8s, "mallory", body)
	if response.Code != http.StatusConflict {
		t.Fatalf("response: %d %s, want 409", response.Code, response.Body)
	}
	if err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "demo"}, &api.Workspace{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("workspace created over another user's client Secret: %v", err)
	}
}

// Until the API creates a workspace's own client Secret, its name can belong
// to another user's flashing build, so deleting the workspace must not delete
// a Secret by name. Garbage collection removes the Secret the workspace owns.
func TestWorkspaceDeleteLeavesSecretItDoesNotOwn(t *testing.T) {
	ws := &api.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "test-ns"},
		Spec:       api.WorkspaceSpec{Owner: "mallory", ClientConfigSecretRef: "demo-jumpstarter-client"},
	}
	k8s := newFakeClient(ws, ownedSecret("demo-jumpstarter-client", ""))
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
	})
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/v1/workspaces/demo", nil)
	ctx.Set("requester", "mallory")
	server.deleteWorkspace(ctx, "demo")

	if response.Code != http.StatusOK {
		t.Fatalf("response: %d %s, want 200", response.Code, response.Body)
	}
	if err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "demo-jumpstarter-client"}, &corev1.Secret{}); err != nil {
		t.Fatalf("deleting the workspace removed a Secret it does not own: %v", err)
	}
}

// A rejected request must not leave a client Secret behind, or every retry
// with the same name would conflict.
func TestWorkspaceFailureRemovesClientSecret(t *testing.T) {
	k8s := newFakeClient()
	// tmpfs needs OperatorConfig to allow it, so this request is rejected.
	body := `{"name":"demo","clientConfig":"YQ==","tmpfsBuildDir":true}`
	if response := postWorkspaceAs(t, k8s, "alice", body); response.Code != http.StatusBadRequest {
		t.Fatalf("response: %d %s, want 400", response.Code, response.Body)
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "demo-jumpstarter-client"}, &corev1.Secret{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("client Secret left behind after a rejected request: %v", err)
	}
}

func TestWorkspaceClientSecretOwnedByWorkspace(t *testing.T) {
	k8s := newFakeClient()
	if response := postWorkspaceAs(t, k8s, "alice", `{"name":"demo","clientConfig":"YQ=="}`); response.Code != http.StatusCreated {
		t.Fatalf("response: %d %s, want 201", response.Code, response.Body)
	}
	secret := &corev1.Secret{}
	if err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "demo-jumpstarter-client"}, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["client.yaml"]) != "a" {
		t.Fatalf("client.yaml = %q, want %q", secret.Data["client.yaml"], "a")
	}
	refs := secret.OwnerReferences
	if len(refs) != 1 || refs[0].Kind != "Workspace" || refs[0].Name != "demo" || refs[0].Controller == nil || !*refs[0].Controller {
		t.Fatalf("owner references = %+v, want the demo Workspace as controller", refs)
	}
}

// The client goes away while the Secret is being created. The Workspace must
// still be removed, or it would hold the name with no client config.
func TestWorkspaceClientSecretFailureRemovesWorkspace(t *testing.T) {
	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				cancel()
				return context.Canceled
			}
			return c.Create(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.loadOperatorConfig = func(context.Context, client.Client, string) (*api.OperatorConfig, error) {
			return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "operatorconfigs"}, "config")
		}
	})
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequestWithContext(reqCtx, http.MethodPost, "/v1/workspaces", strings.NewReader(`{"name":"demo","clientConfig":"YQ=="}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("requester", "alice")
	server.createWorkspace(ctx)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("response: %d %s, want 500", response.Code, response.Body)
	}
	if err := k8s.Get(context.Background(), types.NamespacedName{Namespace: "test-ns", Name: "demo"}, &api.Workspace{}); !k8serrors.IsNotFound(err) {
		t.Fatalf("Workspace left without its client config Secret: %v", err)
	}
}

// The Workspace can be deleted and its name taken again while the Secret is
// being created. Cleaning up after the Secret fails must not delete the
// replacement.
func TestWorkspaceClientSecretFailureSparesReplacement(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	key := types.NamespacedName{Namespace: "test-ns", Name: "demo"}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			switch obj.(type) {
			case *api.Workspace:
				obj.SetUID("original")
			case *corev1.Secret:
				if err := c.Delete(ctx, &api.Workspace{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}); err != nil {
					return err
				}
				replacement := &api.Workspace{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "replacement"}}
				if err := c.Create(ctx, replacement); err != nil {
					return err
				}
				return errors.New("secret create failed")
			}
			return c.Create(ctx, obj, opts...)
		},
		// The fake client ignores UID preconditions, so enforce them here as
		// the API server does.
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			options := (&client.DeleteOptions{}).ApplyOptions(opts)
			if options.Preconditions != nil && options.Preconditions.UID != nil {
				current := &api.Workspace{}
				if err := c.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
					return err
				}
				if current.UID != *options.Preconditions.UID {
					return k8serrors.NewConflict(schema.GroupResource{Resource: "workspaces"}, obj.GetName(), errors.New("UID precondition failed"))
				}
			}
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()

	if response := postWorkspaceAs(t, k8s, "alice", `{"name":"demo","clientConfig":"YQ=="}`); response.Code != http.StatusInternalServerError {
		t.Fatalf("response: %d %s, want 500", response.Code, response.Body)
	}
	ws := &api.Workspace{}
	if err := k8s.Get(t.Context(), key, ws); err != nil || ws.UID != "replacement" {
		t.Fatalf("replacement Workspace deleted by the failed request's cleanup: uid=%q err=%v", ws.UID, err)
	}
}

func postResealAs(t *testing.T, k8s client.Client, requester, body string) *httptest.ResponseRecorder {
	t.Helper()
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) {
			return &rest.Config{Host: "http://127.0.0.1:1"}, nil
		}
	})
	return postAs(t, requester, "/v1/reseals", body, func(c *gin.Context) {
		server.createSealed(c, buildcontract.SealedReseal)
	})
}

func postWorkspaceAs(t *testing.T, k8s client.Client, requester, body string) *httptest.ResponseRecorder {
	t.Helper()
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.loadOperatorConfig = func(context.Context, client.Client, string) (*api.OperatorConfig, error) {
			return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "operatorconfigs"}, "config")
		}
	})
	return postAs(t, requester, "/v1/workspaces", body, server.createWorkspace)
}

func postAs(t *testing.T, requester, path, body string, handle gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("BUILD_API_NAMESPACE", "test-ns")
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("requester", requester)
	handle(ctx)
	return response
}
