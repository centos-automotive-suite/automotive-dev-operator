package buildapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	api "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/gin-gonic/gin"
	imagev1 "github.com/openshift/api/image/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestInternalImageStreamName(t *testing.T) {
	prefix := defaultInternalRegistryURL + "/"
	for _, tc := range []struct{ name, ref, want string }{
		{name: "tag", ref: prefix + "test-ns/resealed:v1", want: "resealed"},
		{name: "digest", ref: prefix + "test-ns/resealed@sha256:" + strings.Repeat("a", 64), want: "resealed"},
		{name: "no tag", ref: prefix + "test-ns/resealed", want: "resealed"},
		{name: "other namespace", ref: prefix + "other-ns/resealed:v1"},
		{name: "external registry", ref: "quay.io/test-ns/resealed:v1"},
		{name: "nested path", ref: prefix + "test-ns/a/b:v1"},
		{name: "empty", ref: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := internalImageStreamName(tc.ref, "test-ns"); got != tc.want {
				t.Fatalf("internalImageStreamName(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// Reseal pods push as ado-build, which may push to existing ImageStreams but
// not create them, so the API creates the output's stream once it accepts the job.
func TestCreateSealedCreatesOutputImageStream(t *testing.T) {
	k8s := newSealedTestClient(t, interceptor.Funcs{})
	if response := postSealed(t, k8s); response.Code/100 != 2 {
		t.Fatalf("response: %d %s", response.Code, response.Body)
	}
	stream := &imagev1.ImageStream{}
	if err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "resealed"}, stream); err != nil {
		t.Fatalf("output ImageStream was not created: %v", err)
	}
}

func TestCreateSealedDuplicateNameLeavesNoImageStream(t *testing.T) {
	existing := &api.ImageReseal{ObjectMeta: metav1.ObjectMeta{Name: "reseal-demo", Namespace: "test-ns"}}
	k8s := newSealedTestClient(t, interceptor.Funcs{}, existing)
	if response := postSealed(t, k8s); response.Code != http.StatusConflict {
		t.Fatalf("response: %d %s, want 409", response.Code, response.Body)
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "resealed"}, &imagev1.ImageStream{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("rejected request left an ImageStream behind: %v", err)
	}
}

// Without its output stream the job could only fail at its final push, so
// the API withdraws it and reports the error instead.
func TestCreateSealedImageStreamFailureRemovesJob(t *testing.T) {
	k8s := newSealedTestClient(t, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetObjectKind().GroupVersionKind().Kind == "ImageStream" {
				return errors.New("imagestream create failed")
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	if response := postSealed(t, k8s); response.Code != http.StatusInternalServerError {
		t.Fatalf("response: %d %s, want 500", response.Code, response.Body)
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "reseal-demo"}, &api.ImageReseal{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("ImageReseal kept after its output stream failed: %v", err)
	}
}

// The transient Secrets hold registry credentials and signing keys. If the
// job is withdrawn and deleting a Secret fails, the Secret must already be
// owned by the job so that garbage collection still removes it.
func TestCreateSealedRollbackLeavesSecretsOwnedByJob(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS or run make test for reseal rollback tests")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	base, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	isStream := func(obj client.Object) bool { return obj.GetObjectKind().GroupVersionKind().Kind == "ImageStream" }
	// envtest has no ImageStream API; act as an OpenShift cluster that refuses the create.
	k8s := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if isStream(obj) {
				return k8serrors.NewNotFound(imagev1.Resource("imagestreams"), key.Name)
			}
			return c.Get(ctx, key, obj, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if isStream(obj) {
				return errors.New("imagestream create failed")
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	failingDeletes := rest.CopyConfig(cfg)
	failingDeletes.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/secrets/") {
				return &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{},
					Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}
			return rt.RoundTrip(r)
		})
	})

	body := `{"name":"reseal-demo","inputRef":"quay.io/example/input:v1",` +
		`"outputRef":"` + defaultInternalRegistryURL + `/default/resealed:v1",` +
		`"registryCredentials":{"enabled":true,"authType":"username-password",` +
		`"registryUrl":"quay.io","username":"user","password":"secret"}}`
	if response := postSealedRequest(t, k8s, failingDeletes, "default", body); response.Code != http.StatusInternalServerError {
		t.Fatalf("response: %d %s, want 500", response.Code, response.Body)
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := cs.CoreV1().Secrets("default").Get(t.Context(), "reseal-demo-registry-auth", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range secret.OwnerReferences {
		if ref.Kind == "ImageReseal" && ref.Name == "reseal-demo" {
			return
		}
	}
	t.Fatalf("Secret left without an owner after its job was withdrawn: %+v", secret.OwnerReferences)
}

func newSealedTestClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := imagev1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

// postSealed submits a reseal to the internal registry; it carries no registry
// or key material, so the handler makes no clientset calls.
func postSealed(t *testing.T, k8s client.Client) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"name":"reseal-demo","inputRef":"quay.io/example/input:v1",` +
		`"outputRef":"` + defaultInternalRegistryURL + `/test-ns/resealed:v1"}`
	return postSealedRequest(t, k8s, &rest.Config{Host: "http://127.0.0.1:1"}, "test-ns", body)
}

func postSealedRequest(t *testing.T, k8s client.Client, cfg *rest.Config, namespace, body string) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("BUILD_API_NAMESPACE", namespace)
	server := newTestServer(t, func(deps *apiDependencies) {
		deps.getClientFromRequest = func(*gin.Context) (client.Client, error) { return k8s, nil }
		deps.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) { return cfg, nil }
	})
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/reseals", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("requester", "user")
	server.createSealed(ctx, buildcontract.SealedOperation("reseal"))
	return response
}
