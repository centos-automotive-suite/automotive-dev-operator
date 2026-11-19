package buildapi

import (
	"net/http"
	"net/http/httptest"
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
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The output ImageStream is left to the imagereseal controller, which claims it
// for the job once the job starts; the API only checks ownership up front.
func TestCreateSealedLeavesOutputStreamToController(t *testing.T) {
	k8s := newSealedTestClient(t)
	if response := postSealed(t, k8s); response.Code/100 != 2 {
		t.Fatalf("response: %d %s", response.Code, response.Body)
	}
	if err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "reseal-demo"}, &api.ImageReseal{}); err != nil {
		t.Fatalf("job not created: %v", err)
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "resealed"}, &imagev1.ImageStream{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("API created the output ImageStream; claiming it is the controller's job: %v", err)
	}
}

func TestCreateSealedDuplicateNameLeavesNoImageStream(t *testing.T) {
	existing := &api.ImageReseal{ObjectMeta: metav1.ObjectMeta{Name: "reseal-demo", Namespace: "test-ns"}}
	k8s := newSealedTestClient(t, existing)
	if response := postSealed(t, k8s); response.Code != http.StatusConflict {
		t.Fatalf("response: %d %s, want 409", response.Code, response.Body)
	}
	err := k8s.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: "resealed"}, &imagev1.ImageStream{})
	if !k8serrors.IsNotFound(err) {
		t.Fatalf("rejected request left an ImageStream behind: %v", err)
	}
}

func newSealedTestClient(t *testing.T, objs ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := imagev1.Install(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
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
