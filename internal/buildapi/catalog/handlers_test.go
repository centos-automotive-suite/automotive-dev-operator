package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(automotivev1alpha1.AddToScheme(s))
	return s
}

func newTestHandler(objs ...client.Object) (*Handler, client.Client) {
	scheme := newTestScheme()
	builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&automotivev1alpha1.CatalogImage{})
	c := builder.Build()
	h := NewHandler(c, logr.Discard(), "default")
	return h, c
}

func TestHandleGetCatalogImage_DoesNotWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)

	img := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-image",
			Namespace: "default",
		},
		Spec: automotivev1alpha1.CatalogImageSpec{
			RegistryURL: "quay.io/test/image:latest",
		},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase:       automotivev1alpha1.CatalogImagePhaseAvailable,
			AccessCount: 5,
		},
	}

	h, c := newTestHandler(img)

	router := gin.New()
	router.GET("/catalog/images/:name", h.HandleGetCatalogImage)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images/test-image?namespace=default", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CatalogImageResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Name != "test-image" {
		t.Errorf("expected name test-image, got %s", resp.Name)
	}

	// Verify the object was NOT modified (AccessCount unchanged)
	var after automotivev1alpha1.CatalogImage
	if err := c.Get(t.Context(), client.ObjectKey{Name: "test-image", Namespace: "default"}, &after); err != nil {
		t.Fatalf("failed to get catalog image: %v", err)
	}
	if after.Status.AccessCount != 5 {
		t.Errorf("AccessCount changed from 5 to %d — GET should not write", after.Status.AccessCount)
	}
}

func TestHandleGetCatalogImage_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h, _ := newTestHandler()

	router := gin.New()
	router.GET("/catalog/images/:name", h.HandleGetCatalogImage)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images/nonexistent?namespace=default", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
