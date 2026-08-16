package catalog

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

	req := httptest.NewRequest(http.MethodGet, "/catalog/images/test-image", nil)
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

func TestHandleListCatalogImages_SortByCreated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	older := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "img-older",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-2 * 24 * time.Hour)},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/older:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase: automotivev1alpha1.CatalogImagePhaseAvailable,
		},
	}
	newer := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "img-newer",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Time},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/newer:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase: automotivev1alpha1.CatalogImagePhaseAvailable,
		},
	}

	h, _ := newTestHandler(older, newer)

	router := gin.New()
	router.GET("/catalog/images", h.HandleListCatalogImages)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images?sort=created", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CatalogImageListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(resp.Items))
	}
	if resp.Items[0].Name != "img-newer" {
		t.Errorf("expected newest first, got %s", resp.Items[0].Name)
	}
}

func TestHandleListCatalogImages_Latest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		sort      string
		olderName string
		newerName string
		schedule  string
		wantName  string
	}{
		{
			name:      "sort=created picks newest",
			sort:      "created",
			olderName: "sched-old",
			newerName: "sched-fresh",
			schedule:  "nightly-qemu",
			wantName:  "sched-fresh",
		},
		{
			name:      "sort=name still picks newest by creation time",
			sort:      "name",
			olderName: "aaa-older",
			newerName: "zzz-newer",
			schedule:  "nightly",
			wantName:  "zzz-newer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			older := &automotivev1alpha1.CatalogImage{
				ObjectMeta: metav1.ObjectMeta{
					Name:              tt.olderName,
					Namespace:         "default",
					CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-24 * time.Hour)},
					Labels: map[string]string{
						automotivev1alpha1.LabelScheduledImageBuildName: tt.schedule,
					},
				},
				Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/older:v1"},
				Status: automotivev1alpha1.CatalogImageStatus{
					Phase: automotivev1alpha1.CatalogImagePhaseAvailable,
				},
			}
			newer := &automotivev1alpha1.CatalogImage{
				ObjectMeta: metav1.ObjectMeta{
					Name:              tt.newerName,
					Namespace:         "default",
					CreationTimestamp: metav1.Time{Time: metav1.Now().Time},
					Labels: map[string]string{
						automotivev1alpha1.LabelScheduledImageBuildName: tt.schedule,
					},
				},
				Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/newer:v1"},
				Status: automotivev1alpha1.CatalogImageStatus{
					Phase: automotivev1alpha1.CatalogImagePhaseAvailable,
				},
			}

			h, _ := newTestHandler(older, newer)
			router := gin.New()
			router.GET("/catalog/images", h.HandleListCatalogImages)

			url := fmt.Sprintf("/catalog/images?latest=true&sort=%s", tt.sort)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}

			var resp CatalogImageListResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(resp.Items) != 1 {
				t.Fatalf("expected 1 item (latest per schedule), got %d", len(resp.Items))
			}
			if resp.Items[0].Name != tt.wantName {
				t.Errorf("expected %s, got %s", tt.wantName, resp.Items[0].Name)
			}
		})
	}
}

func TestHandleListCatalogImages_DefaultAvailableLatest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	pending := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pending-head",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Time},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec:   automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/pending:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhasePending},
	}
	olderAvailable := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "older-available",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-48 * time.Hour)},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec:   automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/older:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhaseAvailable},
	}
	newerAvailable := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "newer-available",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-24 * time.Hour)},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec:   automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/newer:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhaseAvailable},
	}
	otherSchedule := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "other-schedule",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-12 * time.Hour)},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-ebbr",
			},
		},
		Spec:   automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/ebbr:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhaseAvailable},
	}

	h, _ := newTestHandler(pending, olderAvailable, newerAvailable, otherSchedule)
	router := gin.New()
	router.GET("/catalog/images", h.HandleListCatalogImages)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CatalogImageListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 Available heads, got %d: %+v", len(resp.Items), namesOf(resp.Items))
	}
	got := map[string]bool{}
	for _, item := range resp.Items {
		got[item.Name] = true
		if item.Phase != string(automotivev1alpha1.CatalogImagePhaseAvailable) {
			t.Errorf("expected Available, got %s for %s", item.Phase, item.Name)
		}
	}
	if !got["newer-available"] || !got["other-schedule"] {
		t.Errorf("expected newer-available and other-schedule, got %v", namesOf(resp.Items))
	}
	if got["pending-head"] || got["older-available"] {
		t.Errorf("default list should omit pending and superseded heads, got %v", namesOf(resp.Items))
	}
}

func TestHandleListCatalogImages_PhaseAllLatestFalse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	pending := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pending-head",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Time},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec:   automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/pending:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhasePending},
	}
	available := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "available-head",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-24 * time.Hour)},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec:   automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/available:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{Phase: automotivev1alpha1.CatalogImagePhaseAvailable},
	}

	h, _ := newTestHandler(pending, available)
	router := gin.New()
	router.GET("/catalog/images", h.HandleListCatalogImages)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images?phase=all&latest=false", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CatalogImageListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items with phase=all&latest=false, got %d: %v", len(resp.Items), namesOf(resp.Items))
	}
}

func namesOf(items []CatalogImageResponse) []string {
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.Name
	}
	return names
}

func TestLatestGroupKey(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			name: "scheduled image groups by schedule name",
			labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
			want: "schedule:nightly-qemu",
		},
		{
			name: "non-scheduled groups by distro/arch/target",
			labels: map[string]string{
				automotivev1alpha1.LabelDistro:       "autosd",
				automotivev1alpha1.LabelArchitecture: "x86_64",
				automotivev1alpha1.LabelTarget:       "qemu",
			},
			want: "autosd/x86_64/qemu",
		},
		{
			name:   "empty labels produce unique per-image key",
			labels: map[string]string{},
			want:   "name:test-img",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := &automotivev1alpha1.CatalogImage{
				ObjectMeta: metav1.ObjectMeta{Name: "test-img", Labels: tt.labels},
			}
			got := latestGroupKey(img)
			if got != tt.want {
				t.Errorf("latestGroupKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScheduleNameInResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	img := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nightly-qemu-abc123",
			Namespace: "default",
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
				automotivev1alpha1.LabelSourceType:              "Scheduled",
			},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{
			RegistryURL: "quay.io/test/image:latest",
		},
	}

	h, _ := newTestHandler(img)

	router := gin.New()
	router.GET("/catalog/images/:name", h.HandleGetCatalogImage)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images/nightly-qemu-abc123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CatalogImageResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ScheduleName != "nightly-qemu" {
		t.Errorf("expected scheduleName %q, got %q", "nightly-qemu", resp.ScheduleName)
	}
	if resp.SourceType != "Scheduled" {
		t.Errorf("expected sourceType %q, got %q", "Scheduled", resp.SourceType)
	}
}

func TestHandleGetCatalogImage_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h, _ := newTestHandler()

	router := gin.New()
	router.GET("/catalog/images/:name", h.HandleGetCatalogImage)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
