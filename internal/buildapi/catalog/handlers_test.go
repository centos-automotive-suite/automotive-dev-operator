package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/catalogcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/catalogimage"
	"github.com/containers/image/v5/types"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

type publishRegistry struct {
	catalogimage.RegistryClient
	err error
}

func (r publishRegistry) VerifyImageAccessible(context.Context, string, *types.DockerAuthConfig) (bool, error) {
	return r.err == nil, r.err
}

func (r publishRegistry) GetImageMetadata(context.Context, string, *types.DockerAuthConfig) (*automotivev1alpha1.RegistryMetadata, error) {
	return &automotivev1alpha1.RegistryMetadata{BuilderImageResolved: true, SizeBytes: 1024}, nil
}

func TestHandlePublishImageBuild_PreservesProvenance(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name        string
		catalogName string
		registryErr error
	}{
		{name: "verified", catalogName: "published"},
		{name: "registry unavailable", registryErr: fmt.Errorf("temporary registry failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "default"},
				Spec: automotivev1alpha1.ImageBuildSpec{
					Architecture: "aarch64",
					AIB:          &automotivev1alpha1.AIBSpec{Mode: "bootc", Distro: "autosd", Target: "ebbr"},
					Export:       &automotivev1alpha1.ExportSpec{Container: "quay.io/test/image:latest"},
				},
				Status: automotivev1alpha1.ImageBuildStatus{
					Phase:            automotivev1alpha1.ImageBuildPhaseCompleted,
					BuilderImageUsed: "registry.example/default/aib-build@sha256:" + strings.Repeat("a", 64),
				},
			}
			unrelated := &automotivev1alpha1.CatalogImage{
				ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: build.Namespace},
				Spec:       automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/other:latest"},
			}
			c := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(build, unrelated).
				WithStatusSubresource(&automotivev1alpha1.CatalogImage{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						// The API server drops status on creation when the status subresource is enabled.
						obj.(*automotivev1alpha1.CatalogImage).Status = automotivev1alpha1.CatalogImageStatus{}
						return c.Create(ctx, obj, opts...)
					},
				}).Build()
			h := NewHandler(c, logr.Discard(), "default")
			h.publisher = catalogimage.NewPublisher(c, publishRegistry{err: tc.registryErr}, nil, logr.Discard())
			router := gin.New()
			router.POST("/catalog/publish", h.HandlePublishImageBuild)
			body := fmt.Sprintf(`{"imageBuildName":"source","catalogImageName":%q,"tags":["release"]}`, tc.catalogName)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/catalog/publish", strings.NewReader(body)))
			if w.Code != http.StatusCreated {
				t.Fatalf("publish returned %d: %s", w.Code, w.Body.String())
			}
			var response catalogcontract.CatalogImageResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			name := tc.catalogName
			if name == "" {
				name = build.Name
			}
			var entry automotivev1alpha1.CatalogImage
			if err := c.Get(t.Context(), client.ObjectKey{Name: name, Namespace: build.Namespace}, &entry); err != nil {
				t.Fatal(err)
			}
			if entry.Spec.BuilderImage != build.Status.BuilderImageUsed || entry.Status.SourceImageBuild != build.Name {
				t.Fatalf("lost persisted provenance: %+v", entry)
			}
			if entry.Labels[automotivev1alpha1.LabelSourceType] != string(catalogimage.PublishSourceManual) ||
				response.SourceType != string(catalogimage.PublishSourceManual) || response.SourceImageBuild != build.Name {
				t.Fatalf("incorrect manual source: labels=%v response=%+v", entry.Labels, response)
			}
			if entry.Spec.RegistryURL != build.Spec.GetContainerPush() || len(entry.Spec.Tags) != 1 || entry.Spec.Tags[0] != "release" ||
				entry.Spec.Metadata.Architecture != "arm64" || entry.Spec.Metadata.ExportFormat != "oci" || !entry.Spec.Metadata.Bootc {
				t.Fatalf("incorrect published metadata: %+v", entry.Spec)
			}
			if (entry.Status.RegistryMetadata == nil) != (tc.registryErr != nil) {
				t.Fatalf("unexpected registry metadata: %+v", entry.Status.RegistryMetadata)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(unrelated), unrelated); err != nil {
				t.Fatalf("publishing removed an unrelated entry: %v", err)
			}
		})
	}
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

	var resp catalogcontract.CatalogImageResponse
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

	var resp catalogcontract.CatalogImageListResponse
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

func TestHandleListCatalogImages_SortByPublishedAt(t *testing.T) {
	gin.SetMode(gin.TestMode)

	oldCreate := metav1.NewTime(metav1.Now().Add(-48 * time.Hour))
	newerPublish := metav1.NewTime(metav1.Now().Add(-time.Hour))
	olderPublish := metav1.NewTime(metav1.Now().Add(-24 * time.Hour))

	staleCreate := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "published-recently",
			Namespace:         "default",
			CreationTimestamp: oldCreate,
		},
		Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/old-create:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase:       automotivev1alpha1.CatalogImagePhaseAvailable,
			PublishedAt: &newerPublish,
		},
	}
	freshCreate := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "created-later",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-2 * time.Hour)},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/new-create:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase:       automotivev1alpha1.CatalogImagePhaseAvailable,
			PublishedAt: &olderPublish,
		},
	}

	h, _ := newTestHandler(staleCreate, freshCreate)
	router := gin.New()
	router.GET("/catalog/images", h.HandleListCatalogImages)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images?sort=created&latest=false", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp catalogcontract.CatalogImageListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(resp.Items))
	}
	if resp.Items[0].Name != "published-recently" {
		t.Errorf("expected published-recently first (newer publishedAt), got %s", resp.Items[0].Name)
	}
}

func TestHandleListCatalogImages_LatestUsesPublishedAt(t *testing.T) {
	gin.SetMode(gin.TestMode)

	oldCreate := metav1.NewTime(metav1.Now().Add(-48 * time.Hour))
	newerPublish := metav1.NewTime(metav1.Now().Add(-time.Hour))

	olderHead := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "overwritten-head",
			Namespace:         "default",
			CreationTimestamp: oldCreate,
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/head:v2"},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase:       automotivev1alpha1.CatalogImagePhaseAvailable,
			PublishedAt: &newerPublish,
		},
	}
	newerCreate := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "legacy-timestamped",
			Namespace:         "default",
			CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-2 * time.Hour)},
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
			},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/legacy:v1"},
		Status: automotivev1alpha1.CatalogImageStatus{
			Phase: automotivev1alpha1.CatalogImagePhaseAvailable,
		},
	}

	h, _ := newTestHandler(olderHead, newerCreate)
	router := gin.New()
	router.GET("/catalog/images", h.HandleListCatalogImages)

	req := httptest.NewRequest(http.MethodGet, "/catalog/images", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp catalogcontract.CatalogImageListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("expected 1 latest head, got %d: %v", len(resp.Items), namesOf(resp.Items))
	}
	if resp.Items[0].Name != "overwritten-head" {
		t.Errorf("expected overwritten-head (newer publishedAt), got %s", resp.Items[0].Name)
	}
}

func TestToCatalogImageResponse_DigestFallsBackToResolved(t *testing.T) {
	img := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{Name: "img", Namespace: "default"},
		Spec:       automotivev1alpha1.CatalogImageSpec{RegistryURL: "quay.io/test/img:latest"},
		Status: automotivev1alpha1.CatalogImageStatus{
			RegistryMetadata: &automotivev1alpha1.RegistryMetadata{ResolvedDigest: "sha256:from-status"},
		},
	}
	resp := ToCatalogImageResponse(img)
	if resp.Digest != "sha256:from-status" {
		t.Errorf("digest = %q, want resolved digest from status", resp.Digest)
	}

	img.Spec.Digest = "sha256:from-spec"
	resp = ToCatalogImageResponse(img)
	if resp.Digest != "sha256:from-spec" {
		t.Errorf("digest = %q, want spec digest to win", resp.Digest)
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

			var resp catalogcontract.CatalogImageListResponse
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

	var resp catalogcontract.CatalogImageListResponse
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

	var resp catalogcontract.CatalogImageListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items with phase=all&latest=false, got %d: %v", len(resp.Items), namesOf(resp.Items))
	}
}

func namesOf(items []catalogcontract.CatalogImageResponse) []string {
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

	var resp catalogcontract.CatalogImageResponse
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
