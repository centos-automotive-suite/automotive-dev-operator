package buildapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

var _ = Describe("APIServer", func() {
	var (
		server *APIServer
		logger logr.Logger
	)

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		logger = logr.Discard()
		server = NewAPIServer(":0", logger)
	})

	AfterEach(func() {
		server = nil
	})

	Context("Server Creation", func() {
		It("should create a valid API server", func() {
			Expect(server).NotTo(BeNil())
			Expect(server.router).NotTo(BeNil())
			Expect(server.server).NotTo(BeNil())
			Expect(server.addr).To(Equal(":0"))
			Expect(server.log).To(Equal(logger))
		})
	})

	Context("Health Endpoint", func() {
		It("should return 200 OK for health check", func() {
			req, err := http.NewRequest("GET", "/v1/healthz", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Body.String()).To(Equal("ok"))
		})
	})

	Context("OpenAPI Endpoint", func() {
		It("should return OpenAPI spec", func() {
			req, err := http.NewRequest("GET", "/v1/openapi.yaml", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Header().Get("Content-Type")).To(Equal("application/yaml"))
			Expect(w.Body.String()).NotTo(BeEmpty())
		})
	})

	Context("Builds Endpoints Authentication", func() {
		var testCases = []struct {
			method string
			path   string
		}{
			{"GET", "/v1/builds"},
			{"POST", "/v1/builds"},
			{"GET", "/v1/builds/test-build"},
			{"GET", "/v1/builds/test-build/logs"},
			{"GET", "/v1/builds/test-build/template"},
			{"POST", "/v1/builds/test-build/uploads"},
			{"POST", "/v1/builds/test-build/cancel"},
			{"DELETE", "/v1/builds/test-build"},
		}

		It("should require authentication for all builds endpoints", func() {
			for _, tc := range testCases {
				By(fmt.Sprintf("testing %s %s", tc.method, tc.path))

				req, err := http.NewRequest(tc.method, tc.path, nil)
				Expect(err).NotTo(HaveOccurred())

				w := httptest.NewRecorder()
				server.router.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			}
		})
	})

	Context("createBuild S3 validation", func() {
		var (
			originalGetClientFromRequestFn func(*gin.Context) (ctrlclient.Client, error)
			originalLoadOperatorConfigFn   func(context.Context, ctrlclient.Client, string) (*automotivev1alpha1.OperatorConfig, error)
			originalNamespace              string
			hasOriginalNamespace           bool
		)

		BeforeEach(func() {
			originalGetClientFromRequestFn = getClientFromRequestFn
			originalLoadOperatorConfigFn = loadOperatorConfigFn
			originalNamespace, hasOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
			Expect(os.Setenv("BUILD_API_NAMESPACE", "test-ns")).To(Succeed())
			loadOperatorConfigFn = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return nil, k8serrors.NewNotFound(schema.GroupResource{}, "config")
			}
		})

		AfterEach(func() {
			getClientFromRequestFn = originalGetClientFromRequestFn
			loadOperatorConfigFn = originalLoadOperatorConfigFn
			if hasOriginalNamespace {
				Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
			} else {
				Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
			}
		})

		newCreateBuildFakeClient := func(objs ...ctrlclient.Object) ctrlclient.Client {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for _, obj := range objs {
				builder = builder.WithObjects(obj)
			}
			return builder.Build()
		}

		It("should return 400 when both s3Credentials and s3CredentialsSecretName are set", func() {
			fakeClient := newCreateBuildFakeClient()
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			body := `{
				"name": "test-build",
				"manifest": "name: test",
				"s3Bucket": "my-bucket",
				"s3Credentials": {"accessKeyId": "AKIA...", "secretAccessKey": "secret"},
				"s3CredentialsSecretName": "existing-secret"
			}`

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")

			server.createBuild(c)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
			Expect(w.Body.String()).To(ContainSubstring("cannot specify both"))
		})

		It("should accept s3Bucket without credentials for IAM-based auth", func() {
			fakeClient := newCreateBuildFakeClient()
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			body := `{
				"name": "test-build",
				"manifest": "name: test",
				"s3Bucket": "my-bucket"
			}`

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")

			server.createBuild(c)

			Expect(w.Code).To(Equal(http.StatusAccepted))
		})

		It("should clean up inline S3 secret when ImageBuild creation fails", func() {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(corev1.AddToScheme(scheme)).To(Succeed())

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithInterceptorFuncs(interceptor.Funcs{
					Create: func(ctx context.Context, c ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
						if _, ok := obj.(*automotivev1alpha1.ImageBuild); ok {
							return fmt.Errorf("simulated ImageBuild creation failure")
						}
						return c.Create(ctx, obj, opts...)
					},
				}).
				Build()

			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			body := `{
				"name": "test-build",
				"manifest": "name: test",
				"s3Bucket": "my-bucket",
				"s3Credentials": {"accessKeyId": "AKIA_TEST", "secretAccessKey": "secret_test"}
			}`

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")

			server.createBuild(c)

			Expect(w.Code).To(Equal(http.StatusInternalServerError))

			// Verify the generated S3 secret was cleaned up
			secretList := &corev1.SecretList{}
			Expect(fakeClient.List(context.Background(), secretList)).To(Succeed())
			for _, s := range secretList.Items {
				Expect(s.Labels).NotTo(HaveKeyWithValue(labels.ResourceType, "s3-auth"),
					"inline S3 secret should have been deleted after ImageBuild creation failure")
			}
		})

		It("should create ImageBuild with insecureSkipTLSVerify set to true", func() {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			body := `{
				"name": "test-tls-build",
				"manifest": "name: test",
				"s3Bucket": "my-bucket",
				"s3Endpoint": "https://minio.example.com",
				"s3InsecureSkipTLSVerify": true,
				"s3Credentials": {"accessKeyId": "AKIA", "secretAccessKey": "secret"}
			}`

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")

			server.createBuild(c)

			Expect(w.Code).To(Equal(http.StatusAccepted))

			// Verify the created ImageBuild has insecureSkipTLSVerify set
			buildList := &automotivev1alpha1.ImageBuildList{}
			Expect(fakeClient.List(context.Background(), buildList)).To(Succeed())
			Expect(buildList.Items).To(HaveLen(1))
			created := buildList.Items[0]
			Expect(created.Spec.Export.Disk.S3).NotTo(BeNil())
			Expect(created.Spec.Export.Disk.S3.InsecureSkipTLSVerify).To(BeTrue())
			Expect(created.Spec.Export.Disk.S3.Endpoint).To(Equal("https://minio.example.com"))
		})

		It("should create ImageBuild with insecureSkipTLSVerify defaulting to false", func() {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			body := `{
				"name": "test-tls-default",
				"manifest": "name: test",
				"s3Bucket": "my-bucket",
				"s3Credentials": {"accessKeyId": "AKIA", "secretAccessKey": "secret"}
			}`

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds", strings.NewReader(body))
			c.Request.Header.Set("Content-Type", "application/json")

			server.createBuild(c)

			Expect(w.Code).To(Equal(http.StatusAccepted))

			buildList := &automotivev1alpha1.ImageBuildList{}
			Expect(fakeClient.List(context.Background(), buildList)).To(Succeed())
			Expect(buildList.Items).To(HaveLen(1))
			created := buildList.Items[0]
			Expect(created.Spec.Export.Disk.S3).NotTo(BeNil())
			Expect(created.Spec.Export.Disk.S3.InsecureSkipTLSVerify).To(BeFalse())
		})
	})

	Context("Delete Build", func() {
		var (
			originalGetClientFromRequestFn func(*gin.Context) (ctrlclient.Client, error)
			originalNamespace              string
			hasOriginalNamespace           bool
		)

		BeforeEach(func() {
			originalGetClientFromRequestFn = getClientFromRequestFn
			originalNamespace, hasOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
			Expect(os.Setenv("BUILD_API_NAMESPACE", "test-ns")).To(Succeed())
		})

		AfterEach(func() {
			getClientFromRequestFn = originalGetClientFromRequestFn
			if hasOriginalNamespace {
				Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
			} else {
				Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
			}
		})

		newTestBuild := func(name, owner string, useServiceAccountAuth bool, containerPush, exportOCI string) *automotivev1alpha1.ImageBuild {
			build := &automotivev1alpha1.ImageBuild{}
			build.Name = name
			build.Namespace = "test-ns"
			build.Annotations = map[string]string{
				labels.RequestedBy: owner,
			}
			if useServiceAccountAuth || containerPush != "" || exportOCI != "" {
				build.Spec.Export = &automotivev1alpha1.ExportSpec{
					UseServiceAccountAuth: useServiceAccountAuth,
					Container:             containerPush,
				}
				if exportOCI != "" {
					build.Spec.Export.Disk = &automotivev1alpha1.DiskExport{OCI: exportOCI}
				}
			}
			return build
		}

		newFakeClient := func(objs ...ctrlclient.Object) ctrlclient.Client {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for _, obj := range objs {
				builder = builder.WithObjects(obj)
			}
			return builder.Build()
		}

		It("should return 404 when build does not exist", func() {
			fakeClient := newFakeClient()
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodDelete, "/v1/builds/nonexistent", nil)
			c.Set("requester", "alice")

			server.deleteBuild(c, "nonexistent")

			Expect(w.Code).To(Equal(http.StatusNotFound))
			Expect(w.Body.String()).To(ContainSubstring("build not found"))
		})

		It("should return 403 when user does not own the build", func() {
			build := newTestBuild("my-build", "alice", false, "", "")
			fakeClient := newFakeClient(build)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodDelete, "/v1/builds/my-build", nil)
			c.Set("requester", "bob")

			server.deleteBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusForbidden))
			Expect(w.Body.String()).To(ContainSubstring("you can only delete your own builds"))
		})

		It("should delete a build owned by the requester", func() {
			build := newTestBuild("my-build", "alice", false, "", "")
			fakeClient := newFakeClient(build)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodDelete, "/v1/builds/my-build", nil)
			c.Set("requester", "alice")

			server.deleteBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusOK))
			var resp map[string]string
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["message"]).To(ContainSubstring("my-build"))
			Expect(resp["message"]).To(ContainSubstring("deleted"))

			// Verify build was actually deleted
			err := fakeClient.Get(context.Background(), types.NamespacedName{
				Name: "my-build", Namespace: "test-ns",
			}, &automotivev1alpha1.ImageBuild{})
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())
		})

		It("should delete ImageStreamTags and empty ImageStream when build used internal registry", func() {
			containerPush := defaultInternalRegistryURL + "/test-ns/my-ir-build:bootc"
			build := newTestBuild("my-ir-build", "alice", true, containerPush, "")

			// Pre-create ImageStream (with no status tags — simulates empty after tag deletion)
			is := &unstructured.Unstructured{}
			is.SetGroupVersionKind(schema.GroupVersionKind{
				Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
			})
			is.SetName("my-ir-build")
			is.SetNamespace("test-ns")

			// Pre-create ImageStreamTag
			ist := &unstructured.Unstructured{}
			ist.SetGroupVersionKind(schema.GroupVersionKind{
				Group: "image.openshift.io", Version: "v1", Kind: "ImageStreamTag",
			})
			ist.SetName("my-ir-build:bootc")
			ist.SetNamespace("test-ns")

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			for _, gvk := range []schema.GroupVersionKind{
				{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"},
				{Group: "image.openshift.io", Version: "v1", Kind: "ImageStreamList"},
				{Group: "image.openshift.io", Version: "v1", Kind: "ImageStreamTag"},
				{Group: "image.openshift.io", Version: "v1", Kind: "ImageStreamTagList"},
			} {
				if gvk.Kind == "ImageStreamList" || gvk.Kind == "ImageStreamTagList" {
					scheme.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
				} else {
					scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
				}
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(build, is, ist).
				Build()

			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodDelete, "/v1/builds/my-ir-build", nil)
			c.Set("requester", "alice")

			server.deleteBuild(c, "my-ir-build")

			Expect(w.Code).To(Equal(http.StatusOK))

			// Verify ImageStreamTag was deleted
			istCheck := &unstructured.Unstructured{}
			istCheck.SetGroupVersionKind(schema.GroupVersionKind{
				Group: "image.openshift.io", Version: "v1", Kind: "ImageStreamTag",
			})
			err := fakeClient.Get(context.Background(), types.NamespacedName{
				Name: "my-ir-build:bootc", Namespace: "test-ns",
			}, istCheck)
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())

			// Verify empty ImageStream was also deleted
			isCheck := &unstructured.Unstructured{}
			isCheck.SetGroupVersionKind(schema.GroupVersionKind{
				Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
			})
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Name: "my-ir-build", Namespace: "test-ns",
			}, isCheck)
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("Cancel Build", func() {
		var (
			originalGetClientFromRequestFn func(*gin.Context) (ctrlclient.Client, error)
			originalNamespace              string
			hasOriginalNamespace           bool
		)

		BeforeEach(func() {
			originalGetClientFromRequestFn = getClientFromRequestFn
			originalNamespace, hasOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
			Expect(os.Setenv("BUILD_API_NAMESPACE", "test-ns")).To(Succeed())
		})

		AfterEach(func() {
			getClientFromRequestFn = originalGetClientFromRequestFn
			if hasOriginalNamespace {
				Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
			} else {
				Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
			}
		})

		newCancelTestBuild := func(phase, pipelineRunName string) *automotivev1alpha1.ImageBuild {
			build := &automotivev1alpha1.ImageBuild{}
			build.Name = "my-build"
			build.Namespace = testNamespace
			build.Annotations = map[string]string{
				labels.RequestedBy: "alice",
			}
			build.Status.Phase = phase
			build.Status.PipelineRunName = pipelineRunName
			return build
		}

		newCancelFakeClient := func(objs ...ctrlclient.Object) ctrlclient.Client {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(tektonv1.AddToScheme(scheme)).To(Succeed())
			return fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objs...).
				WithStatusSubresource(&automotivev1alpha1.ImageBuild{}).
				Build()
		}

		It("should return 404 when build does not exist", func() {
			fakeClient := newCancelFakeClient()
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/nonexistent/cancel", nil)
			c.Set("requester", "alice")

			server.cancelBuild(c, "nonexistent")

			Expect(w.Code).To(Equal(http.StatusNotFound))
			Expect(w.Body.String()).To(ContainSubstring("build not found"))
		})

		It("should return 403 when user does not own the build", func() {
			build := newCancelTestBuild("Building", "")
			fakeClient := newCancelFakeClient(build)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/my-build/cancel", nil)
			c.Set("requester", "bob")

			server.cancelBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusForbidden))
			Expect(w.Body.String()).To(ContainSubstring("you can only cancel your own builds"))
		})

		It("should return 409 when build is already completed", func() {
			build := newCancelTestBuild("Completed", "")
			fakeClient := newCancelFakeClient(build)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/my-build/cancel", nil)
			c.Set("requester", "alice")

			server.cancelBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusConflict))
			Expect(w.Body.String()).To(ContainSubstring("cannot be cancelled"))
		})

		It("should return 409 when build has already failed", func() {
			build := newCancelTestBuild("Failed", "")
			fakeClient := newCancelFakeClient(build)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/my-build/cancel", nil)
			c.Set("requester", "alice")

			server.cancelBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusConflict))
			Expect(w.Body.String()).To(ContainSubstring("cannot be cancelled"))
		})

		It("should cancel a pending build without a PipelineRun", func() {
			build := newCancelTestBuild("Pending", "")
			fakeClient := newCancelFakeClient(build)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/my-build/cancel", nil)
			c.Set("requester", "alice")

			server.cancelBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusOK))
			var resp map[string]string
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["message"]).To(ContainSubstring("cancelled"))

			// Verify ImageBuild status was updated
			updated := &automotivev1alpha1.ImageBuild{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{
				Name: "my-build", Namespace: testNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Cancelled"))
			Expect(updated.Status.Message).To(Equal("Build cancelled by user"))
			Expect(updated.Status.CompletionTime).NotTo(BeNil())
		})

		It("should return 409 when PipelineRun already completed", func() {
			build := newCancelTestBuild("Building", "my-build-pr")
			completionTime := metav1.Now()
			pipelineRun := &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-build-pr",
					Namespace: testNamespace,
				},
				Status: tektonv1.PipelineRunStatus{
					PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
						CompletionTime: &completionTime,
					},
				},
			}
			fakeClient := newCancelFakeClient(build, pipelineRun)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/my-build/cancel", nil)
			c.Set("requester", "alice")

			server.cancelBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusConflict))
			Expect(w.Body.String()).To(ContainSubstring("already completed"))
		})

		It("should cancel a building build and patch its PipelineRun", func() {
			build := newCancelTestBuild("Building", "my-build-pr")
			pipelineRun := &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-build-pr",
					Namespace: testNamespace,
				},
			}
			fakeClient := newCancelFakeClient(build, pipelineRun)
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/v1/builds/my-build/cancel", nil)
			c.Set("requester", "alice")

			server.cancelBuild(c, "my-build")

			Expect(w.Code).To(Equal(http.StatusOK))

			// Verify PipelineRun was patched with Cancelled status
			updatedPR := &tektonv1.PipelineRun{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{
				Name: "my-build-pr", Namespace: testNamespace,
			}, updatedPR)).To(Succeed())
			Expect(string(updatedPR.Spec.Status)).To(Equal("Cancelled"))

			// Verify ImageBuild status was updated
			updated := &automotivev1alpha1.ImageBuild{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{
				Name: "my-build", Namespace: testNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Cancelled"))
			Expect(updated.Status.CompletionTime).NotTo(BeNil())
		})
	})

	Context("OperatorConfig Endpoint", func() {
		var (
			originalGetClientFromRequestFn func(*gin.Context) (ctrlclient.Client, error)
			originalLoadOperatorConfigFn   func(context.Context, ctrlclient.Client, string) (*automotivev1alpha1.OperatorConfig, error)
			originalLoadTargetDefaultsFn   func(context.Context, ctrlclient.Client, string) (map[string]TargetDefaults, error)
			originalNamespace              string
			hasOriginalNamespace           bool
		)

		BeforeEach(func() {
			originalGetClientFromRequestFn = getClientFromRequestFn
			originalLoadOperatorConfigFn = loadOperatorConfigFn
			originalLoadTargetDefaultsFn = loadTargetDefaultsFn
			originalNamespace, hasOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
			Expect(os.Setenv("BUILD_API_NAMESPACE", "default")).To(Succeed())
		})

		AfterEach(func() {
			getClientFromRequestFn = originalGetClientFromRequestFn
			loadOperatorConfigFn = originalLoadOperatorConfigFn
			loadTargetDefaultsFn = originalLoadTargetDefaultsFn
			if hasOriginalNamespace {
				Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
			} else {
				Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
			}
		})

		It("should return default AIB image when config resource is not found", func() {
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return nil, nil
			}
			loadOperatorConfigFn = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return nil, k8serrors.NewNotFound(
					schema.GroupResource{
						Group:    "automotive.sdv.cloud.redhat.com",
						Resource: "operatorconfigs",
					},
					"config",
				)
			}

			req, err := http.NewRequest(http.MethodGet, "/v1/config", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("reqID", "test-req-id")

			server.handleGetOperatorConfig(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response OperatorConfigResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.AutomotiveImageBuilder).To(Equal(automotivev1alpha1.DefaultAutomotiveImageBuilderImage))
			Expect(response.JumpstarterTargets).To(BeNil())
			Expect(response.TargetDefaults).To(BeNil())
		})

		It("should return jumpstarter targets and target defaults when config exists", func() {
			config := &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{
					Jumpstarter: &automotivev1alpha1.JumpstarterConfig{
						TargetMappings: map[string]automotivev1alpha1.JumpstarterTargetMapping{
							"qemu": {
								Selector: "board-type=qemu",
							},
							"ebbr": {
								Selector: "board-type=ebbr",
								FlashCmd: "j storage flash ${IMAGE}",
							},
						},
					},
				},
			}

			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return nil, nil
			}
			loadOperatorConfigFn = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return config, nil
			}
			loadTargetDefaultsFn = func(_ context.Context, _ ctrlclient.Client, _ string) (map[string]TargetDefaults, error) {
				return map[string]TargetDefaults{
					"ebbr": {Architecture: "arm64", ExtraArgs: []string{"--separate-partitions"}},
				}, nil
			}

			req, err := http.NewRequest(http.MethodGet, "/v1/config", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("reqID", "test-req-id")

			server.handleGetOperatorConfig(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response OperatorConfigResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.JumpstarterTargets).To(HaveLen(2))
			Expect(response.JumpstarterTargets["qemu"]).To(Equal(JumpstarterTarget{Selector: "board-type=qemu"}))
			Expect(response.JumpstarterTargets["ebbr"]).To(Equal(JumpstarterTarget{
				Selector: "board-type=ebbr",
				FlashCmd: "j storage flash ${IMAGE}",
			}))
			Expect(response.TargetDefaults).To(HaveLen(1))
			Expect(response.TargetDefaults["ebbr"]).To(Equal(TargetDefaults{
				Architecture: "arm64",
				ExtraArgs:    []string{"--separate-partitions"},
			}))
		})

		It("should return per-target validation hints in target defaults", func() {
			config := &automotivev1alpha1.OperatorConfig{
				Spec: automotivev1alpha1.OperatorConfigSpec{},
			}
			getClientFromRequestFn = func(_ *gin.Context) (ctrlclient.Client, error) {
				return nil, nil
			}
			loadOperatorConfigFn = func(_ context.Context, _ ctrlclient.Client, _ string) (*automotivev1alpha1.OperatorConfig, error) {
				return config, nil
			}
			loadTargetDefaultsFn = func(_ context.Context, _ ctrlclient.Client, _ string) (map[string]TargetDefaults, error) {
				return map[string]TargetDefaults{
					"qemu": {
						DefaultFormat:         "raw",
						AcceptedFormats:       []string{"qcow2", "raw"},
						AcceptedArchitectures: []string{"amd64", "arm64"},
					},
				}, nil
			}

			req, err := http.NewRequest(http.MethodGet, "/v1/config", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("reqID", "test-req-id")

			server.handleGetOperatorConfig(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response OperatorConfigResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.TargetDefaults).To(HaveLen(1))
			Expect(response.TargetDefaults["qemu"].AcceptedFormats).To(ConsistOf("qcow2", "raw"))
			Expect(response.TargetDefaults["qemu"].AcceptedArchitectures).To(ConsistOf("amd64", "arm64"))
		})
	})

	Context("Server Lifecycle", func() {
		It("should start and stop gracefully", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			errChan := make(chan error, 1)
			go func() {
				errChan <- server.Start(ctx)
			}()

			time.Sleep(100 * time.Millisecond)

			cancel()

			Eventually(errChan, 2*time.Second).Should(Receive(BeNil()))
		})
	})

	Context("Integration with Kubernetes", func() {
		BeforeEach(func() {
			if os.Getenv("KUBECONFIG") == "" && os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
				Skip("no kubernetes configuration found")
			}
		})

		It("should be able to connect to Kubernetes cluster", func() {
			req, err := http.NewRequest("GET", "/v1/healthz", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Body.String()).To(Equal("ok"))
		})
	})
})

var _ = Describe("APIServer Performance", func() {
	var (
		server *APIServer
	)

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		server = NewAPIServer(":0", logr.Discard())
	})

	It("should handle health endpoint requests", func() {
		req, _ := http.NewRequest("GET", "/v1/healthz", nil)

		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
	})

	It("should handle openapi endpoint requests efficiently", func() {
		req, _ := http.NewRequest("GET", "/v1/openapi.yaml", nil)

		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
	})

	Context("buildProducedArtifacts", func() {
		DescribeTable("returns correct result for each phase",
			func(phase string, pushTaskRun string, flashTaskRun string, expected bool) {
				build := &automotivev1alpha1.ImageBuild{
					Status: automotivev1alpha1.ImageBuildStatus{
						Phase:            phase,
						PushTaskRunName:  pushTaskRun,
						FlashTaskRunName: flashTaskRun,
					},
				}
				Expect(buildProducedArtifacts(build)).To(Equal(expected))
			},
			Entry("Pending", phasePending, "", "", false),
			Entry("Uploading", phaseUploading, "", "", false),
			Entry("Building", phaseBuilding, "", "", false),
			Entry("Pushing (in progress)", phasePushing, "", "", false),
			Entry("Flashing", phaseFlashing, "", "", true),
			Entry("Completed", phaseCompleted, "", "", true),
			Entry("Cancelled", phaseCancelled, "", "", false),
			Entry("Failed during build (no push/flash)", phaseFailed, "", "", false),
			Entry("Failed during push", phaseFailed, "push-taskrun", "", false),
			Entry("Failed during flash", phaseFailed, "push-taskrun", "flash-taskrun", true),
		)
	})
})
