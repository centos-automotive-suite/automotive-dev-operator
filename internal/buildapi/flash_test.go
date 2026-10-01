package buildapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	apis "knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Flash", func() {
	var (
		server               *APIServer
		originalNamespace    string
		hasOriginalNamespace bool
	)

	newFakeClient := func(objs ...ctrlclient.Object) ctrlclient.Client {
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(tektonv1.AddToScheme(scheme)).To(Succeed())
		builder := fake.NewClientBuilder().WithScheme(scheme)
		for _, obj := range objs {
			builder = builder.WithObjects(obj)
		}
		return builder.Build()
	}

	newFlashTaskRun := func(name, requestedBy, phase string) *tektonv1.TaskRun {
		tr := &tektonv1.TaskRun{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "test-ns",
				Labels: map[string]string{
					labels.FlashTaskRun: name,
				},
				Annotations: map[string]string{
					labels.RequestedBy: requestedBy,
				},
				CreationTimestamp: metav1.NewTime(time.Now()),
			},
		}
		switch phase {
		case "running":
			now := metav1.Now()
			tr.Status.StartTime = &now
		case "completed":
			now := metav1.Now()
			tr.Status.StartTime = &now
			tr.Status.CompletionTime = &now
			tr.Status.Status = duckv1.Status{
				Conditions: duckv1.Conditions{
					{
						Type:   apis.ConditionSucceeded,
						Status: corev1.ConditionTrue,
					},
				},
			}
		case "failed":
			now := metav1.Now()
			tr.Status.StartTime = &now
			tr.Status.CompletionTime = &now
			tr.Status.Status = duckv1.Status{
				Conditions: duckv1.Conditions{
					{
						Type:    apis.ConditionSucceeded,
						Status:  corev1.ConditionFalse,
						Message: "build step failed",
					},
				},
			}
		}
		return tr
	}

	BeforeEach(func() {
		gin.SetMode(gin.TestMode)
		server = newTestServer(GinkgoT(), nil)

		originalNamespace, hasOriginalNamespace = os.LookupEnv("BUILD_API_NAMESPACE")
		Expect(os.Setenv("BUILD_API_NAMESPACE", "test-ns")).To(Succeed())
	})

	AfterEach(func() {
		if hasOriginalNamespace {
			Expect(os.Setenv("BUILD_API_NAMESPACE", originalNamespace)).To(Succeed())
		} else {
			Expect(os.Unsetenv("BUILD_API_NAMESPACE")).To(Succeed())
		}
	})

	Context("getTaskRunStatus", func() {
		It("should return pending for TaskRun with no start time", func() {
			tr := newFlashTaskRun("test-flash", "alice", "pending")
			phase, msg := getTaskRunStatus(tr)
			Expect(phase).To(Equal(phasePending))
			Expect(msg).To(Equal("Waiting to start"))
		})

		It("should return running for started TaskRun", func() {
			tr := newFlashTaskRun("test-flash", "alice", "running")
			phase, msg := getTaskRunStatus(tr)
			Expect(phase).To(Equal(phaseRunning))
			Expect(msg).To(Equal("Flash in progress"))
		})

		It("should return completed for successful TaskRun", func() {
			tr := newFlashTaskRun("test-flash", "alice", "completed")
			phase, msg := getTaskRunStatus(tr)
			Expect(phase).To(Equal(phaseCompleted))
			Expect(msg).To(Equal("Flash completed successfully"))
		})

		It("should return failed with message for failed TaskRun", func() {
			tr := newFlashTaskRun("test-flash", "alice", "failed")
			phase, msg := getTaskRunStatus(tr)
			Expect(phase).To(Equal(phaseFailed))
			Expect(msg).To(Equal("build step failed"))
		})

		It("should return failed when completed with no Succeeded condition", func() {
			tr := newFlashTaskRun("test-flash", "alice", "pending")
			now := metav1.Now()
			tr.Status.CompletionTime = &now
			phase, msg := getTaskRunStatus(tr)
			Expect(phase).To(Equal(phaseFailed))
			Expect(msg).To(Equal("Flash failed"))
		})
	})

	Context("getFlash", func() {
		It("should return 404 for nonexistent flash TaskRun", func() {
			fakeClient := newFakeClient()
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes/nonexistent", nil)

			server.getFlash(c, "nonexistent")

			Expect(w.Code).To(Equal(http.StatusNotFound))
			Expect(w.Body.String()).To(ContainSubstring("flash TaskRun not found"))
		})

		It("should return 404 for TaskRun without flash label", func() {
			tr := &tektonv1.TaskRun{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "not-a-flash",
					Namespace: "test-ns",
					Labels:    map[string]string{},
				},
			}
			fakeClient := newFakeClient(tr)
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes/not-a-flash", nil)

			server.getFlash(c, "not-a-flash")

			Expect(w.Code).To(Equal(http.StatusNotFound))
		})

		It("should return flash details for valid flash TaskRun", func() {
			tr := newFlashTaskRun("my-flash", "alice", "running")
			fakeClient := newFakeClient(tr)
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes/my-flash", nil)

			server.getFlash(c, "my-flash")

			Expect(w.Code).To(Equal(http.StatusOK))
			var resp buildcontract.FlashResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.Name).To(Equal("my-flash"))
			Expect(resp.Phase).To(Equal(phaseRunning))
			Expect(resp.RequestedBy).To(Equal("alice"))
		})

		It("should return lease ID for completed flash TaskRun", func() {
			tr := newFlashTaskRun("my-flash", "alice", "completed")
			tr.Status.Results = []tektonv1.TaskRunResult{
				{
					Name:  "lease-id",
					Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "lease-abc123"},
				},
			}
			fakeClient := newFakeClient(tr)
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes/my-flash", nil)

			server.getFlash(c, "my-flash")

			Expect(w.Code).To(Equal(http.StatusOK))
			var resp buildcontract.FlashResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.Name).To(Equal("my-flash"))
			Expect(resp.Phase).To(Equal(phaseCompleted))
			Expect(resp.LeaseID).To(Equal("lease-abc123"))
		})
	})

	Context("listFlash", func() {
		It("should return empty list when no flash TaskRuns exist", func() {
			fakeClient := newFakeClient()
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes", nil)

			server.listFlash(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var resp []buildcontract.FlashListItem
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp).To(BeEmpty())
		})

		It("should list flash TaskRuns sorted by creation time", func() {
			tr1 := newFlashTaskRun("flash-old", "alice", "completed")
			tr1.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))
			tr2 := newFlashTaskRun("flash-new", "bob", "running")
			tr2.CreationTimestamp = metav1.NewTime(time.Now())

			fakeClient := newFakeClient(tr1, tr2)
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes", nil)

			server.listFlash(c)

			Expect(w.Code).To(Equal(http.StatusOK))
			var resp []buildcontract.FlashListItem
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp).To(HaveLen(2))
			Expect(resp[0].Name).To(Equal("flash-new"))
			Expect(resp[1].Name).To(Equal("flash-old"))
		})
	})

	Context("streamFlashLogs", func() {
		var fakeRESTConfig *rest.Config

		BeforeEach(func() {
			fakeRESTConfig = &rest.Config{Host: "https://fake-k8s:6443"}
			server.deps.getRESTConfigFromRequest = func(_ *gin.Context) (*rest.Config, error) {
				return fakeRESTConfig, nil
			}
		})

		It("should return 404 for nonexistent flash TaskRun", func() {
			fakeClient := newFakeClient()
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes/nonexistent/logs", nil)

			server.streamFlashLogs(c, "nonexistent")

			Expect(w.Code).To(Equal(http.StatusNotFound))
		})

		It("should return 503 when flash pod is not ready", func() {
			tr := newFlashTaskRun("my-flash", "alice", "pending")
			fakeClient := newFakeClient(tr)
			server.deps.getClientFromRequest = func(_ *gin.Context) (ctrlclient.Client, error) {
				return fakeClient, nil
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodGet, "/v1/flashes/my-flash/logs", nil)

			server.streamFlashLogs(c, "my-flash")

			Expect(w.Code).To(Equal(http.StatusServiceUnavailable))
			Expect(w.Body.String()).To(ContainSubstring("flash pod not ready"))
		})
	})
})
