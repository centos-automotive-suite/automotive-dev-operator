package buildapi

import (
	"context"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
)

var _ = Describe("Log Streaming", func() {
	Describe("getStepContainerNames", func() {
		It("returns only step- prefixed containers", func() {
			pod := corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "step-build"},
						{Name: "step-push"},
						{Name: "sidecar-tekton"},
					},
				},
			}
			names := getStepContainerNames(pod)
			Expect(names).To(Equal([]string{"step-build", "step-push"}))
		})

		It("falls back to all containers when no step- prefix found", func() {
			pod := corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "main"},
						{Name: "sidecar"},
					},
				},
			}
			names := getStepContainerNames(pod)
			Expect(names).To(Equal([]string{"main", "sidecar"}))
		})

		It("returns empty slice for pod with no containers", func() {
			pod := corev1.Pod{}
			names := getStepContainerNames(pod)
			Expect(names).To(BeEmpty())
		})
	})

	Describe("shouldExitLogStream", func() {
		var originalIsTerminal func(string) bool

		BeforeEach(func() {
			originalIsTerminal = isTerminalPhase
		})

		AfterEach(func() {
			isTerminalPhase = originalIsTerminal
		})

		It("returns true when phase is terminal and all pods complete", func() {
			isTerminalPhase = func(_ string) bool { return true }

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "default"},
				Status:     automotivev1alpha1.ImageBuildStatus{Phase: "Completed"},
			}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib).Build()

			result := shouldExitLogStream(
				testContext(), k8sClient, "test-build", "default", ib, true,
			)
			Expect(result).To(BeTrue())
		})

		It("returns false when phase is terminal but pods not complete", func() {
			isTerminalPhase = func(_ string) bool { return true }

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "default"},
				Status:     automotivev1alpha1.ImageBuildStatus{Phase: "Completed"},
			}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib).Build()

			result := shouldExitLogStream(
				testContext(), k8sClient, "test-build", "default", ib, false,
			)
			Expect(result).To(BeFalse())
		})

		It("returns false when phase is not terminal", func() {
			isTerminalPhase = func(_ string) bool { return false }

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "default"},
				Status:     automotivev1alpha1.ImageBuildStatus{Phase: "Building"},
			}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib).Build()

			result := shouldExitLogStream(
				testContext(), k8sClient, "test-build", "default", ib, true,
			)
			Expect(result).To(BeFalse())
		})

		It("returns false when build not found (k8s Get fails)", func() {
			isTerminalPhase = func(_ string) bool { return true }

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "default"},
			}
			result := shouldExitLogStream(
				testContext(), k8sClient, "missing", "default", ib, true,
			)
			Expect(result).To(BeFalse())
		})
	})

	Describe("writeLogStreamFooter", func() {
		It("writes 'no logs' message when hadStream is false", func() {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			writeLogStreamFooter(c, false)
			Expect(w.Body.String()).To(ContainSubstring("[No logs available]"))
		})

		It("writes 'completed' message when hadStream is true", func() {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			writeLogStreamFooter(c, true)
			Expect(w.Body.String()).To(ContainSubstring("[Log streaming completed]"))
		})
	})

	Describe("sortPodsByStartTime", func() {
		It("sorts pods by start time, nil-start-time last", func() {
			t1 := metav1.Now()
			t2 := metav1.NewTime(t1.Add(60e9))

			pods := []corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "no-start"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "late"}, Status: corev1.PodStatus{StartTime: &t2}},
				{ObjectMeta: metav1.ObjectMeta{Name: "early"}, Status: corev1.PodStatus{StartTime: &t1}},
			}

			sortPodsByStartTime(pods)

			Expect(pods[0].Name).To(Equal("early"))
			Expect(pods[1].Name).To(Equal("late"))
			Expect(pods[2].Name).To(Equal("no-start"))
		})
	})

	Describe("podTaskName", func() {
		It("returns tekton label when present", func() {
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "my-pod",
					Labels: map[string]string{"tekton.dev/pipelineTask": tasks.PipelineTaskBuildImage},
				},
			}
			Expect(podTaskName(pod)).To(Equal(tasks.PipelineTaskBuildImage))
		})

		It("falls back to pod name when label missing", func() {
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "my-pod"},
			}
			Expect(podTaskName(pod)).To(Equal("my-pod"))
		})
	})

	Describe("logStreamHeader", func() {
		It("formats header with task and container name", func() {
			header := logStreamHeader(tasks.PipelineTaskBuildImage, "step-build")
			Expect(header).To(Equal("\n===== Logs from build-image/build =====\n\n"))
		})

		It("handles container name without step- prefix", func() {
			header := logStreamHeader("task", "main")
			Expect(header).To(Equal("\n===== Logs from task/main =====\n\n"))
		})
	})

	Describe("isPodTerminal", func() {
		It("returns true for Succeeded", func() {
			Expect(isPodTerminal(corev1.PodSucceeded)).To(BeTrue())
		})

		It("returns true for Failed", func() {
			Expect(isPodTerminal(corev1.PodFailed)).To(BeTrue())
		})

		It("returns false for Running", func() {
			Expect(isPodTerminal(corev1.PodRunning)).To(BeFalse())
		})

		It("returns false for Pending", func() {
			Expect(isPodTerminal(corev1.PodPending)).To(BeFalse())
		})
	})

	Describe("isBuildTerminal", func() {
		var originalIsTerminal func(string) bool

		BeforeEach(func() {
			originalIsTerminal = isTerminalPhase
		})

		AfterEach(func() {
			isTerminalPhase = originalIsTerminal
		})

		It("returns true when build phase is terminal", func() {
			isTerminalPhase = func(_ string) bool { return true }

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "done-build", Namespace: "default"},
				Status:     automotivev1alpha1.ImageBuildStatus{Phase: "Completed"},
			}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib).Build()

			result := isBuildTerminal(testContext(), k8sClient, "done-build", "default")
			Expect(result).To(BeTrue())
		})

		It("returns false when build phase is not terminal", func() {
			isTerminalPhase = func(_ string) bool { return false }

			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "running-build", Namespace: "default"},
				Status:     automotivev1alpha1.ImageBuildStatus{Phase: "Building"},
			}
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ib).Build()

			result := isBuildTerminal(testContext(), k8sClient, "running-build", "default")
			Expect(result).To(BeFalse())
		})

		It("returns false when build not found", func() {
			scheme := runtime.NewScheme()
			Expect(automotivev1alpha1.AddToScheme(scheme)).To(Succeed())
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			result := isBuildTerminal(testContext(), k8sClient, "missing", "default")
			Expect(result).To(BeFalse())
		})
	})
})

func testContext() context.Context {
	return context.Background()
}
