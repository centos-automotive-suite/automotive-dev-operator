package buildapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var _ = Describe("pendingPodStage", func() {
	It("returns empty string for pod with no waiting containers", func() {
		pod := &corev1.Pod{
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
			},
		}
		Expect(pendingPodStage(pod)).To(BeEmpty())
	})

	DescribeTable("returns expected stage for waiting reason",
		func(reason, expected string) {
			pod := &corev1.Pod{
				Status: corev1.PodStatus{
					Phase: corev1.PodPending,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							State: corev1.ContainerState{
								Waiting: &corev1.ContainerStateWaiting{Reason: reason},
							},
						},
					},
				},
			}
			Expect(pendingPodStage(pod)).To(Equal(expected))
		},
		Entry("ContainerCreating", "ContainerCreating", "Pulling image"),
		Entry("PodInitializing", "PodInitializing", "Pulling image"),
		Entry("ErrImagePull", "ErrImagePull", "Pulling image (retrying)"),
		Entry("ImagePullBackOff", "ImagePullBackOff", "Pulling image (retrying)"),
	)

	It("detects waiting init containers", func() {
		pod := &corev1.Pod{
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				InitContainerStatuses: []corev1.ContainerStatus{
					{
						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"},
						},
					},
				},
			},
		}
		Expect(pendingPodStage(pod)).To(Equal("Pulling image"))
	})

	It("returns empty for unrecognized waiting reason", func() {
		pod := &corev1.Pod{
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{Reason: "Unschedulable"},
						},
					},
				},
			},
		}
		Expect(pendingPodStage(pod)).To(BeEmpty())
	})
})

func TestBuildProgressAcrossPodTransitions(t *testing.T) {
	for _, tt := range []struct {
		name  string
		pods  []*corev1.Pod
		stage string
		done  int
	}{
		{name: "before pod creation", stage: "Starting build"},
		{name: "pulling build image", pods: []*corev1.Pod{progressTestPod("build-image", corev1.PodPending, "", 1)}, stage: "Pulling image"},
		{name: "before first checkpoint", pods: []*corev1.Pod{progressTestPod("build-image", corev1.PodRunning, "", 1)}, stage: "Starting build"},
		{name: "preparing", pods: []*corev1.Pod{progressTestPod("build-image", corev1.PodRunning, "Preparing build|1|4", 1)}, stage: "Preparing build", done: 1},
		{name: "building", pods: []*corev1.Pod{progressTestPod("build-image", corev1.PodRunning, "Building image|2|4", 1)}, stage: "Building image", done: 2},
		{name: "finished pod with stale checkpoint", pods: []*corev1.Pod{progressTestPod("build-image", corev1.PodSucceeded, "Preparing build|1|4", 1)}, stage: "Finalizing build", done: 4},
		{name: "finished pod without checkpoint", pods: []*corev1.Pod{progressTestPod("build-image", corev1.PodSucceeded, "", 1)}, stage: "Finalizing build", done: 4},
		{name: "starting push", pods: []*corev1.Pod{
			progressTestPod("build-image", corev1.PodSucceeded, "Compressing artifacts|3|4", 1),
			progressTestPod("push-disk-artifact", corev1.PodPending, "", 2),
		}, stage: "Pulling image", done: 4},
		{name: "pushing", pods: []*corev1.Pod{
			progressTestPod("build-image", corev1.PodSucceeded, "Compressing artifacts|3|4", 1),
			progressTestPod("push-disk-artifact", corev1.PodRunning, "Pushing artifact|0|1", 2),
		}, stage: "Pushing artifact", done: 4},
		{name: "push completed without final checkpoint", pods: []*corev1.Pod{
			progressTestPod("build-image", corev1.PodSucceeded, "Compressing artifacts|3|4", 1),
			progressTestPod("push-disk-artifact", corev1.PodSucceeded, "Pushing artifact|0|1", 2),
		}, stage: "Finalizing build", done: 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			build := &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB:       &automotivev1alpha1.AIBSpec{Mode: "image"},
					SecretRef: "registry-auth",
					Export:    &automotivev1alpha1.ExportSpec{Disk: &automotivev1alpha1.DiskExport{OCI: "registry.example/test"}},
				},
				Status: automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
			}
			cs := progressTestClient(t, tt.pods...)
			tasks := readTaskProgressFromPods(t.Context(), cs, "test-run", "test-ns")
			got := buildProgressStep(build, tasks, false)
			want := BuildStep{Stage: tt.stage, Done: tt.done, Total: 5}
			if *got != want {
				t.Fatalf("progress = %+v, want %+v", *got, want)
			}
		})
	}
}

func TestBuildProgressIncludesS3BeforeItsPodExists(t *testing.T) {
	build := &automotivev1alpha1.ImageBuild{
		Spec: automotivev1alpha1.ImageBuildSpec{
			AIB: &automotivev1alpha1.AIBSpec{Mode: "image"},
			Export: &automotivev1alpha1.ExportSpec{Disk: &automotivev1alpha1.DiskExport{
				S3: &automotivev1alpha1.S3Export{Bucket: "test-bucket"},
			}},
		},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
	}
	initial := buildProgressStep(build, nil, false)
	cs := progressTestClient(t,
		progressTestPod("build-image", corev1.PodSucceeded, "Preparing build|1|4", 1),
		progressTestPod("push-disk-artifact-s3", corev1.PodRunning, "", 2),
	)
	tasks := readTaskProgressFromPods(t.Context(), cs, "test-run", "test-ns")
	pushing := buildProgressStep(build, tasks, false)
	if initial.Total != 5 || pushing.Total != 5 || pushing.Done != 4 || pushing.Stage != "Pushing to S3" {
		t.Fatalf("incorrect S3 progress: initial=%+v pushing=%+v", initial, pushing)
	}
}

func TestBuildProgressEstimatesBuilderStepsBeforeAnnotations(t *testing.T) {
	build := &automotivev1alpha1.ImageBuild{
		Spec:   automotivev1alpha1.ImageBuildSpec{AIB: &automotivev1alpha1.AIBSpec{Mode: "bootc"}},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
	}
	cs := progressTestClient(t, progressTestPod("build-image", corev1.PodPending, "", 1))
	tasks := readTaskProgressFromPods(t.Context(), cs, "test-run", "test-ns")
	got := buildProgressStep(build, tasks, true)
	if got.Total != 5 || got.Done != 0 {
		t.Fatalf("synthetic checkpoint changed the build estimate: %+v", got)
	}
}

func TestParseProgressAnnotationValidatesCounts(t *testing.T) {
	for _, value := range []string{"Building|-1|4", "Building|5|4", "Building|0|0", "Building|0|-1", "|1|4", "Building|one|4"} {
		if _, ok := parseProgressAnnotation(value); ok {
			t.Errorf("accepted invalid checkpoint %q", value)
		}
	}
	if got, ok := parseProgressAnnotation("Pushing artifact|0|1"); !ok || got.Done != 0 || got.Total != 1 {
		t.Fatalf("rejected valid checkpoint: %+v", got)
	}
}

func progressTestPod(task string, phase corev1.PodPhase, annotation string, start int64) *corev1.Pod {
	startTime := metav1.NewTime(time.Unix(start, 0))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: task, Namespace: "test-ns",
			Labels: map[string]string{"tekton.dev/pipelineRun": "test-run", "tekton.dev/memberOf": "tasks", "tekton.dev/pipelineTask": task},
		},
		Status: corev1.PodStatus{Phase: phase, StartTime: &startTime},
	}
	if annotation != "" {
		pod.Annotations = map[string]string{labels.Progress: annotation}
	}
	if phase == corev1.PodPending {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}
	}
	return pod
}

func progressTestClient(t *testing.T, pods ...*corev1.Pod) *kubernetes.Clientset {
	t.Helper()
	list := corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}}
	for _, pod := range pods {
		list.Items = append(list.Items, *pod)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/test-ns/pods" || r.URL.Query().Get("labelSelector") != "tekton.dev/pipelineRun=test-run,tekton.dev/memberOf=tasks" {
			t.Errorf("unexpected pod query: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(list); err != nil {
			t.Errorf("encode pods: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}
