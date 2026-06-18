package buildapi

import (
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	corev1 "k8s.io/api/core/v1"
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
