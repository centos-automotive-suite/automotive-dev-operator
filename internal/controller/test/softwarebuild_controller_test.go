/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package test

import (
	"context"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/softwarebuild"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

var _ = Describe("SoftwareBuild Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-sb"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		sb := &automotivev1alpha1.SoftwareBuild{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind SoftwareBuild")
			err := k8sClient.Get(ctx, typeNamespacedName, sb)
			if err != nil && errors.IsNotFound(err) {
				resource := &automotivev1alpha1.SoftwareBuild{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: automotivev1alpha1.SoftwareBuildSpec{
						Runtime: automotivev1alpha1.SoftwareBuildRuntimeSpec{
							Image: "ghcr.io/zephyrproject-rtos/ci-base:latest",
						},
						Source: automotivev1alpha1.SoftwareBuildSourceSpec{
							Type: automotivev1alpha1.SoftwareBuildSourceGit,
							Git: &automotivev1alpha1.SoftwareBuildGitSource{
								URL:      "https://github.com/vtz/body-ecu",
								Revision: "main",
							},
						},
						Stages: automotivev1alpha1.SoftwareBuildPipelineStages{
							Fetch:     automotivev1alpha1.SoftwareBuildStageSpec{Command: "west init -l . && west update"},
							Prebuild:  automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo prebuild"},
							Build:     automotivev1alpha1.SoftwareBuildStageSpec{Command: "west build -b native_sim app"},
							Postbuild: automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo postbuild"},
							Deploy:    automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo deploy"},
						},
						Destination: automotivev1alpha1.SoftwareBuildDestinationSpec{
							Type: automotivev1alpha1.SoftwareBuildDestSharedFolder,
							Path: "/workspace/artifacts",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &automotivev1alpha1.SoftwareBuild{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance SoftwareBuild")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &softwarebuild.SoftwareBuildReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should accept ubuntu runtime image", func() {
			ubuntuName := "test-sb-ubuntu"
			resource := &automotivev1alpha1.SoftwareBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ubuntuName,
					Namespace: "default",
				},
				Spec: automotivev1alpha1.SoftwareBuildSpec{
					Runtime: automotivev1alpha1.SoftwareBuildRuntimeSpec{
						Image: "ubuntu:24.04",
					},
					Source: automotivev1alpha1.SoftwareBuildSourceSpec{
						Type:     automotivev1alpha1.SoftwareBuildSourceHostPath,
						HostPath: &automotivev1alpha1.SoftwareBuildHostPathSource{Path: "/src"},
					},
					Stages: automotivev1alpha1.SoftwareBuildPipelineStages{
						Fetch:     automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo fetch"},
						Prebuild:  automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo pre"},
						Build:     automotivev1alpha1.SoftwareBuildStageSpec{Command: "make"},
						Postbuild: automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo post"},
						Deploy:    automotivev1alpha1.SoftwareBuildStageSpec{Command: "echo deploy"},
					},
					Destination: automotivev1alpha1.SoftwareBuildDestinationSpec{
						Type: automotivev1alpha1.SoftwareBuildDestSharedFolder,
						Path: "/out",
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler := &softwarebuild.SoftwareBuildReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: ubuntuName, Namespace: "default"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
	})
})
