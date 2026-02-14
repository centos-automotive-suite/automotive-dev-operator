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

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/imagesealed"
)

var _ = Describe("ImageSealed Controller", func() {
	const namespace = "default"

	Context("When reconciling a single-operation sealed resource", func() {
		const resourceName = "test-sealed-prepare-reseal"

		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{Name: resourceName, Namespace: namespace}

		BeforeEach(func() {
			By("creating the ImageSealed resource")
			sealed := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, sealed)
			if err != nil && errors.IsNotFound(err) {
				resource := &automotivev1alpha1.ImageSealed{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: namespace,
					},
					Spec: automotivev1alpha1.ImageSealedSpec{
						Operation:    "prepare-reseal",
						InputRef:     "quay.io/test/bootc:seal",
						OutputRef:    "quay.io/test/bootc:prepared",
						BuilderImage: "quay.io/test/builder:latest",
						Architecture: "arm64",
						KeySecretRef: "test-seal-key",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should reconcile and update status appropriately", func() {
			By("Reconciling the ImageSealed resource")
			r := &imagesealed.Reconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			// First reconcile: without Tekton CRDs in envtest, ensureSealedTasks will fail
			// and the controller should set status to Failed with a descriptive message.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})

			sealed := &automotivev1alpha1.ImageSealed{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, sealed)).To(Succeed())

			if err != nil {
				// Reconciler returned an error (e.g., status update itself failed) — still a valid path
				Expect(sealed.Status.Phase).To(BeElementOf("", "Pending", "Failed"))
			} else {
				// Reconciler handled the error gracefully: expect Failed (Tekton CRDs absent) or Running (CRDs present)
				Expect(sealed.Status.Phase).To(BeElementOf("Failed", "Running"))
				if sealed.Status.Phase == "Failed" {
					Expect(sealed.Status.Message).To(ContainSubstring("sealed tasks"))
				}
			}
		})
	})

	Context("When reconciling with empty operation", func() {
		const resourceName = "test-sealed-empty-op"

		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{Name: resourceName, Namespace: namespace}

		BeforeEach(func() {
			sealed := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, sealed)
			if err != nil && errors.IsNotFound(err) {
				resource := &automotivev1alpha1.ImageSealed{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: namespace,
					},
					Spec: automotivev1alpha1.ImageSealedSpec{
						InputRef: "quay.io/test/bootc:seal",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should fail with missing operation error", func() {
			r := &imagesealed.Reconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			sealed := &automotivev1alpha1.ImageSealed{}
			err = k8sClient.Get(ctx, typeNamespacedName, sealed)
			Expect(err).NotTo(HaveOccurred())
			Expect(sealed.Status.Phase).To(Equal("Failed"))
			Expect(sealed.Status.Message).To(ContainSubstring("operation or spec.stages must be set"))
		})
	})

	Context("When reconciling with invalid stage name", func() {
		const resourceName = "test-sealed-invalid-stage"

		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{Name: resourceName, Namespace: namespace}

		BeforeEach(func() {
			sealed := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, sealed)
			if err != nil && errors.IsNotFound(err) {
				resource := &automotivev1alpha1.ImageSealed{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: namespace,
					},
					Spec: automotivev1alpha1.ImageSealedSpec{
						Stages:   []string{"prepare-reseal", "bogus-op"},
						InputRef: "quay.io/test/bootc:seal",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should fail with invalid operation error", func() {
			r := &imagesealed.Reconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			sealed := &automotivev1alpha1.ImageSealed{}
			err = k8sClient.Get(ctx, typeNamespacedName, sealed)
			Expect(err).NotTo(HaveOccurred())
			Expect(sealed.Status.Phase).To(Equal("Failed"))
			Expect(sealed.Status.Message).To(ContainSubstring(`invalid sealed operation "bogus-op"`))
		})
	})

	Context("When reconciling a completed resource", func() {
		const resourceName = "test-sealed-completed"

		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{Name: resourceName, Namespace: namespace}

		BeforeEach(func() {
			sealed := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, sealed)
			if err != nil && errors.IsNotFound(err) {
				resource := &automotivev1alpha1.ImageSealed{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: namespace,
					},
					Spec: automotivev1alpha1.ImageSealedSpec{
						Operation: "reseal",
						InputRef:  "quay.io/test/bootc:seal",
						OutputRef: "quay.io/test/bootc:resealed",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())

				// Set status to Completed
				err = k8sClient.Get(ctx, typeNamespacedName, resource)
				Expect(err).NotTo(HaveOccurred())
				resource.Status.Phase = "Completed"
				resource.Status.Message = "Done"
				Expect(k8sClient.Status().Update(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &automotivev1alpha1.ImageSealed{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should be a no-op for completed resources", func() {
			r := &imagesealed.Reconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())

			sealed := &automotivev1alpha1.ImageSealed{}
			err = k8sClient.Get(ctx, typeNamespacedName, sealed)
			Expect(err).NotTo(HaveOccurred())
			Expect(sealed.Status.Phase).To(Equal("Completed"))
		})
	})

	Context("When reconciling a non-existent resource", func() {
		It("should not error for missing resources", func() {
			r := &imagesealed.Reconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			result, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "does-not-exist", Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())
		})
	})
})
