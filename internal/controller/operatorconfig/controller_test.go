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

package operatorconfig

import (
	"context"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	imagev1 "github.com/openshift/api/image/v1"
	securityv1 "github.com/openshift/api/security/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var _ = Describe("workspace infrastructure reconciliation", func() {
	var (
		r      *OperatorConfigReconciler
		config *automotivev1alpha1.OperatorConfig
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(rbacv1.AddToScheme(scheme)).To(Succeed())
		Expect(securityv1.AddToScheme(scheme)).To(Succeed())
		r = &OperatorConfigReconciler{
			Client:      fake.NewClientBuilder().WithScheme(scheme).Build(),
			Log:         logr.Discard(),
			IsOpenShift: new(true),
		}
		config = &automotivev1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "test-ns"},
		}
	})

	DescribeTable("requires pod user namespaces",
		func(upgrade bool) {
			ctx := context.Background()
			if upgrade {
				legacy := r.buildWorkspaceSCC()
				legacy.UserNamespaceLevel = ""
				legacy.AllowPrivilegedContainer = true
				legacy.AllowedCapabilities = []corev1.Capability{"*"}
				legacy.FSGroup = securityv1.FSGroupStrategyOptions{Type: securityv1.FSGroupStrategyRunAsAny}
				legacy.SupplementalGroups = securityv1.SupplementalGroupsStrategyOptions{Type: securityv1.SupplementalGroupsStrategyRunAsAny}
				legacy.Volumes = []securityv1.FSType{securityv1.FSTypeAll}
				setSpecHashAnnotation(legacy, computeSpecHash(legacy))
				Expect(r.Create(ctx, legacy)).To(Succeed())
			}

			Expect(r.deployWorkspaceInfra(ctx, config)).To(Succeed())
			actual := &securityv1.SecurityContextConstraints{}
			Expect(r.Get(ctx, client.ObjectKey{Name: workspaceSCCName}, actual)).To(Succeed())
			Expect(actual.UserNamespaceLevel).To(Equal(securityv1.NamespaceLevelRequirePod))
			Expect(actual.AllowPrivilegedContainer).To(BeFalse())
			Expect(actual.AllowedCapabilities).NotTo(ContainElement(corev1.Capability("*")))
			Expect(actual.AllowHostDirVolumePlugin).To(BeFalse())
			Expect(actual.Volumes).NotTo(ContainElement(securityv1.FSTypeAll))
			Expect(actual.FSGroup.Ranges).To(Equal([]securityv1.IDRange{{Min: 0, Max: 65534}}))
			Expect(actual.SupplementalGroups.Ranges).To(Equal([]securityv1.IDRange{{Min: 0, Max: 65534}}))

			// Reconciliation must keep the same policy on subsequent passes.
			Expect(r.deployWorkspaceInfra(ctx, config)).To(Succeed())
			unchanged := &securityv1.SecurityContextConstraints{}
			Expect(r.Get(ctx, client.ObjectKey{Name: workspaceSCCName}, unchanged)).To(Succeed())
			Expect(unchanged.ResourceVersion).To(Equal(actual.ResourceVersion))
		},
		Entry("on a new installation", false),
		Entry("when upgrading from the privileged workspace SCC", true),
	)

	It("propagates SCC creation failures without retrying a privileged policy", func() {
		var attempts int
		r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if scc, ok := obj.(*securityv1.SecurityContextConstraints); ok {
					attempts++
					Expect(scc.UserNamespaceLevel).To(Equal(securityv1.NamespaceLevelRequirePod))
					Expect(scc.AllowPrivilegedContainer).To(BeFalse())
					return fmt.Errorf("workspace SCC rejected")
				}
				return c.Create(ctx, obj, opts...)
			},
		})
		Expect(r.deployWorkspaceInfra(context.Background(), config)).To(MatchError(ContainSubstring("workspace SCC rejected")))
		Expect(attempts).To(Equal(1))
	})
})

var _ = Describe("build identity reconciliation", func() {
	var (
		r      *OperatorConfigReconciler
		config *automotivev1alpha1.OperatorConfig
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(rbacv1.AddToScheme(scheme)).To(Succeed())
		Expect(admissionregistrationv1.AddToScheme(scheme)).To(Succeed())
		Expect(imagev1.Install(scheme)).To(Succeed())
		r = &OperatorConfigReconciler{
			Client:      fake.NewClientBuilder().WithScheme(scheme).Build(),
			Log:         logr.Discard(),
			IsOpenShift: new(true),
		}
		config = &automotivev1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "test-ns"},
		}
	})

	// Every object deployBuildIdentity owns, keyed for Get and Delete.
	owned := func() []client.Object {
		return []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: automotivev1alpha1.BuildServiceAccountName, Namespace: "test-ns"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: automotivev1alpha1.RegistryServiceAccountName, Namespace: "test-ns"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: automotivev1alpha1.RegistryPullServiceAccountName, Namespace: "test-ns"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: sccPrivilegedRoleName}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: pipelineSCCBindingName, Namespace: "test-ns"}},
			&admissionregistrationv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: r.buildBuildPodPatchPolicy("test-ns").Name}},
			&admissionregistrationv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: r.buildBuildPodPatchPolicyBinding("test-ns").Name}},
		}
	}

	It("binds the pod patch policy to the build namespace", func() {
		ctx := context.Background()
		Expect(r.deployBuildIdentity(ctx, config)).To(Succeed())

		policy := r.buildBuildPodPatchPolicy("test-ns")
		binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
		Expect(r.Get(ctx, client.ObjectKey{Name: r.buildBuildPodPatchPolicyBinding("test-ns").Name}, binding)).To(Succeed())
		Expect(binding.Spec.PolicyName).To(Equal(policy.Name))
		Expect(binding.Spec.ValidationActions).To(Equal([]admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}))
		Expect(binding.Spec.MatchResources.NamespaceSelector.MatchLabels).To(Equal(map[string]string{"kubernetes.io/metadata.name": "test-ns"}))
		Expect(r.buildBuildPodPatchPolicy("other-ns").Name).NotTo(Equal(policy.Name),
			"instances in different namespaces must not share cluster-scoped policy objects")
	})

	It("creates registry ServiceAccounts that never mount their token", func() {
		ctx := context.Background()
		Expect(r.deployBuildIdentity(ctx, config)).To(Succeed())

		for _, name := range []string{automotivev1alpha1.RegistryServiceAccountName, automotivev1alpha1.RegistryPullServiceAccountName} {
			sa := &corev1.ServiceAccount{}
			Expect(r.Get(ctx, client.ObjectKey{Name: name, Namespace: "test-ns"}, sa)).To(Succeed(), name)
			Expect(sa.AutomountServiceAccountToken).To(HaveValue(BeFalse()), name)
		}
	})

	// Build pods push the builder cache as ado-build, which may push to an
	// existing ImageStream but not create one.
	It("creates the builder cache ImageStream once and keeps an existing one", func() {
		ctx := context.Background()
		Expect(r.deployBuildIdentity(ctx, config)).To(Succeed())
		stream := &imagev1.ImageStream{}
		Expect(r.Get(ctx, client.ObjectKey{Name: tasks.BuilderCacheStreamName, Namespace: "test-ns"}, stream)).To(Succeed())

		stream.Annotations = map[string]string{"example.com/cached": "builders"}
		Expect(r.Update(ctx, stream)).To(Succeed())
		Expect(r.deployBuildIdentity(ctx, config)).To(Succeed())
		kept := &imagev1.ImageStream{}
		Expect(r.Get(ctx, client.ObjectKey{Name: tasks.BuilderCacheStreamName, Namespace: "test-ns"}, kept)).To(Succeed())
		Expect(kept.Annotations).To(HaveKeyWithValue("example.com/cached", "builders"))
	})

	It("deletes everything it created on cleanup", func() {
		ctx := context.Background()
		Expect(r.deployBuildIdentity(ctx, config)).To(Succeed())
		for _, obj := range owned() {
			Expect(r.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed(), "%T %s", obj, obj.GetName())
		}

		Expect(r.cleanupBuildIdentity(ctx, config)).To(Succeed())
		for _, obj := range owned() {
			Expect(errors.IsNotFound(r.Get(ctx, client.ObjectKeyFromObject(obj), obj))).To(BeTrue(), "%T %s", obj, obj.GetName())
		}
	})
})

var _ = Describe("metrics reader ClusterRoleBinding reconciliation", func() {
	DescribeTable("should reconcile existing bindings",
		func(mutate func(*rbacv1.ClusterRoleBinding), expectedDeletes, expectedCreates, expectedUpdates int, unmanaged bool) {
			ctx := context.Background()
			r := &OperatorConfigReconciler{Log: logr.Discard()}
			desired := r.buildMetricsReaderClusterRoleBinding("test-ns")
			existing := desired.DeepCopy()
			mutate(existing)
			existing.UID = "original-binding"

			scheme := runtime.NewScheme()
			Expect(rbacv1.AddToScheme(scheme)).To(Succeed())
			var deletes, creates, updates int
			r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						deletes++
						Expect(obj.GetUID()).To(Equal(existing.UID))
						return c.Delete(ctx, obj, opts...)
					},
					Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						creates++
						Expect(obj.GetResourceVersion()).To(BeEmpty())
						return c.Create(ctx, obj, opts...)
					},
					Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
						updates++
						Expect(obj.(*rbacv1.ClusterRoleBinding).RoleRef).To(Equal(existing.RoleRef), "roleRef is immutable")
						return c.Update(ctx, obj, opts...)
					},
				}).Build()

			Expect(r.createOrUpdate(ctx, desired, nil)).To(Succeed())
			Expect(deletes).To(Equal(expectedDeletes))
			Expect(creates).To(Equal(expectedCreates))
			Expect(updates).To(Equal(expectedUpdates))

			actual := &rbacv1.ClusterRoleBinding{}
			Expect(r.Get(ctx, client.ObjectKeyFromObject(desired), actual)).To(Succeed())
			if unmanaged {
				Expect(actual.RoleRef).To(Equal(existing.RoleRef))
				Expect(actual.UID).To(Equal(existing.UID))
				return
			}
			Expect(actual.RoleRef).To(Equal(desired.RoleRef))
			Expect(actual.Subjects).To(Equal(desired.Subjects))
			Expect(actual.Annotations).To(HaveKeyWithValue(specHashAnnotation,
				computeSpecHash(r.buildMetricsReaderClusterRoleBinding("test-ns"))))

			Expect(r.createOrUpdate(ctx, r.buildMetricsReaderClusterRoleBinding("test-ns"), nil)).To(Succeed())
			Expect(deletes).To(Equal(expectedDeletes))
			Expect(creates).To(Equal(expectedCreates))
			Expect(updates).To(Equal(expectedUpdates))
		},
		Entry("replace the legacy role reference with its old desired-state hash", func(binding *rbacv1.ClusterRoleBinding) {
			binding.RoleRef.Name = "metrics-reader"
			setSpecHashAnnotation(binding, computeSpecHash(binding))
		}, 1, 1, 0, false),
		Entry("replace the legacy role reference without a hash", func(binding *rbacv1.ClusterRoleBinding) {
			binding.RoleRef.Name = "metrics-reader"
		}, 1, 1, 0, false),
		Entry("leave unmanaged legacy bindings untouched", func(binding *rbacv1.ClusterRoleBinding) {
			binding.RoleRef.Name = "metrics-reader"
			binding.Annotations = map[string]string{unmanagedAnnotationKey: unmanagedAnnotationTrue}
		}, 0, 0, 0, true),
		Entry("skip unchanged bindings", func(binding *rbacv1.ClusterRoleBinding) {
			setSpecHashAnnotation(binding, computeSpecHash(binding))
		}, 0, 0, 0, false),
		Entry("update subjects without replacing the binding", func(binding *rbacv1.ClusterRoleBinding) {
			binding.Subjects[0].Namespace = "old-ns"
		}, 0, 0, 1, false),
	)
})

var _ = Describe("setCondition", func() {
	var (
		r      *OperatorConfigReconciler
		config *automotivev1alpha1.OperatorConfig
	)

	BeforeEach(func() {
		r = &OperatorConfigReconciler{}
		config = &automotivev1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-config",
				Generation: 1,
			},
		}
	})

	It("should add a new condition", func() {
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionTrue, "ReconcileSucceeded", "all good")

		Expect(config.Status.Conditions).To(HaveLen(1))
		c := config.Status.Conditions[0]
		Expect(c.Type).To(Equal(automotivev1alpha1.OperatorConfigConditionReady))
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Reason).To(Equal("ReconcileSucceeded"))
		Expect(c.Message).To(Equal("all good"))
		Expect(c.ObservedGeneration).To(Equal(int64(1)))
	})

	It("should update an existing condition of the same type", func() {
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionFalse, "DeployFailed", "broken")
		firstTransition := config.Status.Conditions[0].LastTransitionTime

		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionTrue, "ReconcileSucceeded", "fixed")

		Expect(config.Status.Conditions).To(HaveLen(1))
		c := config.Status.Conditions[0]
		Expect(c.Status).To(Equal(metav1.ConditionTrue))
		Expect(c.Reason).To(Equal("ReconcileSucceeded"))
		Expect(c.LastTransitionTime).NotTo(Equal(firstTransition))
	})

	It("should track multiple condition types independently", func() {
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionTrue, "ReconcileSucceeded", "ok")
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionDegraded, metav1.ConditionFalse, "ReconcileSucceeded", "ok")
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReconciling, metav1.ConditionFalse, "ReconcileSucceeded", "done")

		Expect(config.Status.Conditions).To(HaveLen(3))

		types := map[string]metav1.ConditionStatus{}
		for _, c := range config.Status.Conditions {
			types[c.Type] = c.Status
		}
		Expect(types).To(HaveKeyWithValue("Ready", metav1.ConditionTrue))
		Expect(types).To(HaveKeyWithValue("Degraded", metav1.ConditionFalse))
		Expect(types).To(HaveKeyWithValue("Reconciling", metav1.ConditionFalse))
	})

	It("should use the config's generation for ObservedGeneration", func() {
		config.Generation = 5
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionTrue, "Ok", "ok")

		Expect(config.Status.Conditions[0].ObservedGeneration).To(Equal(int64(5)))
	})

	It("should set all three conditions for a failed deploy scenario", func() {
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionFalse, "DeployFailed", "err")
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionDegraded, metav1.ConditionTrue, "DeployFailed", "err")
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReconciling, metav1.ConditionFalse, "ReconcileFailed", "err")

		types := map[string]metav1.ConditionStatus{}
		for _, c := range config.Status.Conditions {
			types[c.Type] = c.Status
		}
		Expect(types).To(HaveKeyWithValue("Ready", metav1.ConditionFalse))
		Expect(types).To(HaveKeyWithValue("Degraded", metav1.ConditionTrue))
		Expect(types).To(HaveKeyWithValue("Reconciling", metav1.ConditionFalse))
	})

	It("should transition from degraded to healthy", func() {
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionFalse, "DeployFailed", "broken")
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionDegraded, metav1.ConditionTrue, "DeployFailed", "broken")

		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionReady, metav1.ConditionTrue, "ReconcileSucceeded", "recovered")
		r.setCondition(config, automotivev1alpha1.OperatorConfigConditionDegraded, metav1.ConditionFalse, "ReconcileSucceeded", "recovered")

		types := map[string]metav1.ConditionStatus{}
		for _, c := range config.Status.Conditions {
			types[c.Type] = c.Status
		}
		Expect(types).To(HaveKeyWithValue("Ready", metav1.ConditionTrue))
		Expect(types).To(HaveKeyWithValue("Degraded", metav1.ConditionFalse))
	})
})
