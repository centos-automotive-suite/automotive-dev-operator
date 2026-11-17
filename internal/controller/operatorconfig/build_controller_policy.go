package operatorconfig

import (
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func buildControllerWorkloadPolicyName(namespace string) string {
	return "ado-build-controller-workloads-" + namespace
}

// buildBuildControllerWorkloadPolicy limits the ServiceAccounts the build
// controller may run workloads as. RBAC lets it create pods and Tekton and
// Shipwright runs but cannot say which ServiceAccount they use, so without
// this it could start one as the operator and take its permissions.
func (r *OperatorConfigReconciler) buildBuildControllerWorkloadPolicy(namespace string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	controllerUser := "system:serviceaccount:" + namespace + ":" + automotivev1alpha1.BuildControllerServiceAccountName
	rule := func(group, version string, resources ...string) admissionregistrationv1.NamedRuleWithOperations {
		return admissionregistrationv1.NamedRuleWithOperations{
			RuleWithOperations: admissionregistrationv1.RuleWithOperations{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
				Rule: admissionregistrationv1.Rule{
					APIGroups: []string{group}, APIVersions: []string{version}, Resources: resources,
				},
			},
		}
	}
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: buildControllerWorkloadPolicyName(namespace),
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: ptr.To(admissionregistrationv1.Fail),
			// Requests in other versions are converted to these, so the
			// field paths below hold for all of them.
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule("", "v1", "pods"),
					rule("tekton.dev", "v1", "taskruns", "pipelineruns"),
					rule("shipwright.io", "v1beta1", "buildruns"),
				},
			},
			MatchConditions: []admissionregistrationv1.MatchCondition{{
				Name:       "build-controller",
				Expression: fmt.Sprintf("request.userInfo.username == %q", controllerUser),
			}},
			Variables: []admissionregistrationv1.Variable{
				// An empty name leaves the choice to the cluster: the pod's
				// namespace default, or Tekton's configured default.
				{Name: "allowed", Expression: fmt.Sprintf("['', 'default', %q, %q]",
					automotivev1alpha1.BuildServiceAccountName, workspaceServiceAccountName)},
				{Name: "serviceAccounts", Expression: "request.resource.resource == 'pipelineruns' ? " +
					"[object.spec.?taskRunTemplate.?serviceAccountName.orValue('')] + " +
					"object.spec.?taskRunSpecs.orValue([]).map(s, s.?serviceAccountName.orValue('')) : " +
					"request.resource.resource == 'buildruns' ? [object.spec.?serviceAccount.orValue('')] : " +
					"request.resource.resource == 'pods' ? " +
					"[object.spec.?serviceAccountName.orValue(''), object.spec.?serviceAccount.orValue('')] : " +
					"[object.spec.?serviceAccountName.orValue('')]"},
			},
			Validations: []admissionregistrationv1.Validation{{
				Expression: "variables.serviceAccounts.all(sa, sa in variables.allowed)",
				Message: fmt.Sprintf("the build controller may only run workloads as %s or %s",
					automotivev1alpha1.BuildServiceAccountName, workspaceServiceAccountName),
			}},
		},
	}
}

// buildBuildControllerWorkloadPolicyBinding enforces the workload policy in
// the operator's namespace only.
func (r *OperatorConfigReconciler) buildBuildControllerWorkloadPolicyBinding(namespace string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	name := buildControllerWorkloadPolicyName(namespace)
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        name,
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
			MatchResources: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": namespace},
				},
			},
		},
	}
}
