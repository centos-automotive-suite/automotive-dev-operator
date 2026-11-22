package operatorconfig

import (
	"fmt"
	"strings"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func workloadAccountsPolicyName(namespace string) string {
	return "ado-workload-accounts-" + namespace
}

// buildWorkloadAccountsPolicy limits the ServiceAccounts the build controller
// and the build API may run workloads as. RBAC lets them create pods and
// Tekton and Shipwright runs but cannot say which ServiceAccount those use, so
// without this either could start one as the operator and take its
// permissions. Both may create Secrets, so they may not create the type that
// Kubernetes fills with a token for the ServiceAccount it names. Nor can RBAC
// say which pod an exec reaches, and the operator's pod holds its token, so
// they may exec only into a build's source-local step, the Shipwright waiter
// the build API streams container build context into.
func (r *OperatorConfigReconciler) buildWorkloadAccountsPolicy(namespace string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	// The policy checks the account each workload will run as, where the
	// request shows it. Before the policy sees them, the API server gives a pod
	// naming no account its namespace's default, and Tekton's webhook gives a
	// run naming none its configured default (default upstream, pipeline on
	// OpenShift Pipelines). Shipwright picks a BuildRun's account only later,
	// pipeline if there is one, so a BuildRun naming none is refused.
	accounts := []string{automotivev1alpha1.BuildServiceAccountName, workspaceServiceAccountName, "default"}
	users := fmt.Sprintf("[%q, %q]",
		"system:serviceaccount:"+namespace+":"+automotivev1alpha1.BuildControllerServiceAccountName,
		"system:serviceaccount:"+namespace+":"+automotivev1alpha1.BuildAPIServiceAccountName)
	write := []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
	connect := []admissionregistrationv1.OperationType{admissionregistrationv1.Connect}
	rule := func(operations []admissionregistrationv1.OperationType, group, version string, resources ...string) admissionregistrationv1.NamedRuleWithOperations {
		return admissionregistrationv1.NamedRuleWithOperations{
			RuleWithOperations: admissionregistrationv1.RuleWithOperations{
				Operations: operations,
				Rule: admissionregistrationv1.Rule{
					APIGroups: []string{group}, APIVersions: []string{version}, Resources: resources,
				},
			},
		}
	}
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: workloadAccountsPolicyName(namespace),
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: ptr.To(admissionregistrationv1.Fail),
			// Requests in other versions are converted to these, so the
			// field paths below hold for all of them.
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule(write, "", "v1", "pods", "secrets"),
					rule(write, "tekton.dev", "v1", "taskruns", "pipelineruns"),
					rule(write, "shipwright.io", "v1beta1", "buildruns"),
					rule(connect, "", "v1", "pods/exec"),
				},
			},
			MatchConditions: []admissionregistrationv1.MatchCondition{{
				Name:       "build-workload-creators",
				Expression: "request.userInfo.username in " + users,
			}},
			Variables: []admissionregistrationv1.Variable{
				{Name: "allowed", Expression: "['" + strings.Join(accounts, "', '") + "']"},
				// The only CONNECT matched is exec, whose object is its
				// PodExecOptions.
				{Name: "exec", Expression: "request.operation == 'CONNECT'"},
				{Name: "serviceAccounts", Expression: "variables.exec || request.resource.resource == 'secrets' ? [] : " +
					"request.resource.resource == 'pipelineruns' ? " +
					"[object.spec.?taskRunTemplate.?serviceAccountName.orValue('')] + " +
					// A task naming no account runs as the template's.
					"object.spec.?taskRunSpecs.orValue([]).map(s, s.?serviceAccountName.orValue('')).filter(sa, sa != '') : " +
					"request.resource.resource == 'buildruns' ? [object.spec.?serviceAccount.orValue('')] : " +
					"request.resource.resource == 'pods' ? " +
					"[object.spec.?serviceAccountName.orValue(''), object.spec.?serviceAccount.orValue('')] : " +
					"[object.spec.?serviceAccountName.orValue('')]"},
			},
			Validations: []admissionregistrationv1.Validation{
				{
					Expression: "variables.serviceAccounts.all(sa, sa in variables.allowed)",
					Message:    "build workloads may only run as " + strings.Join(accounts, ", "),
				},
				{
					Expression: fmt.Sprintf("request.resource.resource != 'secrets' || object.?type.orValue('') != %q",
						corev1.SecretTypeServiceAccountToken),
					Message: "ServiceAccount token Secrets may not be created here",
				},
				{
					// Naming no container picks the pod's first.
					Expression: "!variables.exec || object.?container.orValue('').contains('source-local')",
					Message:    "exec is only allowed into a build's source-local step",
				},
			},
		},
	}
}

// buildWorkloadAccountsPolicyBinding enforces the workload policy in
// the operator's namespace only.
func (r *OperatorConfigReconciler) buildWorkloadAccountsPolicyBinding(namespace string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	name := workloadAccountsPolicyName(namespace)
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build",
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
