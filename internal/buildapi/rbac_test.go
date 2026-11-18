package buildapi

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// generatedRules returns every rule in the role `make manifests` generates from
// the markers in rbac.go.
func generatedRules(t *testing.T) []rbacv1.PolicyRule {
	t.Helper()
	data, err := os.ReadFile("../../config/rbac/build-api/role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rules []rbacv1.PolicyRule
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		// Role and ClusterRole share the rules field.
		var role rbacv1.Role
		err := decoder.Decode(&role)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, role.Rules...)
	}
	if len(rules) == 0 {
		t.Fatal("no rules in the generated role")
	}
	return rules
}

// The build API serves any authenticated user, so a hole in it must not reach
// what the operator can do.
func TestBuildAPIRoleCannotWidenItsRights(t *testing.T) {
	forbiddenGroups := []string{"*", "rbac.authorization.k8s.io", "security.openshift.io", "admissionregistration.k8s.io", "apps"}
	forbiddenResources := []string{"*", "serviceaccounts", "pods/attach", "pods/ephemeralcontainers"}
	forbiddenVerbs := []string{"*", "escalate", "bind", "impersonate"}
	for _, rule := range generatedRules(t) {
		for _, group := range rule.APIGroups {
			if slices.Contains(forbiddenGroups, group) {
				t.Errorf("rule grants API group %q: %+v", group, rule)
			}
		}
		for _, resource := range rule.Resources {
			if slices.Contains(forbiddenResources, resource) {
				t.Errorf("rule grants resource %q: %+v", resource, rule)
			}
		}
		for _, verb := range rule.Verbs {
			if slices.Contains(forbiddenVerbs, verb) {
				t.Errorf("rule grants verb %q: %+v", verb, rule)
			}
		}
		if slices.Contains(rule.Resources, "serviceaccounts/token") {
			want := []string{automotivev1alpha1.RegistryServiceAccountName, automotivev1alpha1.RegistryPullServiceAccountName}
			if !slices.Equal(rule.ResourceNames, want) {
				t.Errorf("token rule names %v, want only the registry accounts %v", rule.ResourceNames, want)
			}
		}
	}
}

// The build API reads Secrets and ConfigMaps by name. A list or watch of the
// namespace would read every one, including other components' credentials.
func TestBuildAPIRoleReadsSecretsAndConfigMapsOnlyByName(t *testing.T) {
	for _, rule := range generatedRules(t) {
		if !slices.Contains(rule.Resources, "secrets") && !slices.Contains(rule.Resources, "configmaps") {
			continue
		}
		for _, verb := range []string{"list", "watch"} {
			if slices.Contains(rule.Verbs, verb) {
				t.Errorf("rule grants %s on %v: %+v", verb, rule.Resources, rule)
			}
		}
	}
}
