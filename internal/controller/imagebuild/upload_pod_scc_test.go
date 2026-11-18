package imagebuild

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// The upload pod runs as its namespace's default account with a fixed
// non-root UID, which OpenShift's restricted-v2 SCC refuses. A pod may use any
// SCC its creator may, so the build controller needs nonroot-v2, and no more.
func TestBuildControllerMayUseOnlyTheNonRootSCC(t *testing.T) {
	data, err := os.ReadFile("../../../config/rbac/build-controller/role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var sccRules []rbacv1.PolicyRule
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
		for _, rule := range role.Rules {
			if slices.Contains(rule.APIGroups, "security.openshift.io") {
				sccRules = append(sccRules, rule)
			}
		}
	}
	want := rbacv1.PolicyRule{
		APIGroups:     []string{"security.openshift.io"},
		Resources:     []string{"securitycontextconstraints"},
		ResourceNames: []string{"nonroot-v2"},
		Verbs:         []string{"use"},
	}
	if !reflect.DeepEqual(sccRules, []rbacv1.PolicyRule{want}) {
		t.Fatalf("SCC rules = %+v, want only %+v", sccRules, want)
	}
}
