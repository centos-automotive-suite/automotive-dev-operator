package buildapi

import (
	"reflect"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestAppendWorkspaceRepoCustomDefs(t *testing.T) {
	req := &buildcontract.BuildRequest{CustomDefs: []string{"existing=value"}}
	reposJSON := []byte(`[{"id":"workspace-kernel-build","baseurl":"http://10.0.0.1:8080"}]`)

	appendWorkspaceRepoCustomDefs(req, reposJSON)

	want := []string{
		"existing=value",
		`extra_repos=[{"id":"workspace-kernel-build","baseurl":"http://10.0.0.1:8080"}]`,
		`extra_build_repos=[{"id":"workspace-kernel-build","baseurl":"http://10.0.0.1:8080"}]`,
	}
	if !reflect.DeepEqual(req.CustomDefs, want) {
		t.Fatalf("CustomDefs = %#v, want %#v", req.CustomDefs, want)
	}
}
