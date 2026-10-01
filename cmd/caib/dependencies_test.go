package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Keep CLI dependencies on the shared wire contract and API client. Importing
// the server package brings cluster and controller dependencies into the CLI.
func TestCLIExcludesBuildAPIServer(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./...")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list CLI dependencies: %v\n%s", err, out)
	}
	const serverPackage = "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	for dependency := range strings.FieldsSeq(string(out)) {
		if strings.HasPrefix(dependency, serverPackage) && dependency != serverPackage+"/client" {
			t.Fatalf("CLI imports server package %s", dependency)
		}
	}
}
