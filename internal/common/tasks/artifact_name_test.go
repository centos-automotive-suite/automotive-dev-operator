package tasks

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExportFileNameUsesArtifactName(t *testing.T) {
	naming := shellFunctions(t, buildImageScript, "SAFE_DISTRO=", "\ndetect_stat_command")
	for _, tc := range []struct{ name, artifactName, format, want string }{
		{"defaults to distro and target", "", "qcow2", "autosd-ride4_sa8775p_sx.qcow2"},
		{"artifact name replaces the base name", "auto-osbuild-qemu-autosd10-qa-regular@debug-x86_64-1.abc", "raw", "auto-osbuild-qemu-autosd10-qa-regular@debug-x86_64-1.abc.raw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", naming+"\necho \"$EXPORT_FILE\"")
			cmd.Env = append(os.Environ(), "DISTRO=autosd", "TARGET=ride4_sa8775p_sx", "EXPORT_FORMAT="+tc.format, "ARTIFACT_NAME="+tc.artifactName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("naming failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Errorf("EXPORT_FILE = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestArtifactNameTaskPlumbing(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")
	declared := false
	for _, param := range task.Spec.Params {
		if param.Name == "artifact-name" {
			declared = param.Default != nil && param.Default.StringVal == ""
		}
	}
	if !declared {
		t.Error("build task must declare artifact-name with an empty default")
	}

	pipeline := GenerateTektonPipeline("test", "test-ns", nil)
	declared = false
	for _, param := range pipeline.Spec.Params {
		if param.Name == "artifact-name" {
			declared = param.Default != nil && param.Default.StringVal == ""
		}
	}
	if !declared {
		t.Error("pipeline must declare artifact-name with an empty default")
	}
	for i := range pipeline.Spec.Tasks {
		if pipeline.Spec.Tasks[i].Name != "build-image" {
			continue
		}
		if got, ok := taskParamBinding(&pipeline.Spec.Tasks[i], "artifact-name"); !ok || got != "$(params.artifact-name)" {
			t.Fatalf("build-image artifact-name binding = %q, present=%t", got, ok)
		}
		return
	}
	t.Fatal("pipeline has no build-image task")
}
