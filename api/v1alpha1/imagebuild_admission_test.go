package v1alpha1

import (
	"os"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestImageBuildDiskPushSecretAdmission checks against a real API server that
// a disk OCI export is only admitted with the Secret its push mounts.
func TestImageBuildDiskPushSecretAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS or run make test for CRD admission tests")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{getCRDPath()}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	const internalDisk = "image-registry.openshift-image-registry.svc:5000/default/demo:disk"
	const missingPushSecret = "pushSecretRef is required when export.disk.oci is set"
	for _, tc := range []struct {
		name    string
		spec    ImageBuildSpec
		wantErr string
	}{
		{
			name: "hybrid push with both Secrets",
			spec: ImageBuildSpec{
				SecretRef:     "demo-external-registry-auth",
				PushSecretRef: "demo-internal-registry-auth",
				Export: &ExportSpec{
					UseServiceAccountAuth: true,
					Container:             "ghcr.io/example/demo:latest",
					Disk:                  &DiskExport{OCI: internalDisk},
				},
			},
		},
		{
			name: "disk push with only the build Secret",
			spec: ImageBuildSpec{
				SecretRef: "demo-registry-auth",
				Export:    &ExportSpec{Disk: &DiskExport{OCI: "quay.io/example/demo:disk"}},
			},
			wantErr: missingPushSecret,
		},
		{
			name: "internal disk push without a Secret",
			spec: ImageBuildSpec{
				Export: &ExportSpec{UseServiceAccountAuth: true, Disk: &DiskExport{OCI: internalDisk}},
			},
			wantErr: missingPushSecret,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := &ImageBuild{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "demo-", Namespace: "default"},
				Spec:       tc.spec,
			}
			err := k8s.Create(t.Context(), build)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid build rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || strings.Contains(err.Error(), "no such key") {
				t.Fatalf("admission error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
