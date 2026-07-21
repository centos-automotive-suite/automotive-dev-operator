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

package catalogimage

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func TestResolvedExportFormatForCatalog(t *testing.T) {
	tests := []struct {
		name         string
		spec         automotivev1alpha1.ImageBuildSpec
		statusFormat string
		wantFormat   string
		wantBootc    bool
	}{
		{
			name: "container push build shows oci format",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Mode: "bootc"},
				Export: &automotivev1alpha1.ExportSpec{
					Container: "quay.io/test/img:latest",
					Format:    "qcow2",
				},
			},
			statusFormat: "qcow2",
			wantFormat:   "oci",
			wantBootc:    true,
		},
		{
			name: "disk-only build shows resolved format",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Mode: "image"},
				Export: &automotivev1alpha1.ExportSpec{
					Format: "simg",
					Disk:   &automotivev1alpha1.DiskExport{OCI: "quay.io/test/disk:latest"},
				},
			},
			statusFormat: "simg",
			wantFormat:   "simg",
			wantBootc:    false,
		},
		{
			name: "disk-only build uses status resolved format over spec",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Mode: "image"},
				Export: &automotivev1alpha1.ExportSpec{
					Format: "qcow2",
					Disk:   &automotivev1alpha1.DiskExport{OCI: "quay.io/test/disk:latest"},
				},
			},
			statusFormat: "simg",
			wantFormat:   "simg",
			wantBootc:    false,
		},
		{
			name: "image mode with container push still shows oci",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Mode: "image"},
				Export: &automotivev1alpha1.ExportSpec{
					Container: "quay.io/test/img:latest",
					Format:    "simg",
				},
			},
			statusFormat: "simg",
			wantFormat:   "oci",
			wantBootc:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ib := &automotivev1alpha1.ImageBuild{
				Spec:   tt.spec,
				Status: automotivev1alpha1.ImageBuildStatus{ResolvedExportFormat: tt.statusFormat},
			}

			exportFormat := resolvedExportFormat(ib)
			if ib.Spec.GetContainerPush() != "" {
				exportFormat = "oci"
			}

			if exportFormat != tt.wantFormat {
				t.Errorf("ExportFormat = %q, want %q", exportFormat, tt.wantFormat)
			}

			bootc := ib.Spec.GetMode() == "bootc"
			if bootc != tt.wantBootc {
				t.Errorf("Bootc = %v, want %v", bootc, tt.wantBootc)
			}
		})
	}
}
