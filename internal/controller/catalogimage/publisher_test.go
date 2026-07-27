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
	"context"
	"testing"

	"github.com/containers/image/v5/types"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func TestBuildCatalogImage_ScheduleNameLabel(t *testing.T) {
	p := &Publisher{log: logr.Discard()}

	t.Run("sets schedule name label when provided", func(t *testing.T) {
		ci := p.buildCatalogImage(PublishOptions{
			Name:         "test-img",
			Namespace:    "default",
			RegistryURL:  "quay.io/test:latest",
			Source:       PublishSourceScheduled,
			ScheduleName: "nightly-autosd-qemu",
		})

		got := ci.Labels[automotivev1alpha1.LabelScheduledImageBuildName]
		if got != "nightly-autosd-qemu" {
			t.Errorf("expected schedule label %q, got %q", "nightly-autosd-qemu", got)
		}
	})

	t.Run("omits schedule name label when empty", func(t *testing.T) {
		ci := p.buildCatalogImage(PublishOptions{
			Name:        "test-img",
			Namespace:   "default",
			RegistryURL: "quay.io/test:latest",
			Source:      PublishSourceManual,
		})

		if _, ok := ci.Labels[automotivev1alpha1.LabelScheduledImageBuildName]; ok {
			t.Error("schedule label should not be set for manual publishes")
		}
	})
}

type stubRegistryClient struct{}

func (s *stubRegistryClient) VerifyImageAccessible(_ context.Context, _ string, _ *types.DockerAuthConfig) (bool, error) {
	return true, nil
}

func (s *stubRegistryClient) GetImageMetadata(_ context.Context, _ string, _ *types.DockerAuthConfig) (*automotivev1alpha1.RegistryMetadata, error) {
	return &automotivev1alpha1.RegistryMetadata{SizeBytes: 1024}, nil
}

func (s *stubRegistryClient) VerifyDigest(_ context.Context, _ string, _ string, _ *types.DockerAuthConfig) (bool, string, error) {
	return true, "sha256:abc123", nil
}

func newFakePublisherWithRegistry(objs ...client.Object) *Publisher {
	scheme := newPublisherTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&automotivev1alpha1.CatalogImage{}).
		WithIndex(&automotivev1alpha1.CatalogImage{}, "spec.registryUrl", func(o client.Object) []string {
			ci := o.(*automotivev1alpha1.CatalogImage)
			return []string{ci.Spec.RegistryURL}
		}).
		Build()
	return NewPublisher(c, &stubRegistryClient{}, nil, logr.Discard())
}

func TestPublishFromImageBuild_PropagatesScheduleName(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nightly-autosd-qemu-abc123",
			Namespace: "default",
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-autosd-qemu",
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			AIB: &automotivev1alpha1.AIBSpec{Mode: "bootc"},
			Export: &automotivev1alpha1.ExportSpec{
				Container: "quay.io/test/img:latest",
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: "Completed"},
	}

	pub := newFakePublisherWithRegistry()
	res, err := pub.PublishFromImageBuild(context.Background(), ib, "", nil, nil, PublishSourceScheduled)
	if err != nil {
		t.Fatalf("PublishFromImageBuild() error: %v", err)
	}
	if got := res.CatalogImage.Labels[automotivev1alpha1.LabelScheduledImageBuildName]; got != "nightly-autosd-qemu" {
		t.Errorf("expected schedule label propagated, got %q", got)
	}
}

func newPublisherTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(automotivev1alpha1.AddToScheme(s))
	return s
}

func newFakePublisher(objs ...client.Object) *Publisher {
	scheme := newPublisherTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&automotivev1alpha1.CatalogImage{}).
		WithIndex(&automotivev1alpha1.CatalogImage{}, "spec.registryUrl", func(o client.Object) []string {
			ci := o.(*automotivev1alpha1.CatalogImage)
			return []string{ci.Spec.RegistryURL}
		}).
		Build()
	return NewPublisher(c, nil, nil, logr.Discard())
}

func TestPublish_UpdatesExistingOnDuplicateRegistryURL(t *testing.T) {
	existing := &automotivev1alpha1.CatalogImage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "old-build-xyz",
			Namespace: "default",
			Labels: map[string]string{
				automotivev1alpha1.LabelScheduledImageBuildName: "nightly-qemu",
				automotivev1alpha1.LabelSourceType:              string(PublishSourceScheduled),
			},
		},
		Spec: automotivev1alpha1.CatalogImageSpec{
			RegistryURL: "quay.io/test/img:nightly",
			Tags:        []string{"old-tag"},
			Metadata: &automotivev1alpha1.CatalogImageMetadata{
				Architecture: "x86_64",
				Distro:       "autosd",
			},
		},
	}

	pub := newFakePublisher(existing)

	result, err := pub.Publish(context.Background(), PublishOptions{
		Name:        "new-build-abc",
		Namespace:   "default",
		RegistryURL: "quay.io/test/img:nightly",
		Tags:        []string{"updated-tag"},
		Source:      PublishSourceScheduled,
		Metadata: &automotivev1alpha1.CatalogImageMetadata{
			Architecture: "aarch64",
			Distro:       "autosd",
		},
		ScheduleName:         "nightly-qemu",
		SourceImageBuildName: "new-build-abc",
	})
	if err != nil {
		t.Fatalf("Publish() error: %v", err)
	}

	if result.CatalogImage.Name != "old-build-xyz" {
		t.Errorf("expected existing CatalogImage name %q, got %q", "old-build-xyz", result.CatalogImage.Name)
	}
	if len(result.CatalogImage.Spec.Tags) != 1 || result.CatalogImage.Spec.Tags[0] != "updated-tag" {
		t.Errorf("expected tags [updated-tag], got %v", result.CatalogImage.Spec.Tags)
	}
	if result.CatalogImage.Spec.Metadata.Architecture != "aarch64" {
		t.Errorf("expected arch aarch64, got %q", result.CatalogImage.Spec.Metadata.Architecture)
	}
}

func TestPublish_CreatesNewWhenNoExisting(t *testing.T) {
	pub := newFakePublisher()

	result, err := pub.Publish(context.Background(), PublishOptions{
		Name:        "fresh-build",
		Namespace:   "default",
		RegistryURL: "quay.io/test/img:v1",
		Tags:        []string{"release"},
		Source:      PublishSourceManual,
		Metadata: &automotivev1alpha1.CatalogImageMetadata{
			Architecture: "x86_64",
			Distro:       "autosd",
		},
	})
	if err != nil {
		t.Fatalf("Publish() error: %v", err)
	}

	if result.CatalogImage.Name != "fresh-build" {
		t.Errorf("expected name %q, got %q", "fresh-build", result.CatalogImage.Name)
	}
}

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
