package imagebuild

import (
	"context"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestExtractImageStreamName(t *testing.T) {
	tests := []struct {
		name     string
		build    *automotivev1alpha1.ImageBuild
		wantName string
	}{
		{
			name:     "no export spec",
			build:    &automotivev1alpha1.ImageBuild{},
			wantName: "",
		},
		{
			name: "export without internal registry",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Container: "quay.io/myorg/myimage:latest",
					},
				},
			},
			wantName: "",
		},
		{
			name: "container push to internal registry",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Container:             tasks.DefaultInternalRegistryURL + "/test-ns/myimage:bootc",
						UseServiceAccountAuth: true,
					},
				},
			},
			wantName: "myimage",
		},
		{
			name: "disk OCI export to internal registry",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						UseServiceAccountAuth: true,
						Disk: &automotivev1alpha1.DiskExport{
							OCI: tasks.DefaultInternalRegistryURL + "/test-ns/diskimage:disk",
						},
					},
				},
			},
			wantName: "diskimage",
		},
		{
			name: "both container and disk point to same stream",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Container:             tasks.DefaultInternalRegistryURL + "/test-ns/shared:bootc",
						UseServiceAccountAuth: true,
						Disk: &automotivev1alpha1.DiskExport{
							OCI: tasks.DefaultInternalRegistryURL + "/test-ns/shared:disk",
						},
					},
				},
			},
			wantName: "shared",
		},
		{
			name: "URL without tag",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Container:             tasks.DefaultInternalRegistryURL + "/test-ns/notag",
						UseServiceAccountAuth: true,
					},
				},
			},
			wantName: "notag",
		},
		{
			name: "URL with only namespace, no stream name",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Container:             tasks.DefaultInternalRegistryURL + "/test-ns/",
						UseServiceAccountAuth: true,
					},
				},
			},
			wantName: "",
		},
		{
			name: "URL with no namespace separator",
			build: &automotivev1alpha1.ImageBuild{
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Container:             tasks.DefaultInternalRegistryURL + "/bare",
						UseServiceAccountAuth: true,
					},
				},
			},
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractImageStreamName(tt.build)
			if got != tt.wantName {
				t.Errorf("extractImageStreamName() = %q, want %q", got, tt.wantName)
			}
		})
	}
}

// newTestSchemeWithImageStream creates a scheme with the CRD types and registers
// the ImageStream GVK so the fake client can work with unstructured ImageStreams.
func newTestSchemeWithImageStream() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(automotivev1alpha1.AddToScheme(s))

	// Register ImageStream GVK so the fake client knows how to handle it.
	// We use unstructured objects (no Go types for image.openshift.io), so
	// we need to tell the scheme about the GVR→GVK mapping.
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"},
		&unstructured.Unstructured{},
	)
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStreamList"},
		&unstructured.UnstructuredList{},
	)

	return s
}

func newImageStream(name string) *unstructured.Unstructured {
	const namespace = "test-ns"
	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})
	is.SetName(name)
	is.SetNamespace(namespace)
	is.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by":              "build-api",
		"automotive.sdv.cloud.redhat.com/transient": "true",
	})
	return is
}

func newImageBuildWithInternalRegistry(buildName, imageName, tag string) *automotivev1alpha1.ImageBuild {
	const namespace = "test-ns"
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildName,
			Namespace: namespace,
			UID:       types.UID(buildName + "-uid"),
		},
		TypeMeta: metav1.TypeMeta{
			APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
			Kind:       "ImageBuild",
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Export: &automotivev1alpha1.ExportSpec{
				Container:             tasks.DefaultInternalRegistryURL + "/" + namespace + "/" + imageName + ":" + tag,
				UseServiceAccountAuth: true,
			},
		},
	}
}

func TestEnsureImageStreamOwnerRef(t *testing.T) {
	const ns = "test-ns"

	t.Run("sets owner reference on existing ImageStream", func(t *testing.T) {
		scheme := newTestSchemeWithImageStream()
		is := newImageStream("myimage")
		build := newImageBuildWithInternalRegistry("build-1", "myimage", "bootc")

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(is).
			Build()

		r := &ImageBuildReconciler{
			Client: client,
			Scheme: scheme,
			Log:    ctrl.Log.WithName("test"),
		}

		if err := r.ensureImageStreamOwnerRef(context.Background(), build); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef() returned unexpected error: %v", err)
		}

		// Fetch the ImageStream and verify owner reference was set
		updated := &unstructured.Unstructured{}
		updated.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		if err := client.Get(context.Background(), types.NamespacedName{
			Name: "myimage", Namespace: ns,
		}, updated); err != nil {
			t.Fatalf("failed to get ImageStream: %v", err)
		}

		refs := updated.GetOwnerReferences()
		if len(refs) != 1 {
			t.Fatalf("expected 1 owner reference, got %d", len(refs))
		}
		if refs[0].Name != "build-1" {
			t.Errorf("owner ref name = %q, want %q", refs[0].Name, "build-1")
		}
		if refs[0].UID != build.UID {
			t.Errorf("owner ref UID = %q, want %q", refs[0].UID, build.UID)
		}
		if refs[0].Controller != nil && *refs[0].Controller {
			t.Error("owner ref should NOT be a controller reference")
		}
	})

	t.Run("multiple builds co-own the same ImageStream", func(t *testing.T) {
		scheme := newTestSchemeWithImageStream()
		is := newImageStream("shared")
		build1 := newImageBuildWithInternalRegistry("build-1", "shared", "bootc")
		build2 := newImageBuildWithInternalRegistry("build-2", "shared", "disk")

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(is).
			Build()

		r := &ImageBuildReconciler{
			Client: client,
			Scheme: scheme,
			Log:    ctrl.Log.WithName("test"),
		}

		if err := r.ensureImageStreamOwnerRef(context.Background(), build1); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef(build1) returned unexpected error: %v", err)
		}
		if err := r.ensureImageStreamOwnerRef(context.Background(), build2); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef(build2) returned unexpected error: %v", err)
		}

		updated := &unstructured.Unstructured{}
		updated.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		if err := client.Get(context.Background(), types.NamespacedName{
			Name: "shared", Namespace: ns,
		}, updated); err != nil {
			t.Fatalf("failed to get ImageStream: %v", err)
		}

		refs := updated.GetOwnerReferences()
		if len(refs) != 2 {
			t.Fatalf("expected 2 owner references, got %d", len(refs))
		}

		names := map[string]bool{}
		for _, ref := range refs {
			names[ref.Name] = true
			if ref.Controller != nil && *ref.Controller {
				t.Errorf("owner ref for %q should NOT be a controller reference", ref.Name)
			}
		}
		if !names["build-1"] || !names["build-2"] {
			t.Errorf("expected owner refs from build-1 and build-2, got %v", names)
		}
	})

	t.Run("idempotent — calling twice does not duplicate", func(t *testing.T) {
		scheme := newTestSchemeWithImageStream()
		is := newImageStream("myimage")
		build := newImageBuildWithInternalRegistry("build-1", "myimage", "bootc")

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(is).
			Build()

		r := &ImageBuildReconciler{
			Client: client,
			Scheme: scheme,
			Log:    ctrl.Log.WithName("test"),
		}

		if err := r.ensureImageStreamOwnerRef(context.Background(), build); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef() returned unexpected error: %v", err)
		}
		if err := r.ensureImageStreamOwnerRef(context.Background(), build); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef() returned unexpected error: %v", err)
		}

		updated := &unstructured.Unstructured{}
		updated.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		if err := client.Get(context.Background(), types.NamespacedName{
			Name: "myimage", Namespace: ns,
		}, updated); err != nil {
			t.Fatalf("failed to get ImageStream: %v", err)
		}

		refs := updated.GetOwnerReferences()
		if len(refs) != 1 {
			t.Fatalf("expected 1 owner reference after double-call, got %d", len(refs))
		}
	})

	t.Run("no-op when build does not use internal registry", func(t *testing.T) {
		scheme := newTestSchemeWithImageStream()
		is := newImageStream("myimage")
		build := &automotivev1alpha1.ImageBuild{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "external-build",
				Namespace: ns,
				UID:       "ext-uid",
			},
			Spec: automotivev1alpha1.ImageBuildSpec{
				Export: &automotivev1alpha1.ExportSpec{
					Container: "quay.io/myorg/myimage:latest",
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(is).
			Build()

		r := &ImageBuildReconciler{
			Client: client,
			Scheme: scheme,
			Log:    ctrl.Log.WithName("test"),
		}

		if err := r.ensureImageStreamOwnerRef(context.Background(), build); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef() returned unexpected error: %v", err)
		}

		updated := &unstructured.Unstructured{}
		updated.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		if err := client.Get(context.Background(), types.NamespacedName{
			Name: "myimage", Namespace: ns,
		}, updated); err != nil {
			t.Fatalf("failed to get ImageStream: %v", err)
		}

		refs := updated.GetOwnerReferences()
		if len(refs) != 0 {
			t.Errorf("expected no owner references for external build, got %d", len(refs))
		}
	})

	t.Run("graceful when ImageStream does not exist", func(_ *testing.T) {
		scheme := newTestSchemeWithImageStream()
		build := newImageBuildWithInternalRegistry("build-1", "nonexistent", "bootc")

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		r := &ImageBuildReconciler{
			Client: client,
			Scheme: scheme,
			Log:    ctrl.Log.WithName("test"),
		}

		// Should not panic or return error — just logs and returns
		if err := r.ensureImageStreamOwnerRef(context.Background(), build); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef() returned unexpected error: %v", err)
		}
	})

	t.Run("owner ref set from disk OCI export URL", func(t *testing.T) {
		scheme := newTestSchemeWithImageStream()
		is := newImageStream("diskonly")
		build := &automotivev1alpha1.ImageBuild{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "disk-build",
				Namespace: ns,
				UID:       "disk-uid",
			},
			TypeMeta: metav1.TypeMeta{
				APIVersion: "automotive.sdv.cloud.redhat.com/v1alpha1",
				Kind:       "ImageBuild",
			},
			Spec: automotivev1alpha1.ImageBuildSpec{
				Export: &automotivev1alpha1.ExportSpec{
					UseServiceAccountAuth: true,
					Disk: &automotivev1alpha1.DiskExport{
						OCI: tasks.DefaultInternalRegistryURL + "/" + ns + "/diskonly:disk",
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(is).
			Build()

		r := &ImageBuildReconciler{
			Client: client,
			Scheme: scheme,
			Log:    ctrl.Log.WithName("test"),
		}

		if err := r.ensureImageStreamOwnerRef(context.Background(), build); err != nil {
			t.Fatalf("ensureImageStreamOwnerRef() returned unexpected error: %v", err)
		}

		updated := &unstructured.Unstructured{}
		updated.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		if err := client.Get(context.Background(), types.NamespacedName{
			Name: "diskonly", Namespace: ns,
		}, updated); err != nil {
			t.Fatalf("failed to get ImageStream: %v", err)
		}

		refs := updated.GetOwnerReferences()
		if len(refs) != 1 {
			t.Fatalf("expected 1 owner reference, got %d", len(refs))
		}
		if refs[0].Name != "disk-build" {
			t.Errorf("owner ref name = %q, want %q", refs[0].Name, "disk-build")
		}
	})
}
