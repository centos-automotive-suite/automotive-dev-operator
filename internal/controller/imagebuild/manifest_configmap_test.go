package imagebuild

import (
	"context"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	return scheme
}

func TestCreateOrUpdateManifestConfigMap(t *testing.T) {
	tests := []struct {
		name             string
		imageBuild       *automotivev1alpha1.ImageBuild
		wantCMName       string
		wantManifestKey  string
		wantManifestData string
		wantCustomDefs   string
		wantExtraArgs    string
		wantErr          bool
	}{
		{
			name: "creates ConfigMap with manifest content",
			imageBuild: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-build",
					Namespace: "default",
					UID:       "test-uid-1",
				},
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB: &automotivev1alpha1.AIBSpec{
						Manifest:         "name: test-image\npackages:\n  - vim\n",
						ManifestFileName: "test.aib.yml",
					},
				},
			},
			wantCMName:       "my-build-manifest",
			wantManifestKey:  "test.aib.yml",
			wantManifestData: "name: test-image\npackages:\n  - vim\n",
		},
		{
			name: "uses default filename when not specified",
			imageBuild: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "build-no-filename",
					Namespace: "default",
					UID:       "test-uid-2",
				},
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB: &automotivev1alpha1.AIBSpec{
						Manifest: "name: default-test\n",
					},
				},
			},
			wantCMName:       "build-no-filename-manifest",
			wantManifestKey:  "manifest.aib.yml",
			wantManifestData: "name: default-test\n",
		},
		{
			name: "includes custom definitions in ConfigMap",
			imageBuild: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "build-with-defs",
					Namespace: "default",
					UID:       "test-uid-3",
				},
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB: &automotivev1alpha1.AIBSpec{
						Manifest:         "name: test\n",
						ManifestFileName: "m.aib.yml",
						CustomDefs:       []string{"FOO=bar", "BAZ=qux"},
					},
				},
			},
			wantCMName:       "build-with-defs-manifest",
			wantManifestKey:  "m.aib.yml",
			wantManifestData: "name: test\n",
			wantCustomDefs:   "FOO=bar\nBAZ=qux",
		},
		{
			name: "includes extra args in ConfigMap",
			imageBuild: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "build-with-args",
					Namespace: "default",
					UID:       "test-uid-4",
				},
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB: &automotivev1alpha1.AIBSpec{
						Manifest:         "name: test\n",
						ManifestFileName: "m.aib.yml",
						AIBExtraArgs:     []string{"--verbose", "--no-cache"},
					},
				},
			},
			wantCMName:       "build-with-args-manifest",
			wantManifestKey:  "m.aib.yml",
			wantManifestData: "name: test\n",
			wantExtraArgs:    "--verbose\n--no-cache",
		},
		{
			name: "includes both custom defs and extra args",
			imageBuild: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "build-full",
					Namespace: "default",
					UID:       "test-uid-5",
				},
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB: &automotivev1alpha1.AIBSpec{
						Manifest:         "name: full-build\n",
						ManifestFileName: "full.aib.yml",
						CustomDefs:       []string{"KEY=val"},
						AIBExtraArgs:     []string{"--debug"},
					},
				},
			},
			wantCMName:       "build-full-manifest",
			wantManifestKey:  "full.aib.yml",
			wantManifestData: "name: full-build\n",
			wantCustomDefs:   "KEY=val",
			wantExtraArgs:    "--debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.imageBuild).
				Build()

			r := &ImageBuildReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			ctx := context.Background()
			cmName, err := r.createOrUpdateManifestConfigMap(ctx, tt.imageBuild)
			if (err != nil) != tt.wantErr {
				t.Fatalf("createOrUpdateManifestConfigMap() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if cmName != tt.wantCMName {
				t.Errorf("ConfigMap name = %q, want %q", cmName, tt.wantCMName)
			}

			// Fetch the created ConfigMap and verify its contents
			cm := &corev1.ConfigMap{}
			err = fakeClient.Get(ctx, types.NamespacedName{
				Name:      cmName,
				Namespace: tt.imageBuild.Namespace,
			}, cm)
			if err != nil {
				t.Fatalf("failed to get ConfigMap: %v", err)
			}

			// Verify manifest content
			if cm.Data[tt.wantManifestKey] != tt.wantManifestData {
				t.Errorf("ConfigMap data[%q] = %q, want %q",
					tt.wantManifestKey, cm.Data[tt.wantManifestKey], tt.wantManifestData)
			}

			// Verify custom definitions
			if tt.wantCustomDefs != "" {
				if cm.Data["custom-definitions.env"] != tt.wantCustomDefs {
					t.Errorf("ConfigMap data[custom-definitions.env] = %q, want %q",
						cm.Data["custom-definitions.env"], tt.wantCustomDefs)
				}
			} else {
				if _, ok := cm.Data["custom-definitions.env"]; ok {
					t.Errorf("ConfigMap should not have custom-definitions.env key, but it does")
				}
			}

			// Verify extra args
			if tt.wantExtraArgs != "" {
				if cm.Data["aib-extra-args.txt"] != tt.wantExtraArgs {
					t.Errorf("ConfigMap data[aib-extra-args.txt] = %q, want %q",
						cm.Data["aib-extra-args.txt"], tt.wantExtraArgs)
				}
			} else {
				if _, ok := cm.Data["aib-extra-args.txt"]; ok {
					t.Errorf("ConfigMap should not have aib-extra-args.txt key, but it does")
				}
			}

			// Verify labels
			expectedLabels := map[string]string{
				"app.kubernetes.io/managed-by":                  "automotive-dev-operator",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				"automotive.sdv.cloud.redhat.com/build-name":    tt.imageBuild.Name,
				"automotive.sdv.cloud.redhat.com/resource-type": "manifest",
			}
			for k, v := range expectedLabels {
				if cm.Labels[k] != v {
					t.Errorf("ConfigMap label %q = %q, want %q", k, cm.Labels[k], v)
				}
			}

			// Verify owner reference
			if len(cm.OwnerReferences) != 1 {
				t.Fatalf("ConfigMap should have 1 owner reference, got %d", len(cm.OwnerReferences))
			}
			if cm.OwnerReferences[0].Name != tt.imageBuild.Name {
				t.Errorf("owner reference name = %q, want %q",
					cm.OwnerReferences[0].Name, tt.imageBuild.Name)
			}
		})
	}
}

func TestCreateOrUpdateManifestConfigMap_Update(t *testing.T) {
	scheme := newTestScheme()

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "update-test",
			Namespace: "default",
			UID:       "test-uid-update",
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			AIB: &automotivev1alpha1.AIBSpec{
				Manifest:         "name: original\n",
				ManifestFileName: "m.aib.yml",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(imageBuild).
		Build()

	r := &ImageBuildReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}
	ctx := context.Background()

	// First call - creates the ConfigMap
	cmName, err := r.createOrUpdateManifestConfigMap(ctx, imageBuild)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Update manifest content
	imageBuild.Spec.AIB.Manifest = "name: updated\n"

	// Second call - should update the existing ConfigMap
	cmName2, err := r.createOrUpdateManifestConfigMap(ctx, imageBuild)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if cmName != cmName2 {
		t.Errorf("ConfigMap name changed on update: %q != %q", cmName, cmName2)
	}

	// Verify the ConfigMap has the updated content
	cm := &corev1.ConfigMap{}
	err = fakeClient.Get(ctx, types.NamespacedName{
		Name:      cmName,
		Namespace: "default",
	}, cm)
	if err != nil {
		t.Fatalf("failed to get ConfigMap: %v", err)
	}

	if cm.Data["m.aib.yml"] != "name: updated\n" {
		t.Errorf("ConfigMap was not updated, data = %q, want %q",
			cm.Data["m.aib.yml"], "name: updated\n")
	}
}

func TestManifestConfigMapLockfile(t *testing.T) {
	scheme := newTestScheme()
	build := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "locked-build", Namespace: "default", UID: "locked-uid"},
		Spec:       automotivev1alpha1.ImageBuildSpec{AIB: &automotivev1alpha1.AIBSpec{Manifest: "name: test", Lockfile: `{"version":1}`, Mode: "bootc"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(build).Build()
	r := &ImageBuildReconciler{Client: c, Scheme: scheme}
	ctx := context.Background()
	for _, content := range []string{`{"version":1}`, `{"version":1,"depsolves":{}}`, ""} {
		build.Spec.AIB.Lockfile = content
		name, err := r.createOrUpdateManifestConfigMap(ctx, build)
		if err != nil {
			t.Fatal(err)
		}
		cm := &corev1.ConfigMap{}
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: build.Namespace}, cm); err != nil {
			t.Fatal(err)
		}
		value, present := cm.Data["aib.lock"]
		if value != content || present != (content != "") {
			t.Fatalf("lockfile contents/presence mismatch: %q, %v", value, present)
		}
		if cm.Data["manifest.aib.yml"] != "name: test" {
			t.Fatal("manifest changed")
		}
	}
	for _, tt := range []struct{ name, mode, filename, content string }{
		{"invalid", "bootc", "", `{"version":2}`},
		{"disk", "disk", "", `{"version":1}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			build.Spec.AIB.Mode = tt.mode
			build.Spec.AIB.ManifestFileName = tt.filename
			build.Spec.AIB.Lockfile = tt.content
			if _, err := r.createOrUpdateManifestConfigMap(ctx, build); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
