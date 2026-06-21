package containerbuild

import (
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	shipwrightv1beta1 "github.com/shipwright-io/build/pkg/apis/build/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSafeDerivedName(t *testing.T) {
	tests := []struct {
		name       string
		baseName   string
		suffix     string
		wantExact  string // if non-empty, expect exact match
		wantSuffix string
	}{
		{
			name:      "short name no truncation",
			baseName:  "my-build",
			suffix:    "-br",
			wantExact: "my-build-br",
		},
		{
			name:       "long name gets truncated with hash",
			baseName:   "this-is-a-very-long-build-name-that-will-definitely-exceed-the-limit",
			suffix:     "-br",
			wantSuffix: "-br",
		},
		{
			name:     "suffix alone exceeds limit truncates to max",
			baseName: "name",
			suffix:   strings.Repeat("-very-long-suffix", 5),
			// When hash+suffix exceeds 63 chars, result is truncated; just check length
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeDerivedName(tt.baseName, tt.suffix)

			if len(got) > maxK8sNameLength {
				t.Errorf("result %q length %d exceeds max %d", got, len(got), maxK8sNameLength)
			}

			if tt.wantExact != "" && got != tt.wantExact {
				t.Errorf("safeDerivedName() = %q, want %q", got, tt.wantExact)
			}

			if tt.wantSuffix != "" && !strings.HasSuffix(got, tt.wantSuffix) {
				t.Errorf("result %q does not end with %q", got, tt.wantSuffix)
			}

			// Determinism check
			got2 := safeDerivedName(tt.baseName, tt.suffix)
			if got != got2 {
				t.Errorf("not deterministic: %q != %q", got, got2)
			}
		})
	}

	t.Run("different inputs produce different outputs", func(t *testing.T) {
		a := safeDerivedName("long-name-variant-alpha-padding-padding-padding-padding", "-br")
		b := safeDerivedName("long-name-variant-bravo-padding-padding-padding-padding", "-br")
		if a == b {
			t.Errorf("different inputs produced same output: %q", a)
		}
	})
}

const testNamespace = "test-operator-ns"

func newTestContainerBuild(name string, spec automotivev1alpha1.ContainerBuildSpec) *automotivev1alpha1.ContainerBuild {
	return &automotivev1alpha1.ContainerBuild{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       spec,
	}
}

// findBuildArgParam returns all build-args values from a BuildRun's ParamValues.
func findBuildArgParam(br *shipwrightv1beta1.BuildRun) []string {
	var vals []string
	for _, pv := range br.Spec.Build.Spec.ParamValues {
		if pv.Name == "build-args" {
			for _, sv := range pv.Values {
				if sv.Value != nil {
					vals = append(vals, *sv.Value)
				}
			}
		}
	}
	return vals
}

func TestBuildRunBasic(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test-build", automotivev1alpha1.ContainerBuildSpec{
		Output:        "quay.io/org/image:latest",
		Containerfile: "Containerfile",
		Strategy:      "buildah",
		Architecture:  "amd64",
		Timeout:       30,
	})

	br := r.buildShipwrightBuildRun(cb, "test-build-br", 10*time.Minute)

	if br.Name != "test-build-br" {
		t.Errorf("BuildRun name = %q, want %q", br.Name, "test-build-br")
	}
	if br.Namespace != testNamespace {
		t.Errorf("namespace = %q, want %q", br.Namespace, testNamespace)
	}

	spec := br.Spec.Build.Spec
	if spec == nil {
		t.Fatal("BuildRun spec is nil")
	}
	if spec.Source.Type != shipwrightv1beta1.LocalType {
		t.Errorf("source type = %v, want Local", spec.Source.Type)
	}
	if spec.Source.Local.Timeout.Duration != 10*time.Minute {
		t.Errorf("upload timeout = %v, want 10m", spec.Source.Local.Timeout.Duration)
	}
	if spec.Output.Image != "quay.io/org/image:latest" {
		t.Errorf("output image = %q, want %q", spec.Output.Image, "quay.io/org/image:latest")
	}
	if spec.Timeout.Duration != 30*time.Minute {
		t.Errorf("build timeout = %v, want 30m", spec.Timeout.Duration)
	}
	if spec.Strategy.Name != "buildah" {
		t.Errorf("strategy = %q, want %q", spec.Strategy.Name, "buildah")
	}
	if spec.Strategy.Kind == nil {
		t.Fatal("Strategy.Kind is nil")
	}
	if *spec.Strategy.Kind != shipwrightv1beta1.ClusterBuildStrategyKind {
		t.Errorf("strategy kind = %v, want ClusterBuildStrategy", *spec.Strategy.Kind)
	}
}

func TestBuildRunTargetArch(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:       "quay.io/org/image:latest",
		Architecture: "arm64",
		Timeout:      15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)
	args := findBuildArgParam(br)

	found := false
	for _, v := range args {
		if v == "TARGETARCH=arm64" {
			found = true
		}
	}
	if !found {
		t.Error("TARGETARCH=arm64 build arg not found in paramValues")
	}
}

func TestBuildRunCustomContainerfile(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:        "quay.io/org/image:latest",
		Containerfile: "Dockerfile.prod",
		Timeout:       15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)

	found := false
	for _, pv := range br.Spec.Build.Spec.ParamValues {
		if pv.Name == "dockerfile" && pv.Value != nil && *pv.Value == "Dockerfile.prod" {
			found = true
		}
	}
	if !found {
		t.Error("dockerfile param not set for custom Containerfile")
	}
}

func TestBuildRunDefaultContainerfileAlwaysPassesParam(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:  "quay.io/org/image:latest",
		Timeout: 15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)

	found := false
	for _, pv := range br.Spec.Build.Spec.ParamValues {
		if pv.Name == "dockerfile" {
			found = true
			if pv.SingleValue == nil || pv.Value == nil || *pv.Value != "Containerfile" {
				t.Errorf("expected dockerfile param = 'Containerfile', got %v", pv.SingleValue)
			}
		}
	}
	if !found {
		t.Error("dockerfile param must always be set to override Shipwright's Dockerfile default")
	}
}

func TestBuildRunPushSecret(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:        "quay.io/org/image:latest",
		PushSecretRef: "my-push-secret",
		Timeout:       15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)

	if br.Spec.Build.Spec.Output.PushSecret == nil {
		t.Fatal("PushSecret should be set")
	}
	if *br.Spec.Build.Spec.Output.PushSecret != "my-push-secret" {
		t.Errorf("PushSecret = %q, want %q", *br.Spec.Build.Spec.Output.PushSecret, "my-push-secret")
	}
}

func TestBuildRunBuildArgs(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:  "quay.io/org/image:latest",
		Timeout: 15,
		BuildArgs: map[string]string{
			"VERSION": "1.0",
			"ENV":     "prod",
		},
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)
	args := findBuildArgParam(br)

	foundVersion := false
	foundEnv := false
	for _, v := range args {
		if v == "VERSION=1.0" {
			foundVersion = true
		}
		if v == "ENV=prod" {
			foundEnv = true
		}
	}
	if !foundVersion {
		t.Error("VERSION=1.0 build arg not found")
	}
	if !foundEnv {
		t.Error("ENV=prod build arg not found")
	}
}

func TestBuildRunNamespacedStrategy(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:       "quay.io/org/image:latest",
		Strategy:     "custom-strategy",
		StrategyKind: "BuildStrategy",
		Timeout:      15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)

	if br.Spec.Build.Spec.Strategy.Kind == nil {
		t.Fatal("Strategy.Kind is nil")
	}
	if *br.Spec.Build.Spec.Strategy.Kind != shipwrightv1beta1.NamespacedBuildStrategyKind {
		t.Errorf("strategy kind = %v, want NamespacedBuildStrategy", *br.Spec.Build.Spec.Strategy.Kind)
	}
}

func TestExtractRegistryHost(t *testing.T) {
	tests := []struct {
		imageRef string
		want     string
	}{
		{"image-registry.openshift-image-registry.svc:5000/ns/img:tag", "image-registry.openshift-image-registry.svc:5000"},
		{"quay.io/org/image:latest", "quay.io"},
		{"registry.example.com/image:v1", "registry.example.com"},
		{"docker://registry.example.com/image:v1", "registry.example.com"},
		{"ubuntu:latest", ""},
		{"localhost:5000/myimg:latest", "localhost:5000"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.imageRef, func(t *testing.T) {
			got := extractRegistryHost(tt.imageRef)
			if got != tt.want {
				t.Errorf("extractRegistryHost(%q) = %q, want %q", tt.imageRef, got, tt.want)
			}
		})
	}
}

func TestBuildRunInsecureRegistryForInternalPush(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:                "image-registry.openshift-image-registry.svc:5000/ns/img:latest",
		UseServiceAccountAuth: true,
		Timeout:               15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)

	var insecureVals []string
	for _, pv := range br.Spec.Build.Spec.ParamValues {
		if pv.Name == "registries-insecure" {
			for _, sv := range pv.Values {
				if sv.Value != nil {
					insecureVals = append(insecureVals, *sv.Value)
				}
			}
		}
	}
	if len(insecureVals) != 1 || insecureVals[0] != "image-registry.openshift-image-registry.svc:5000" {
		t.Errorf("registries-insecure = %v, want [image-registry.openshift-image-registry.svc:5000]", insecureVals)
	}
}

func TestBuildRunNoInsecureRegistryForExternalPush(t *testing.T) {
	r := &ContainerBuildReconciler{}
	cb := newTestContainerBuild("test", automotivev1alpha1.ContainerBuildSpec{
		Output:  "quay.io/org/image:latest",
		Timeout: 15,
	})

	br := r.buildShipwrightBuildRun(cb, "test-br", 5*time.Minute)

	for _, pv := range br.Spec.Build.Spec.ParamValues {
		if pv.Name == "registries-insecure" {
			t.Error("registries-insecure should not be set for external registry push")
		}
	}
}
