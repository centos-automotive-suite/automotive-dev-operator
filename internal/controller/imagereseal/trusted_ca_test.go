package imagereseal

import (
	"context"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(automotivev1alpha1.AddToScheme(s))
	utilruntime.Must(tektonv1.AddToScheme(s))
	return s
}

func TestCreateSealedTaskRun_ServiceAccount(t *testing.T) {
	scheme := newTestScheme()
	operatorConfig := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: controllerutils.OperatorNamespace(),
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(operatorConfig).Build()
	r := &Reconciler{Client: fakeClient, Scheme: scheme}

	sealed := &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-reseal",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: automotivev1alpha1.ImageResealSpec{
			Operation: "reseal",
			InputRef:  "quay.io/test/bootc:seal",
			OutputRef: "quay.io/test/bootc:resealed",
		},
	}

	operatorConfig, err := r.resolveOperatorConfig(context.Background())
	if err != nil {
		t.Fatalf("resolveOperatorConfig returned error: %v", err)
	}
	tr, err := r.createSealedTaskRun(context.Background(), sealed, "reseal", operatorConfig)
	if err != nil {
		t.Fatalf("createSealedTaskRun returned error: %v", err)
	}
	if tr.Spec.ServiceAccountName != automotivev1alpha1.BuildServiceAccountName {
		t.Errorf("TaskRun ServiceAccountName = %q, want %q", tr.Spec.ServiceAccountName, automotivev1alpha1.BuildServiceAccountName)
	}

	// Verify the TaskRun was actually created in the cluster with the right SA
	created := &tektonv1.TaskRun{}
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-reseal", Namespace: "default"}, created); err != nil {
		t.Fatalf("TaskRun not found after creation: %v", err)
	}
	if created.Spec.ServiceAccountName != automotivev1alpha1.BuildServiceAccountName {
		t.Errorf("persisted TaskRun ServiceAccountName = %q, want %q", created.Spec.ServiceAccountName, automotivev1alpha1.BuildServiceAccountName)
	}
}

func TestApplyTrustedCABundleFromOSBuilds_ImageReseal(t *testing.T) {
	tests := []struct {
		name     string
		osBuilds *automotivev1alpha1.OSBuildsConfig
		wantKind string
		wantName string
	}{
		{
			name:     "nil osBuilds",
			osBuilds: nil,
		},
		{
			name:     "nil certificates",
			osBuilds: &automotivev1alpha1.OSBuildsConfig{},
		},
		{
			name: "configmap trusted bundle",
			osBuilds: &automotivev1alpha1.OSBuildsConfig{
				Certificates: &automotivev1alpha1.BuildCertificatesConfig{
					TrustedCABundle: &automotivev1alpha1.CertificateSourceRef{
						Kind: "ConfigMap",
						Name: "my-test-ca",
					},
				},
			},
			wantKind: "ConfigMap",
			wantName: "my-test-ca",
		},
		{
			name: "secret trusted bundle",
			osBuilds: &automotivev1alpha1.OSBuildsConfig{
				Certificates: &automotivev1alpha1.BuildCertificatesConfig{
					TrustedCABundle: &automotivev1alpha1.CertificateSourceRef{
						Kind: "Secret",
						Name: "my-test-ca-secret",
					},
				},
			},
			wantKind: "Secret",
			wantName: "my-test-ca-secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buildCfg := &tasks.BuildConfig{}
			controllerutils.ApplyTrustedCABundleFromOSBuilds(buildCfg, tc.osBuilds)
			if buildCfg.TrustedCABundleKind != tc.wantKind {
				t.Fatalf("kind mismatch: got %q want %q", buildCfg.TrustedCABundleKind, tc.wantKind)
			}
			if buildCfg.TrustedCABundleName != tc.wantName {
				t.Fatalf("name mismatch: got %q want %q", buildCfg.TrustedCABundleName, tc.wantName)
			}
		})
	}
}
