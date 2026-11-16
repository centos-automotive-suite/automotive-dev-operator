package agentconn

import (
	"context"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A build's upload agent has a token of its own, which is never a
// workspace's.
func TestConnectUploadReadsTheBuildsToken(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	workspaceToken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: workspaceagent.TokenSecretName("b")},
		Data:       map[string][]byte{workspaceagent.TokenKey: []byte("workspace")},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(workspaceToken).Build()
	build := &automotivev1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b"}}

	_, err := ConnectUpload(context.Background(), kube, build)
	if err == nil || !strings.Contains(err.Error(), workspaceagent.UploadTokenSecretName("b")) {
		t.Errorf("err = %v, want the missing upload token named", err)
	}
}
