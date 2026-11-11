package workspace

import (
	"context"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The API creates a workspace's client config Secret just after the
// Workspace. Until that Secret exists and is controlled by the Workspace, a
// Secret by the same name belongs to someone else, such as a flashing build of
// the same name, and the pod must not mount it.

func clientConfigWorkspace() (*automotivev1alpha1.Workspace, *corev1.PersistentVolumeClaim) {
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default", UID: "ws-uid"},
		Spec: automotivev1alpha1.WorkspaceSpec{
			Owner:                 "alice",
			Architecture:          "amd64",
			ClientConfigSecretRef: "demo-jumpstarter-client",
		},
		Status: automotivev1alpha1.WorkspaceStatus{PVCName: "demo" + pvcSuffix},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "demo" + pvcSuffix, Namespace: "default"},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			},
		},
	}
	return ws, pvc
}

func clientConfigSecret(owner *metav1.OwnerReference) *corev1.Secret {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "demo-jumpstarter-client", Namespace: "default"}}
	if owner != nil {
		secret.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return secret
}

func reconcileDemo(t *testing.T, objs ...client.Object) (*automotivev1alpha1.Workspace, bool, error) {
	t.Helper()
	ws, pvc := clientConfigWorkspace()
	r, fc := newTestReconciler(append([]client.Object{ws, pvc}, objs...)...)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo", Namespace: "default"}})
	podErr := fc.Get(context.Background(), types.NamespacedName{Name: "workspace-demo", Namespace: "default"}, &corev1.Pod{})
	if podErr != nil && !k8serrors.IsNotFound(podErr) {
		t.Fatal(podErr)
	}
	updated := &automotivev1alpha1.Workspace{}
	if getErr := fc.Get(context.Background(), types.NamespacedName{Name: "demo", Namespace: "default"}, updated); getErr != nil {
		t.Fatal(getErr)
	}
	return updated, podErr == nil, err
}

func TestReconcile_WaitsForClientConfigSecret(t *testing.T) {
	ws, podCreated, err := reconcileDemo(t)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if podCreated {
		t.Fatal("pod created before its client config Secret exists")
	}
	if ws.Status.Phase != phaseCreating {
		t.Fatalf("phase = %q, want %q", ws.Status.Phase, phaseCreating)
	}
}

func TestReconcile_RefusesClientConfigSecretOwnedElsewhere(t *testing.T) {
	for name, owner := range map[string]*metav1.OwnerReference{
		"no owner": nil,
		"another owner": {APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageBuild",
			Name: "demo", UID: "build-uid", Controller: new(true)},
		"same workspace, not controller": {APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "Workspace",
			Name: "demo", UID: "ws-uid"},
	} {
		t.Run(name, func(t *testing.T) {
			ws, podCreated, err := reconcileDemo(t, clientConfigSecret(owner))
			if err == nil {
				t.Fatal("expected an error for a client config Secret the workspace does not control")
			}
			if podCreated {
				t.Fatal("pod mounts a client config Secret the workspace does not control")
			}
			if ws.Status.Phase != "Failed" {
				t.Fatalf("phase = %q, want Failed", ws.Status.Phase)
			}
		})
	}
}

func TestReconcile_MountsOwnedClientConfigSecret(t *testing.T) {
	owner := &metav1.OwnerReference{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "Workspace",
		Name: "demo", UID: "ws-uid", Controller: new(true)}
	if _, podCreated, err := reconcileDemo(t, clientConfigSecret(owner)); err != nil || !podCreated {
		t.Fatalf("Reconcile() error = %v, pod created = %t", err, podCreated)
	}
}
