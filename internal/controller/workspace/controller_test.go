package workspace

import (
	"context"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	phaseRunning = "Running"
	phaseStopped = "Stopped"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	return scheme
}

func newTestReconciler(objs ...client.Object) (*Reconciler, client.Client) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&automotivev1alpha1.Workspace{}).
		Build()
	r := &Reconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logr.Discard(),
	}
	return r, fakeClient
}

// runningWorkspace returns a Workspace and its associated PVC and Pod,
// simulating a workspace that is already running.
func runningWorkspace(name, namespace string) (*automotivev1alpha1.Workspace, *corev1.PersistentVolumeClaim, *corev1.Pod) {
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: automotivev1alpha1.WorkspaceSpec{
			Owner:        "testuser",
			Architecture: "amd64",
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseRunning,
			PVCName: name + pvcSuffix,
			PodName: "workspace-" + name,
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + pvcSuffix,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workspace-" + name,
			Namespace: namespace,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
	return ws, pvc, pod
}

func TestReconcile_StopWorkspace(t *testing.T) {
	ws, pvc, pod := runningWorkspace("my-app", "default")
	ws.Spec.Stopped = true

	r, fc := newTestReconciler(ws, pvc, pod)
	ctx := context.Background()

	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-app", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got RequeueAfter=%v", result.RequeueAfter)
	}

	// Pod should be deleted
	deletedPod := &corev1.Pod{}
	err = fc.Get(ctx, types.NamespacedName{Name: "workspace-my-app", Namespace: "default"}, deletedPod)
	if err == nil {
		t.Error("expected pod to be deleted, but it still exists")
	}

	// PVC should still exist
	existingPVC := &corev1.PersistentVolumeClaim{}
	err = fc.Get(ctx, types.NamespacedName{Name: "my-app" + pvcSuffix, Namespace: "default"}, existingPVC)
	if err != nil {
		t.Errorf("expected PVC to still exist, got error: %v", err)
	}

	// Status should be "Stopped" with empty PodName
	updatedWS := &automotivev1alpha1.Workspace{}
	if err := fc.Get(ctx, types.NamespacedName{Name: "my-app", Namespace: "default"}, updatedWS); err != nil {
		t.Fatalf("failed to get workspace: %v", err)
	}
	if updatedWS.Status.Phase != phaseStopped {
		t.Errorf("expected phase %q, got %q", phaseStopped, updatedWS.Status.Phase)
	}
	if updatedWS.Status.PodName != "" {
		t.Errorf("expected empty PodName when stopped, got %q", updatedWS.Status.PodName)
	}
}

func TestReconcile_StartWorkspace(t *testing.T) {
	// Workspace was stopped: has PVC but no pod, Stopped=false (just un-stopped)
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "default",
		},
		Spec: automotivev1alpha1.WorkspaceSpec{
			Owner:        "testuser",
			Architecture: "amd64",
			Stopped:      false,
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseStopped,
			PVCName: "my-app" + pvcSuffix,
			PodName: "",
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app" + pvcSuffix,
			Namespace: "default",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	r, fc := newTestReconciler(ws, pvc)
	ctx := context.Background()

	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-app", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got RequeueAfter=%v", result.RequeueAfter)
	}

	// Pod should be created
	createdPod := &corev1.Pod{}
	err = fc.Get(ctx, types.NamespacedName{Name: "workspace-my-app", Namespace: "default"}, createdPod)
	if err != nil {
		t.Errorf("expected pod to be created, got error: %v", err)
	}

	// Status should show PodName and transition from Stopped
	updatedWS := &automotivev1alpha1.Workspace{}
	if err := fc.Get(ctx, types.NamespacedName{Name: "my-app", Namespace: "default"}, updatedWS); err != nil {
		t.Fatalf("failed to get workspace: %v", err)
	}
	if updatedWS.Status.PodName != "workspace-my-app" {
		t.Errorf("expected PodName %q, got %q", "workspace-my-app", updatedWS.Status.PodName)
	}
	// Phase should not be "Stopped" anymore (pod is Pending since fake client doesn't simulate scheduling)
	if updatedWS.Status.Phase == phaseStopped {
		t.Error("expected phase to change from Stopped")
	}
}

func TestReconcile_StopAlreadyStopped(t *testing.T) {
	// Workspace already stopped: Stopped=true, no pod exists
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "default",
		},
		Spec: automotivev1alpha1.WorkspaceSpec{
			Owner:   "testuser",
			Stopped: true,
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseStopped,
			PVCName: "my-app" + pvcSuffix,
			PodName: "",
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app" + pvcSuffix,
			Namespace: "default",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	r, fc := newTestReconciler(ws, pvc)
	ctx := context.Background()

	// Should succeed without error (idempotent)
	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-app", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got RequeueAfter=%v", result.RequeueAfter)
	}

	// Phase should remain Stopped
	updatedWS := &automotivev1alpha1.Workspace{}
	if err := fc.Get(ctx, types.NamespacedName{Name: "my-app", Namespace: "default"}, updatedWS); err != nil {
		t.Fatalf("failed to get workspace: %v", err)
	}
	if updatedWS.Status.Phase != phaseStopped {
		t.Errorf("expected phase %q, got %q", phaseStopped, updatedWS.Status.Phase)
	}
}

func TestReconcile_DeletedWorkspace(t *testing.T) {
	// Workspace doesn't exist — should return no error
	r, _ := newTestReconciler()
	ctx := context.Background()

	result, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue for deleted workspace, got RequeueAfter=%v", result.RequeueAfter)
	}
}

func TestSetStatus_StoppedClearsPodName(t *testing.T) {
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ws",
			Namespace: "default",
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseRunning,
			PodName: "workspace-test-ws",
		},
	}

	r, fc := newTestReconciler(ws)
	ctx := context.Background()

	err := r.setStatus(ctx, ws, phaseStopped, "")
	if err != nil {
		t.Fatalf("setStatus() error = %v", err)
	}

	updated := &automotivev1alpha1.Workspace{}
	if err := fc.Get(ctx, types.NamespacedName{Name: "test-ws", Namespace: "default"}, updated); err != nil {
		t.Fatalf("failed to get workspace: %v", err)
	}
	if updated.Status.PodName != "" {
		t.Errorf("expected PodName to be cleared, got %q", updated.Status.PodName)
	}
	if updated.Status.Phase != phaseStopped {
		t.Errorf("expected phase %q, got %q", phaseStopped, updated.Status.Phase)
	}
}

func TestSetStatus_RunningSetsPodName(t *testing.T) {
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ws",
			Namespace: "default",
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseStopped,
			PodName: "",
		},
	}

	r, fc := newTestReconciler(ws)
	ctx := context.Background()

	err := r.setStatus(ctx, ws, phaseRunning, "")
	if err != nil {
		t.Fatalf("setStatus() error = %v", err)
	}

	updated := &automotivev1alpha1.Workspace{}
	if err := fc.Get(ctx, types.NamespacedName{Name: "test-ws", Namespace: "default"}, updated); err != nil {
		t.Fatalf("failed to get workspace: %v", err)
	}
	if updated.Status.PodName != "workspace-test-ws" {
		t.Errorf("expected PodName %q, got %q", "workspace-test-ws", updated.Status.PodName)
	}
	if updated.Status.Phase != phaseRunning {
		t.Errorf("expected phase %q, got %q", phaseRunning, updated.Status.Phase)
	}
}

func TestSetStatus_NoOpWhenUnchanged(t *testing.T) {
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ws",
			Namespace: "default",
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			Phase:   phaseStopped,
			PodName: "",
			Message: "",
		},
	}

	r, _ := newTestReconciler(ws)
	ctx := context.Background()

	// Should be a no-op — same phase, same message, same podName
	err := r.setStatus(ctx, ws, phaseStopped, "")
	if err != nil {
		t.Fatalf("setStatus() error = %v", err)
	}
}

func TestBuildPod_PreservesWorkspaceConfig(t *testing.T) {
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ws",
			Namespace: "default",
		},
		Spec: automotivev1alpha1.WorkspaceSpec{
			Architecture:  "amd64",
			Image:         "quay.io/test/toolchain:latest",
			LeaseID:       "lease-123",
			TmpfsBuildDir: true,
		},
		Status: automotivev1alpha1.WorkspaceStatus{
			PVCName: "test-ws-workspace",
		},
	}

	r := &Reconciler{Scheme: newTestScheme()}
	pod := r.buildPod(ws, nil)

	if pod.Name != "workspace-test-ws" {
		t.Errorf("expected pod name %q, got %q", "workspace-test-ws", pod.Name)
	}

	// Check arch affinity
	terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) == 0 || terms[0].MatchExpressions[0].Values[0] != "amd64" {
		t.Error("expected amd64 node affinity")
	}

	// Check lease env var
	foundLease := false
	for _, env := range pod.Spec.Containers[0].Env {
		if env.Name == "JMP_LEASE" && env.Value == "lease-123" {
			foundLease = true
		}
	}
	if !foundLease {
		t.Error("expected JMP_LEASE env var")
	}

	// Check tmpfs volume
	foundTmpfs := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "tmpfs-build" && v.EmptyDir != nil && v.EmptyDir.Medium == corev1.StorageMediumMemory {
			foundTmpfs = true
		}
	}
	if !foundTmpfs {
		t.Error("expected tmpfs-build volume")
	}
}

func TestBuildPod_SecurityContext(t *testing.T) {
	toolchainImage := automotivev1alpha1.DefaultToolchainImage
	customImage := "quay.io/example/custom:latest"

	makeWorkspace := func(image string) *automotivev1alpha1.Workspace {
		return &automotivev1alpha1.Workspace{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ws",
				Namespace: "default",
			},
			Spec: automotivev1alpha1.WorkspaceSpec{
				Architecture: "amd64",
				Image:        image,
			},
			Status: automotivev1alpha1.WorkspaceStatus{
				PVCName: "test-ws-workspace",
			},
		}
	}

	tests := []struct {
		name           string
		image          string
		userNamespaces bool
		wantPrivileged bool
		wantSysAdmin   bool
		wantProcMount  *corev1.ProcMountType
	}{
		{
			name:           "no userns + toolchain image → privileged",
			image:          "", // defaults to toolchain
			userNamespaces: false,
			wantPrivileged: true,
			wantSysAdmin:   false, // privileged implies all caps
		},
		{
			name:           "no userns + custom image → not privileged, no SYS_ADMIN",
			image:          customImage,
			userNamespaces: false,
			wantPrivileged: false,
			wantSysAdmin:   false,
		},
		{
			name:           "userns + toolchain image → not privileged, has SYS_ADMIN",
			image:          "", // defaults to toolchain
			userNamespaces: true,
			wantPrivileged: false,
			wantSysAdmin:   true,
			wantProcMount:  ptr.To(corev1.UnmaskedProcMount),
		},
		{
			name:           "userns + custom image → not privileged, has SYS_ADMIN (scoped to userns)",
			image:          customImage,
			userNamespaces: true,
			wantPrivileged: false,
			wantSysAdmin:   true,
			wantProcMount:  ptr.To(corev1.UnmaskedProcMount),
		},
		{
			name:           "userns + explicit toolchain image → not privileged, has SYS_ADMIN",
			image:          toolchainImage,
			userNamespaces: true,
			wantPrivileged: false,
			wantSysAdmin:   true,
			wantProcMount:  ptr.To(corev1.UnmaskedProcMount),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := makeWorkspace(tt.image)

			var operatorConfig *automotivev1alpha1.OperatorConfig
			if tt.userNamespaces {
				operatorConfig = &automotivev1alpha1.OperatorConfig{
					Status: automotivev1alpha1.OperatorConfigStatus{
						UserNamespacesSupported: true,
					},
				}
			}

			r := &Reconciler{Scheme: newTestScheme()}
			pod := r.buildPod(ws, operatorConfig)

			secCtx := pod.Spec.Containers[0].SecurityContext
			if secCtx == nil {
				t.Fatal("expected SecurityContext to be set")
			}

			// Check Privileged
			isPrivileged := secCtx.Privileged != nil && *secCtx.Privileged
			if isPrivileged != tt.wantPrivileged {
				t.Errorf("Privileged = %v, want %v", isPrivileged, tt.wantPrivileged)
			}

			// Check SYS_ADMIN capability
			hasSysAdmin := false
			if secCtx.Capabilities != nil {
				for _, cap := range secCtx.Capabilities.Add {
					if cap == "SYS_ADMIN" {
						hasSysAdmin = true
					}
				}
			}
			if hasSysAdmin != tt.wantSysAdmin {
				t.Errorf("SYS_ADMIN capability = %v, want %v", hasSysAdmin, tt.wantSysAdmin)
			}

			// Check ProcMount
			if tt.wantProcMount != nil {
				if secCtx.ProcMount == nil {
					t.Errorf("ProcMount = nil, want %v", *tt.wantProcMount)
				} else if *secCtx.ProcMount != *tt.wantProcMount {
					t.Errorf("ProcMount = %v, want %v", *secCtx.ProcMount, *tt.wantProcMount)
				}
			} else if secCtx.ProcMount != nil {
				t.Errorf("ProcMount = %v, want nil", *secCtx.ProcMount)
			}

			// Non-privileged containers must drop ALL caps
			if !tt.wantPrivileged {
				if secCtx.Capabilities == nil {
					t.Fatal("expected Capabilities to be set for non-privileged container")
				}
				dropsAll := false
				for _, cap := range secCtx.Capabilities.Drop {
					if cap == "ALL" {
						dropsAll = true
					}
				}
				if !dropsAll {
					t.Error("non-privileged container must drop ALL capabilities")
				}
			}
		})
	}
}
