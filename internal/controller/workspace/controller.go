// Package workspace provides a Kubernetes controller for managing Workspace custom resources.
package workspace

import (
	"context"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	containerName               = "toolchain"
	pvcSuffix                   = "-workspace"
	leaseAnn                    = "automotive.sdv.cloud.redhat.com/lease-id"
	workspaceServiceAccountName = "ado-workspace"
)

// Reconciler reconciles a Workspace object.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=workspaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=workspaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=workspaces/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;delete

// Reconcile handles Workspace CR changes.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("workspace", req.NamespacedName)

	ws := &automotivev1alpha1.Workspace{}
	if err := r.Get(ctx, req.NamespacedName, ws); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Ensure PVC exists
	if err := r.ensurePVC(ctx, ws); err != nil {
		if statusErr := r.setStatus(ctx, ws, "Failed", fmt.Sprintf("PVC error: %v", err)); statusErr != nil {
			log.Error(statusErr, "failed to update status after PVC error")
		}
		return ctrl.Result{}, err
	}

	// Ensure Pod exists (needs PVC name from status)
	if ws.Status.PVCName == "" {
		return ctrl.Result{Requeue: true}, nil
	}
	pod, err := r.ensurePod(ctx, ws, log)
	if err != nil {
		if statusErr := r.setStatus(ctx, ws, "Failed", fmt.Sprintf("Pod error: %v", err)); statusErr != nil {
			log.Error(statusErr, "failed to update status after pod error")
		}
		return ctrl.Result{}, err
	}

	// Update status from pod phase
	phase := "Pending"
	msg := ""
	if pod != nil {
		switch pod.Status.Phase {
		case corev1.PodRunning:
			phase = "Running"
		case corev1.PodFailed:
			phase = "Failed"
			msg = "Pod failed"
		case corev1.PodSucceeded:
			phase = "Failed"
			msg = "Pod exited unexpectedly"
		default:
			phase = "Creating"
		}
	}

	return ctrl.Result{}, r.setStatus(ctx, ws, phase, msg)
}

func (r *Reconciler) ensurePVC(ctx context.Context, ws *automotivev1alpha1.Workspace) error {
	pvcName := ws.Name + pvcSuffix

	// Check if the PVC already exists
	existing := &corev1.PersistentVolumeClaim{}
	err := r.Get(ctx, client.ObjectKey{Namespace: ws.Namespace, Name: pvcName}, existing)
	if err == nil {
		// PVC exists; ensure status is up to date
		if ws.Status.PVCName != pvcName {
			patch := client.MergeFrom(ws.DeepCopy())
			ws.Status.PVCName = pvcName
			return r.Status().Patch(ctx, ws, patch)
		}
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return err
	}

	pvcSize := ws.Spec.PVCSize
	if pvcSize == "" {
		pvcSize = automotivev1alpha1.DefaultWorkspacePVCSize
	}
	storageQty, err := resource.ParseQuantity(pvcSize)
	if err != nil {
		return fmt.Errorf("invalid pvcSize %q: %w", pvcSize, err)
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: ws.Namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: storageQty,
				},
			},
		},
	}
	if ws.Spec.StorageClass != "" {
		pvc.Spec.StorageClassName = &ws.Spec.StorageClass
	}
	if err := controllerutil.SetControllerReference(ws, pvc, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, pvc); err != nil {
		return err
	}

	// Store the PVC name in status
	patch := client.MergeFrom(ws.DeepCopy())
	ws.Status.PVCName = pvcName
	return r.Status().Patch(ctx, ws, patch)
}

func (r *Reconciler) ensurePod(ctx context.Context, ws *automotivev1alpha1.Workspace, log logr.Logger) (*corev1.Pod, error) {
	podName := "workspace-" + ws.Name
	existing := &corev1.Pod{}
	err := r.Get(ctx, client.ObjectKey{Namespace: ws.Namespace, Name: podName}, existing)
	if err == nil {
		return existing, nil // already exists
	}
	if !k8serrors.IsNotFound(err) {
		return nil, err
	}

	pod := r.buildPod(ws)
	if err := controllerutil.SetControllerReference(ws, pod, r.Scheme); err != nil {
		return nil, err
	}
	log.Info("Creating workspace pod", "pod", podName)
	if err := r.Create(ctx, pod); err != nil {
		return nil, err
	}
	return pod, nil
}

func (r *Reconciler) buildPod(ws *automotivev1alpha1.Workspace) *corev1.Pod {
	podName := "workspace-" + ws.Name
	pvcName := ws.Status.PVCName

	arch := ws.Spec.Architecture
	if arch == "" {
		arch = automotivev1alpha1.DefaultWorkspaceArch
	}
	image := ws.Spec.Image
	if image == "" {
		image = automotivev1alpha1.DefaultToolchainImage
	}

	annotations := map[string]string{
		"io.kubernetes.cri-o.Devices": "/dev/fuse,/dev/net/tun",
	}
	if ws.Spec.LeaseID != "" {
		annotations[leaseAnn] = ws.Spec.LeaseID
	}

	volumes := []corev1.Volume{
		{
			Name: "workspace",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: pvcName,
				},
			},
		},
	}
	volumeMounts := []corev1.VolumeMount{
		{Name: "workspace", MountPath: "/workspace"},
	}

	env := []corev1.EnvVar{
		{Name: "HOME", Value: "/workspace"},
		{Name: "BUILDAH_ISOLATION", Value: "chroot"},
	}

	if ws.Spec.LeaseID != "" {
		env = append(env, corev1.EnvVar{Name: "JMP_LEASE", Value: ws.Spec.LeaseID})
	}

	if ws.Spec.ClientConfigSecretRef != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "jumpstarter-client",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ws.Spec.ClientConfigSecretRef,
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name: "jumpstarter-client", MountPath: "/jumpstarter", ReadOnly: true,
		})
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        podName,
			Namespace:   ws.Namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: workspaceServiceAccountName,
			HostUsers:          ptr.To(false),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: ptr.To[int64](0),
			},
			Containers: []corev1.Container{
				{
					Name:  containerName,
					Image: image,
					Command: []string{"/bin/sh", "-c",
						// Create workspace user (UID 1000) for rootless podman support
						"if ! id workspace &>/dev/null; then useradd -u 1000 -d /workspace -s /bin/bash workspace; fi" +
							" && echo 'workspace:1001:64535' > /etc/subuid" +
							" && echo 'workspace:1001:64535' > /etc/subgid" +
							// Set up workspace directories owned by workspace user
							" && mkdir -p /workspace/src /workspace/cache /workspace/.ssh /workspace/.config /workspace/.local/share/containers" +
							" && chown -R 1000:1000 /workspace/src /workspace/cache /workspace/.ssh /workspace/.config /workspace/.local" +
							// Wrapper scripts: podman/buildah auto-switch to workspace user (UID 1000)
							" && printf '#!/bin/sh\\nCMD=$(basename \"$0\")\\nif [ \"$(id -u)\" = \"0\" ]; then\\n  export HOME=/workspace\\n  exec setpriv --reuid=1000 --regid=1000 --init-groups --inh-caps=+setuid,+setgid --ambient-caps=+setuid,+setgid -- /usr/bin/$CMD \"$@\"\\nfi\\nexec /usr/bin/$CMD \"$@\"\\n' > /usr/local/bin/podman" +
							" && chmod +x /usr/local/bin/podman && ln -f /usr/local/bin/podman /usr/local/bin/buildah" +
							" && [ -f /workspace/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -f /workspace/.ssh/id_ed25519 -N '' -q" +
							" && chown 1000:1000 /workspace/.ssh/id_ed25519 /workspace/.ssh/id_ed25519.pub 2>/dev/null || true" +
							" && if [ -f /jumpstarter/client.yaml ]; then" +
							" mkdir -p /workspace/.config/jumpstarter/clients" +
							" && cp /jumpstarter/client.yaml /workspace/.config/jumpstarter/clients/workspace.yaml" +
							" && chown -R 1000:1000 /workspace/.config" +
							" && setpriv --reuid=1000 --regid=1000 --init-groups -- jmp config client use workspace || true; fi" +
							" && exec sleep infinity"},
					WorkingDir: "/workspace",
					Env:        env,
					Resources:  resourcesOrDefaults(ws.Spec.Resources),
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: ptr.To(true),
						ProcMount:                ptr.To(corev1.UnmaskedProcMount),
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{
								"SETUID",
								"SETGID",
							},
						},
					},
					VolumeMounts: volumeMounts,
				},
			},
			Volumes: volumes,
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/arch",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{arch},
									},
								},
							},
						},
					},
				},
			},
			NodeSelector:                  ws.Spec.NodeSelector,
			TerminationGracePeriodSeconds: ptr.To[int64](5),
			RestartPolicy:                 corev1.RestartPolicyNever,
		},
	}

	return pod
}

func (r *Reconciler) setStatus(ctx context.Context, ws *automotivev1alpha1.Workspace, phase, message string) error {
	if ws.Status.Phase == phase && ws.Status.Message == message && ws.Status.PodName != "" {
		return nil // no change
	}
	patch := client.MergeFrom(ws.DeepCopy())
	ws.Status.Phase = phase
	ws.Status.Message = message
	ws.Status.PodName = "workspace-" + ws.Name
	return r.Status().Patch(ctx, ws, patch)
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.Workspace{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Complete(r)
}

func resourcesOrDefaults(r *corev1.ResourceRequirements) corev1.ResourceRequirements {
	if r != nil {
		return *r
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		},
	}
}
