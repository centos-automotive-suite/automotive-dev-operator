// Package workspace provides a Kubernetes controller for managing Workspace custom resources.
package workspace

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
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
	Scheme     *runtime.Scheme
	Log        logr.Logger
	RestConfig *rest.Config

	clientset     kubernetes.Interface
	clientsetErr  error
	clientsetOnce sync.Once
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=workspaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=workspaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,resources=workspaces/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
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

	// Handle stopped state: delete pod but keep PVC
	if ws.Spec.Stopped {
		if err := r.deleteWorkspacePod(ctx, ws, log); err != nil {
			return ctrl.Result{}, err
		}
		// Preserve existing message (e.g., auto-pause reason) if already Stopped
		msg := ws.Status.Message
		return ctrl.Result{}, r.setStatus(ctx, ws, "Stopped", msg)
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

	if err := r.setStatus(ctx, ws, phase, msg); err != nil {
		return ctrl.Result{}, err
	}

	// Auto-pause check: only for Running workspaces
	if phase == "Running" {
		return r.checkAutoPause(ctx, ws, log)
	}

	return ctrl.Result{}, nil
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

	// Load OperatorConfig only when creating a new pod
	var operatorConfig *automotivev1alpha1.OperatorConfig
	oc := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: "config", Namespace: ws.Namespace}, oc); err == nil {
		operatorConfig = oc
	}

	pod := r.buildPod(ws, operatorConfig)
	if err := controllerutil.SetControllerReference(ws, pod, r.Scheme); err != nil {
		return nil, err
	}
	log.Info("Creating workspace pod", "pod", podName)
	if err := r.Create(ctx, pod); err != nil {
		return nil, err
	}
	return pod, nil
}

func (r *Reconciler) buildPod(ws *automotivev1alpha1.Workspace, operatorConfig *automotivev1alpha1.OperatorConfig) *corev1.Pod {
	podName := "workspace-" + ws.Name
	pvcName := ws.Status.PVCName

	arch := ws.Spec.Architecture
	if arch == "" {
		arch = automotivev1alpha1.DefaultWorkspaceArch
	}
	var wsConfig *automotivev1alpha1.WorkspacesConfig
	if operatorConfig != nil {
		wsConfig = operatorConfig.Spec.Workspaces
	}

	configuredImage := wsConfig.GetToolchainImage()
	image := ws.Spec.Image
	if image == "" {
		image = configuredImage
	}

	// Configured toolchain image gets SYS_ADMIN (for overlay mounts that persist
	// dnf-installed packages) plus SETUID/SETGID (for rootless podman/buildah).
	// User-supplied images get only SETUID/SETGID — no overlay persistence but
	// podman/buildah still work.
	caps := []corev1.Capability{"SETUID", "SETGID"}
	if image == configuredImage {
		caps = append(caps, "SYS_ADMIN")
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

	if ws.Spec.TmpfsBuildDir {
		volumes = append(volumes, corev1.Volume{
			Name: "tmpfs-build",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name: "tmpfs-build", MountPath: "/tmp/build",
		})
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
					Name:       containerName,
					Image:      image,
					Command:    []string{"/usr/local/bin/workspace-entrypoint.sh"},
					WorkingDir: "/workspace",
					Env:        env,
					Resources:  resourcesOrDefaults(ws.Spec.Resources),
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: ptr.To(true),
						ProcMount:                ptr.To(corev1.UnmaskedProcMount),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
							Add:  caps,
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
			Tolerations:                   wsConfig.GetTolerations(),
			TerminationGracePeriodSeconds: ptr.To[int64](5),
			RestartPolicy:                 corev1.RestartPolicyNever,
		},
	}

	return pod
}

func (r *Reconciler) deleteWorkspacePod(ctx context.Context, ws *automotivev1alpha1.Workspace, log logr.Logger) error {
	podName := "workspace-" + ws.Name
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ws.Namespace,
		},
	}
	log.Info("Deleting workspace pod for stop", "pod", podName)
	err := r.Delete(ctx, pod)
	return client.IgnoreNotFound(err)
}

func (r *Reconciler) setStatus(ctx context.Context, ws *automotivev1alpha1.Workspace, phase, message string) error {
	podName := "workspace-" + ws.Name
	if phase == "Stopped" {
		podName = ""
	}
	if ws.Status.Phase == phase && ws.Status.Message == message && ws.Status.PodName == podName {
		return nil // no change
	}
	patch := client.MergeFrom(ws.DeepCopy())
	ws.Status.Phase = phase
	ws.Status.Message = message
	ws.Status.PodName = podName
	if phase == "Stopped" || phase == "Pending" || phase == "Creating" {
		ws.Status.LastActivityTime = nil
	}
	return r.Status().Patch(ctx, ws, patch)
}

// getAutoPauseTimeout returns the effective auto-pause timeout for a workspace.
// Returns 0 if auto-pause is disabled.
func (r *Reconciler) getAutoPauseTimeout(ctx context.Context, ws *automotivev1alpha1.Workspace) time.Duration {
	if ws.Spec.AutoPauseTimeoutMinutes != nil {
		mins := *ws.Spec.AutoPauseTimeoutMinutes
		if mins <= 0 {
			return 0
		}
		return time.Duration(mins) * time.Minute
	}

	oc := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: "config", Namespace: ws.Namespace}, oc); err == nil {
		if oc.Spec.Workspaces != nil {
			return time.Duration(oc.Spec.Workspaces.GetAutoPauseTimeoutMinutes()) * time.Minute
		}
	}

	return time.Duration(automotivev1alpha1.DefaultAutoPauseTimeoutMinutes) * time.Minute
}

// checkAutoPause checks if a Running workspace should be auto-paused due to inactivity.
func (r *Reconciler) checkAutoPause(ctx context.Context, ws *automotivev1alpha1.Workspace, log logr.Logger) (ctrl.Result, error) {
	timeout := r.getAutoPauseTimeout(ctx, ws)
	if timeout == 0 {
		return ctrl.Result{}, nil
	}

	checkInterval := timeout / 3
	if maxInterval := 5 * time.Minute; checkInterval > maxInterval {
		checkInterval = maxInterval
	}

	active, err := r.isWorkspaceActive(ctx, ws)
	if err != nil {
		log.V(1).Info("Failed to check workspace activity, will retry", "error", err)
		return ctrl.Result{RequeueAfter: checkInterval}, nil
	}

	// Active or first idle check: update the activity timestamp and requeue.
	// Only patch when the timestamp is unset or stale (older than checkInterval)
	// to avoid unnecessary API writes on every check.
	if active || ws.Status.LastActivityTime == nil {
		stale := ws.Status.LastActivityTime == nil ||
			(active && time.Since(ws.Status.LastActivityTime.Time) > checkInterval)
		if stale {
			now := metav1.Now()
			patch := client.MergeFrom(ws.DeepCopy())
			ws.Status.LastActivityTime = &now
			if err := r.Status().Patch(ctx, ws, patch); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{RequeueAfter: checkInterval}, nil
	}

	// Workspace is idle — check if timeout has expired
	idleDuration := time.Since(ws.Status.LastActivityTime.Time)
	if idleDuration >= timeout {
		log.Info("Auto-pausing idle workspace",
			"workspace", ws.Name,
			"idleDuration", idleDuration.Truncate(time.Second),
			"timeout", timeout)

		specPatch := client.MergeFrom(ws.DeepCopy())
		ws.Spec.Stopped = true
		if err := r.Patch(ctx, ws, specPatch); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to auto-pause workspace: %w", err)
		}

		msg := fmt.Sprintf("Auto-paused after %s of inactivity", idleDuration.Truncate(time.Minute))
		return ctrl.Result{}, r.setStatus(ctx, ws, "Stopped", msg)
	}

	remaining := timeout - idleDuration
	return ctrl.Result{RequeueAfter: remaining}, nil
}

// getClientset returns the cached Kubernetes clientset, creating it on first use.
func (r *Reconciler) getClientset() (kubernetes.Interface, error) {
	r.clientsetOnce.Do(func() {
		r.clientset, r.clientsetErr = kubernetes.NewForConfig(r.RestConfig)
	})
	if r.clientsetErr != nil {
		return nil, fmt.Errorf("creating clientset: %w", r.clientsetErr)
	}
	return r.clientset, nil
}

// isWorkspaceActive execs into the workspace pod to check for user activity.
// Returns true if active sessions or build processes are detected.
func (r *Reconciler) isWorkspaceActive(ctx context.Context, ws *automotivev1alpha1.Workspace) (bool, error) {
	podName := "workspace-" + ws.Name

	clientset, err := r.getClientset()
	if err != nil {
		return false, err
	}

	// Detect user activity via two signals:
	// 1. Active pts sessions (caib workspace shell connections)
	// 2. Exec'd processes: in Kubernetes, exec'd processes have PPID=0 inside the
	//    container PID namespace (their real parent is outside). PID 1 is the
	//    entrypoint. Any other PPID=0 process (besides this check) is user activity.
	cmd := []string{"/bin/sh", "-c",
		`pts=$(ls /dev/pts/ 2>/dev/null | grep -cE '^[0-9]+$'); ` +
			`if [ "$pts" -gt 0 ]; then echo active; exit 0; fi; ` +
			`extra=$(ps -eo pid,ppid --no-headers | awk '$1 != 1 && $2 == 0 {c++} END {print c+0}'); ` +
			`if [ "$extra" -gt 1 ]; then echo active; exit 0; fi; ` +
			`echo idle`,
	}

	execReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace(ws.Namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, kscheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(r.RestConfig, http.MethodPost, execReq.URL())
	if err != nil {
		return false, fmt.Errorf("creating executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := executor.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		return false, fmt.Errorf("exec failed: %w (stderr: %s)", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()) == "active", nil
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
	}
}
